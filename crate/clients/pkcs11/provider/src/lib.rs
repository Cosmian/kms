#![allow(
    unsafe_code,
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::cargo_common_metadata,
    clippy::multiple_crate_versions,
    clippy::redundant_pub_crate
)]

use std::{path::PathBuf, ptr::addr_of_mut, str::FromStr};

use cosmian_logger::{error, reexport::tracing::Level};
use cosmian_pkcs11_module::{pkcs11::FUNC_LIST, traits::register_backend};
use pkcs11_sys::{CK_FUNCTION_LIST_PTR_PTR, CK_RV, CKR_FUNCTION_FAILED, CKR_OK};

use crate::{kms_object::get_kms_client_with_path, logging::initialize_logging};

mod backend;
mod error;
mod kms_object;
mod logging;
mod pkcs11_certificate;
mod pkcs11_data_object;
mod pkcs11_private_key;
mod pkcs11_public_key;
mod pkcs11_symmetric_key;

/// On Windows, return the directory that contains this DLL.
/// Uses `GetModuleHandleExW` with a static data anchor (more reliable than a
/// function-pointer address, which the linker may place in a thunk outside the
/// DLL's image) plus a hard-coded fallback to the well-known install location.
/// Returns `None` only if every approach fails.
#[cfg(windows)]
fn dll_directory() -> Option<PathBuf> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};

    unsafe extern "system" {
        fn GetModuleHandleExW(dw_flags: u32, lp_module_name: *const u16, phm: *mut usize) -> i32;
        fn GetModuleFileNameW(h_module: usize, lp_filename: *mut u16, n_size: u32) -> u32;
    }

    // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS (0x4) |
    // GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT (0x2)
    // Use a `#[used]` static so the linker guarantees it lives inside this
    // DLL's image — avoids thunk issues with function-pointer addresses.
    const FLAGS: u32 = 0x0000_0004 | 0x0000_0002;
    // u16 anchor: same type as the lp_module_name parameter, avoiding alignment casts.
    const BUF_CAP: u32 = 32_768;
    #[used]
    static DLL_ANCHOR: u16 = 0;
    let addr = &raw const DLL_ANCHOR;

    let mut h_module: usize = 0;
    if unsafe { GetModuleHandleExW(FLAGS, addr, addr_of_mut!(h_module)) } != 0 {
        let mut buf = vec![0_u16; 32_768_usize];
        let len = unsafe { GetModuleFileNameW(h_module, buf.as_mut_ptr(), BUF_CAP) };
        if len > 0 {
            let len_usize = usize::try_from(len).unwrap_or(0);
            if let Some(wide) = buf.get(..len_usize) {
                let dll_path = PathBuf::from(OsString::from_wide(wide));
                if let Some(parent) = dll_path.parent() {
                    return Some(parent.to_path_buf());
                }
            }
        }
    }

    // Hard-coded fallback: the well-known install location used by set_hsm.ps1.
    let fallback = PathBuf::from(r"C:\opt\oracle\extapi\64\pkcs11");
    if fallback.is_dir() {
        return Some(fallback);
    }
    None
}

/// # Safety
/// This function is the first one called by the PKCS#11 library client
/// to get the PKCS#11 functions list.
/// Returns `CKR_FUNCTION_FAILED` if the KMS client cannot be instantiated
/// (e.g. missing or invalid configuration), rather than panicking — a Rust
/// panic across an `extern "C"` boundary is UB and crashes the host process
/// (ORA-07445 on Oracle).
#[unsafe(no_mangle)]
#[expect(unsafe_code)]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    let debug_level =
        std::env::var("COSMIAN_PKCS11_LOGGING_LEVEL").unwrap_or_else(|_| "info".to_owned());

    // On Windows, route logging to the DLL directory so the Oracle service
    // virtual account (which has no writable home directory) can write logs.
    #[cfg(windows)]
    let dll_dir = dll_directory();
    #[cfg(not(windows))]
    let dll_dir: Option<PathBuf> = None;

    let log_home = dll_dir.as_deref().map(|d| d.to_string_lossy().into_owned());
    initialize_logging(
        "cosmian-pkcs11",
        Level::from_str(&debug_level).ok(),
        log_home,
    );

    // Determine which ckms.toml to use.
    // Priority: CKMS_CONF env var (user override) > ckms.toml alongside DLL > default search.
    let explicit_conf: Option<PathBuf> = if std::env::var("CKMS_CONF").is_ok() {
        None // ClientConfig::load will pick up CKMS_CONF itself
    } else {
        dll_dir.as_deref().and_then(|dir| {
            let candidate = dir.join("ckms.toml");
            if candidate.exists() {
                Some(candidate)
            } else {
                None
            }
        })
    };

    let kms_client = match get_kms_client_with_path(explicit_conf) {
        Ok(client) => client,
        Err(e) => {
            error!(
                "C_GetFunctionList: failed to instantiate KMS client: {}. \
                 Check that ckms.toml exists alongside the DLL \
                 (C:\\opt\\oracle\\extapi\\64\\pkcs11\\ckms.toml), \
                 at ~/.cosmian/ckms.toml, or set CKMS_CONF to its path.",
                e
            );
            return CKR_FUNCTION_FAILED;
        }
    };
    register_backend(Box::new(backend::CliBackend::instantiate(kms_client)));
    unsafe {
        FUNC_LIST.C_GetFunctionList = Some(C_GetFunctionList);
        *pp_function_list = addr_of_mut!(FUNC_LIST);
    }
    CKR_OK
}

#[cfg(test)]
#[cfg(feature = "non-fips")]
#[expect(clippy::expect_used, clippy::panic_in_result_fn)]
mod tests;
