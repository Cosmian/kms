#![allow(
    unsafe_code,
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::cargo_common_metadata,
    clippy::multiple_crate_versions,
    clippy::redundant_pub_crate
)]

use std::{path::PathBuf, ptr::addr_of_mut, slice, str::FromStr, sync::Once};

use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kms_client::KmsClient;
use cosmian_logger::reexport::tracing::Level;
use cosmian_pkcs11_module::{
    ModuleError,
    pkcs11::{FUNC_LIST, FUNC_LIST_3_0, PKCS11_INTERFACE, PKCS11_INTERFACE_NAME},
    traits::{register_backend, register_login_fn, register_pin_mode},
};
use pkcs11_sys::{
    CK_FLAGS, CK_FUNCTION_LIST_PTR_PTR, CK_INTERFACE_PTR, CK_INTERFACE_PTR_PTR, CK_RV,
    CK_ULONG_PTR, CK_UTF8CHAR_PTR, CK_VERSION_PTR, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
    CKR_FUNCTION_FAILED, CKR_OK, CRYPTOKI_VERSION_MAJOR,
};

use crate::{kms_object::get_kms_config, logging::initialize_logging};

/// PKCS#11 v3.0 rollout (issue #1156): upper bound on how many bytes `C_GetInterface` will scan
/// looking for the NUL terminator of a caller-supplied `pInterfaceName`. The spec's "PKCS 11"
/// name is 7 bytes; this generous bound (64) keeps the scan bounded (never reads past it, so an
/// unterminated/malicious buffer cannot cause an out-of-bounds read) while comfortably covering
/// any real interface name.
const MAX_INTERFACE_NAME_LEN: usize = 64;

/// Guards the one-time population of the v3.0 `FUNC_LIST_3_0` function-pointer table. Both
/// `C_GetInterfaceList` and `C_GetInterface` write the same constant function pointers into
/// this `static mut`; without synchronization, concurrent calls from different threads would
/// be a data race under Rust's memory model (see security review, issue #1156). `Once` ensures
/// the writes happen at most once, mirroring the existing `initialize_logging` pattern.
static FUNC_LIST_3_0_INIT: Once = Once::new();

/// PKCS#11 v3.0 rollout (issue #1156): populates `FUNC_LIST_3_0` exactly once, regardless of how
/// many threads call `C_GetInterfaceList`/`C_GetInterface` concurrently.
fn ensure_func_list_3_0_registered() {
    FUNC_LIST_3_0_INIT.call_once(|| {
        // SAFETY: guarded by `Once::call_once`, so this write can only ever execute on a single
        // thread, exactly once, eliminating the data race that would otherwise exist between
        // concurrent calls to `C_GetInterfaceList`/`C_GetInterface`.
        unsafe {
            FUNC_LIST_3_0.C_GetFunctionList = Some(C_GetFunctionList);
            FUNC_LIST_3_0.C_GetInterfaceList = Some(C_GetInterfaceList);
            FUNC_LIST_3_0.C_GetInterface = Some(C_GetInterface);
        }
    });
}

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

/// This function performs the KMS backend/config initialization that `C_GetFunctionList` is the
/// first PKCS#11 entry point to trigger. Returns `Err(CKR_FUNCTION_FAILED)` if the KMS client
/// cannot be instantiated (e.g. missing or invalid configuration), rather than panicking — a Rust
/// panic across an `extern "C"` boundary is UB and crashes the host process (ORA-07445 on
/// Oracle).
///
/// PKCS#11 v3.0 rollout (issue #1156): the KMS backend/config initialization performed here is
/// shared with `C_GetInterfaceList`/`C_GetInterface` below via [`ensure_backend_registered`], so
/// that a v3.0-aware caller that skips `C_GetFunctionList` entirely (using only the new v3.0
/// entry points instead, as the spec allows) still gets a working, fully configured backend.
/// Idempotent: safe to call multiple times (e.g. if an application calls more than one of these
/// three entry points), since `register_backend`/`register_pin_mode`/`register_login_fn` simply
/// overwrite the previous registration and `initialize_logging` is guarded by a `std::sync::Once`.
fn ensure_backend_registered() -> Result<(), CK_RV> {
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

    let config = match get_kms_config(explicit_conf) {
        Ok(c) => c,
        Err(e) => {
            cosmian_logger::error!(
                "ensure_backend_registered: failed to load ckms.toml: {}. \
                 Check that ckms.toml exists alongside the DLL \
                 (C:\\opt\\oracle\\extapi\\64\\pkcs11\\ckms.toml), \
                 at ~/.cosmian/ckms.toml, or set CKMS_CONF to its path.",
                e
            );
            return Err(CKR_FUNCTION_FAILED);
        }
    };

    let use_pin = config.pkcs11_use_pin_as_access_token.unwrap_or(false);
    if use_pin {
        // Mode 2 — OIDC pin: register a pre-auth backend so metadata calls
        // (C_GetTokenInfo etc.) work before C_Login, then register the login
        // callback that replaces it with an authenticated backend at C_Login time.
        let base_client = match KmsClient::new_with_config(config.clone()) {
            Ok(c) => c,
            Err(e) => {
                cosmian_logger::error!(
                    "ensure_backend_registered: failed to instantiate base KMS client: {}",
                    e
                );
                return Err(CKR_FUNCTION_FAILED);
            }
        };
        register_backend(Box::new(backend::CliBackend::instantiate(base_client)));
        register_pin_mode(true);
        register_login_fn(Box::new(move |token: &str| {
            let mut cfg = config.clone();
            cfg.http_config.access_token = Some(token.to_owned());
            let kms_client =
                KmsClient::new_with_config(cfg).map_err(|e| ModuleError::Backend(Box::new(e)))?;
            register_backend(Box::new(backend::CliBackend::instantiate(kms_client)));
            Ok(())
        }));
    } else {
        // Modes 0 and 1 — no auth or static token/TLS cert: create KmsClient immediately.
        let kms_client = match KmsClient::new_with_config(config) {
            Ok(client) => client,
            Err(e) => {
                cosmian_logger::error!(
                    "ensure_backend_registered: failed to instantiate KMS client: {}. \
                     Check that ckms.toml exists alongside the DLL \
                     (C:\\opt\\oracle\\extapi\\64\\pkcs11\\ckms.toml), \
                     at ~/.cosmian/ckms.toml, or set CKMS_CONF to its path.",
                    e
                );
                return Err(CKR_FUNCTION_FAILED);
            }
        };
        register_backend(Box::new(backend::CliBackend::instantiate(kms_client)));
    }
    Ok(())
}

#[unsafe(no_mangle)]
#[expect(unsafe_code)]
/// # Safety
/// `pp_function_list` must be non-null and writable.
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if let Err(rv) = ensure_backend_registered() {
        return rv;
    }
    unsafe {
        FUNC_LIST.C_GetFunctionList = Some(C_GetFunctionList);
        *pp_function_list = addr_of_mut!(FUNC_LIST);
    }
    CKR_OK
}

/// PKCS#11 v3.0 rollout (issue #1156): standard v3.0 interface-discovery entry point.
/// Two-call convention (mirrors `C_GetSlotList`/`C_GetMechanismList` in the module crate):
/// called once with `pInterfacesList` null to learn the count, then again with a
/// caller-allocated buffer of at least that size.
///
/// # Safety
/// `pulCount` must be non-null. If non-null, `pInterfacesList` must point to an array of at
/// least `*pulCount` valid, writable `CK_INTERFACE` slots.
#[unsafe(no_mangle)]
#[expect(unsafe_code)]
pub unsafe extern "C" fn C_GetInterfaceList(
    p_interfaces_list: CK_INTERFACE_PTR,
    pul_count: CK_ULONG_PTR,
) -> CK_RV {
    if pul_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if let Err(rv) = ensure_backend_registered() {
        return rv;
    }
    ensure_func_list_3_0_registered();
    unsafe {
        if p_interfaces_list.is_null() {
            *pul_count = 1;
            return CKR_OK;
        }
        if *pul_count < 1 {
            *pul_count = 1;
            return CKR_BUFFER_TOO_SMALL;
        }
        *p_interfaces_list = PKCS11_INTERFACE;
        *pul_count = 1;
    }
    CKR_OK
}

/// PKCS#11 v3.0 rollout (issue #1156): standard v3.0 interface-lookup entry point. This module
/// exposes exactly one interface — the standard "PKCS 11" interface, major version 3 — so
/// `pInterfaceName` (if non-null) must match that name and `pVersion` (if non-null) must request
/// major version 3; `flags` must be 0 (this interface makes no special guarantees, e.g. no
/// fork-safety claim).
///
/// # Safety
/// `ppInterface` must be non-null and writable. If non-null, `pInterfaceName` must point to a
/// NUL-terminated string no longer than [`MAX_INTERFACE_NAME_LEN`] bytes (excluding the NUL); if
/// non-null, `pVersion` must point to a valid `CK_VERSION`.
#[unsafe(no_mangle)]
#[expect(unsafe_code)]
pub unsafe extern "C" fn C_GetInterface(
    p_interface_name: CK_UTF8CHAR_PTR,
    p_version: CK_VERSION_PTR,
    pp_interface: CK_INTERFACE_PTR_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    if pp_interface.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if flags != 0 {
        // This module's sole interface makes no special guarantees (e.g. fork-safety); no
        // interface exists that satisfies a non-zero flag request.
        return CKR_ARGUMENTS_BAD;
    }
    if !p_interface_name.is_null() {
        // SAFETY: the spec's `pInterfaceName` carries no explicit length, so we bound the scan
        // to `MAX_INTERFACE_NAME_LEN` bytes and never read past a NUL terminator found within
        // that bound. A name that does not match within the bound is simply treated as "no such
        // interface" (CKR_ARGUMENTS_BAD), so an unbounded/malicious buffer cannot cause an
        // out-of-bounds read: at most `MAX_INTERFACE_NAME_LEN` bytes are ever inspected.
        let matches = unsafe {
            let mut matched = false;
            for len in 0..=MAX_INTERFACE_NAME_LEN {
                let byte = *p_interface_name.add(len);
                if byte == 0 {
                    let candidate = slice::from_raw_parts(p_interface_name, len);
                    let expected = PKCS11_INTERFACE_NAME
                        .get(..PKCS11_INTERFACE_NAME.len().saturating_sub(1))
                        .unwrap_or(&[]);
                    matched = candidate == expected;
                    break;
                }
            }
            matched
        };
        if !matches {
            return CKR_ARGUMENTS_BAD;
        }
    }
    if !p_version.is_null() {
        // SAFETY: caller guarantees p_version points to a valid CK_VERSION per this function's
        // safety contract.
        let version = unsafe { *p_version };
        if version.major != CRYPTOKI_VERSION_MAJOR {
            return CKR_ARGUMENTS_BAD;
        }
    }
    if let Err(rv) = ensure_backend_registered() {
        return rv;
    }
    ensure_func_list_3_0_registered();
    unsafe {
        *pp_interface = addr_of_mut!(PKCS11_INTERFACE);
    }
    CKR_OK
}

#[cfg(test)]
#[cfg(feature = "non-fips")]
#[expect(clippy::expect_used, clippy::panic_in_result_fn)]
mod tests;
