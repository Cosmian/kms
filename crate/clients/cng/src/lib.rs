#![allow(
    unsafe_code,
    dead_code,
    unreachable_pub,
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::cargo_common_metadata,
    clippy::multiple_crate_versions,
    clippy::redundant_pub_crate
)]
//! # Cosmian KMS CNG Key Storage Provider (KSP)
//!
//! A Windows CNG Key Storage Provider DLL that stores private keys inside
//! Cosmian KMS instead of the local machine store.
//!
//! ## DLL entry point
//!
//! Windows calls `GetKeyStorageInterface` to obtain the
//! `NCRYPT_KEY_STORAGE_FUNCTION_TABLE`.
//!
//! ## Configuration
//!
//! The provider reads `ckms.toml` using the same search order as the `ckms`
//! CLI:
//!
//! 1. Path given in the `CKMS_CONF` environment variable.
//! 2. `ckms.toml` in the same directory as this DLL.
//! 3. `~/.cosmian/ckms.toml` (Windows: `%APPDATA%\.cosmian\ckms.toml`).
//!
//! ## Installation
//!
//! ```powershell
//! ckms cng register --dll "C:\Program Files\Cosmian\Kms\cosmian_kms_cng_ksp.dll"
//! ```

use std::{path::PathBuf, ptr::addr_of_mut};

pub mod backend;
mod blob;
pub mod error;
mod key;
mod provider;
mod registry;

pub use provider::{KSP_PROVIDER_NAME, KSP_PROVIDER_NAME_W};
pub use registry::{is_ksp_registered, register_ksp, unregister_ksp};

// ─── DLL directory detection (Windows-only) ───────────────────────────────────

/// Return the directory that contains this KSP DLL.
///
/// Uses `GetModuleHandleExW` with a `#[used]` static anchor (so the linker
/// places the anchor inside this DLL's image, not in a thunk).
///
/// Returns `None` if every approach fails.
#[cfg(windows)]
pub(crate) fn dll_directory() -> Option<PathBuf> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};

    unsafe extern "system" {
        fn GetModuleHandleExW(dw_flags: u32, lp_module_name: *const u16, phm: *mut usize) -> i32;
        fn GetModuleFileNameW(h_module: usize, lp_filename: *mut u16, n_size: u32) -> u32;
    }

    // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS (0x4) |
    // GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT (0x2)
    const FLAGS: u32 = 0x0000_0004 | 0x0000_0002;
    const BUF_CAP: u32 = 32_768;

    // Use a `#[used]` static anchor so the linker keeps it inside this DLL.
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

    // Hard-coded fallback: the well-known install location.
    let fallback = PathBuf::from(r"C:\Program Files\Cosmian\Kms");
    if fallback.is_dir() {
        return Some(fallback);
    }
    None
}

#[cfg(not(windows))]
pub(crate) fn dll_directory() -> Option<PathBuf> {
    None
}

// ─── Logging initialisation ───────────────────────────────────────────────────

fn initialize_logging(log_home: Option<String>) {
    use cosmian_logger::reexport::tracing_subscriber::{EnvFilter, fmt};

    let level = std::env::var("COSMIAN_CNG_KSP_LOGGING_LEVEL")
        .unwrap_or_else(|_| "info".to_owned());
    let filter = EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info"));

    // Write to a log file when given a log_home directory.
    if let Some(home) = log_home {
        let home_path = PathBuf::from(&home);
        if let Ok(file) = std::fs::File::options()
            .create(true)
            .append(true)
            .open(home_path.join("cosmian_cng_ksp.log"))
        {
            let _subscriber = fmt::Subscriber::builder()
                .with_writer(std::sync::Mutex::new(file))
                .with_env_filter(filter)
                .try_init();
            return;
        }
    }
    // Fall through to stderr.
    let _subscriber = fmt::Subscriber::builder()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .try_init();
}

// ─── DLL entry point ─────────────────────────────────────────────────────────

/// `GetKeyStorageInterface` — mandatory DLL export for CNG KSPs.
///
/// Windows calls this function first to obtain the function-pointer table.
/// The table is static so no allocation occurs here; only logging and a
/// basic sanity-check of the out-parameter.
///
/// # Safety
/// Called by the Windows CNG subsystem.  No Rust invariants are violated on
/// the happy path.  The function is marked `unsafe` because it accepts raw
/// pointers and is callable from uncontrolled C code.
#[cfg(windows)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn GetKeyStorageInterface(
    _psz_provider_name: *const u16,
    pp_function_table: *mut *const windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_STORAGE_FUNCTION_TABLE,
    _dw_flags: u32,
) -> i32 {
    if pp_function_table.is_null() {
        return crate::error::NTE_INVALID_PARAMETER;
    }

    let dll_dir = dll_directory();
    let log_home = dll_dir
        .as_deref()
        .map(|d| d.to_string_lossy().into_owned());
    initialize_logging(log_home);

    cosmian_logger::debug!("CNG KSP GetKeyStorageInterface called");

    unsafe {
        *pp_function_table = &provider::KSP_FUNCTION_TABLE;
    }
    crate::error::ERROR_SUCCESS
}

/// Stub for non-Windows builds so the crate compiles cross-platform in CI.
#[cfg(not(windows))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GetKeyStorageInterface() -> i32 {
    crate::error::NTE_NOT_SUPPORTED
}

#[cfg(all(test, feature = "non-fips"))]
mod tests;
