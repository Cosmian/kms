/// Windows CNG Key Storage Provider registration using the official BCrypt APIs.
///
/// A CNG KSP must be registered via `BCryptRegisterProvider` which creates the
/// proper registry structure under
/// `HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\<name>\UM`.
///
/// After registration, `BCryptAddContextFunction` and
/// `BCryptAddContextFunctionProvider` are called to make the provider
/// discoverable by `NCryptOpenStorageProvider` and `certutil -csplist`.
///
/// The DLL is copied to `%SystemRoot%\System32` because CNG resolves provider
/// images from that directory (only the filename is stored in the registry).
///
/// These helpers are called by the CLI `ckms cng register/unregister` commands
/// and by the NSIS installer.
use std::path::Path;

use cosmian_logger::debug;

use crate::provider::KSP_PROVIDER_NAME;

// ─── BCrypt API types and externs ────────────────────────────────────────────
// These are not exposed in windows-sys 0.59 but are stable Win32 APIs
// available in bcrypt.dll since Windows Vista.

#[allow(clippy::upper_case_acronyms)]
type NTSTATUS = i32;
#[allow(clippy::upper_case_acronyms)]
type PCWSTR = *const u16;
#[allow(clippy::upper_case_acronyms)]
type PWSTR = *mut u16;

const STATUS_SUCCESS: NTSTATUS = 0;

/// BCRYPT_TABLE / CRYPT_LOCAL — operate on the local machine configuration.
const CRYPT_LOCAL: u32 = 1;

/// Lowest priority position.
const CRYPT_PRIORITY_BOTTOM: u32 = 0xFFFF_FFFF;

/// NCRYPT_KEY_STORAGE_INTERFACE = 0x00010001
const NCRYPT_KEY_STORAGE_INTERFACE: u32 = 0x0001_0001;

/// The algorithm name for key storage providers.
const NCRYPT_KEY_STORAGE_ALGORITHM: &[u16] = &[
    b'K' as u16,
    b'E' as u16,
    b'Y' as u16,
    b'_' as u16,
    b'S' as u16,
    b'T' as u16,
    b'O' as u16,
    b'R' as u16,
    b'A' as u16,
    b'G' as u16,
    b'E' as u16,
    0,
];

/// The DLL filename (without path) as stored in the registry.
const CNG_DLL_FILENAME: &str = "cosmian_cng.dll";

#[repr(C)]
struct CryptInterfaceReg {
    dw_interface: u32,
    dw_flags: u32,
    c_functions: u32,
    rgpsz_functions: *mut PWSTR,
}

#[repr(C)]
struct CryptImageReg {
    psz_image: PWSTR,
    c_interfaces: u32,
    rgp_interfaces: *mut *mut CryptInterfaceReg,
}

#[repr(C)]
struct CryptProviderReg {
    c_aliases: u32,
    rgpsz_aliases: *mut PWSTR,
    p_um: *mut CryptImageReg,
    p_km: *mut CryptImageReg,
}

#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptRegisterProvider(
        pszProvider: PCWSTR,
        dwFlags: u32,
        pReg: *const CryptProviderReg,
    ) -> NTSTATUS;

    fn BCryptUnregisterProvider(pszProvider: PCWSTR) -> NTSTATUS;

    fn BCryptAddContextFunction(
        dwTable: u32,
        pszContext: PCWSTR,
        dwInterface: u32,
        pszFunction: PCWSTR,
        dwPosition: u32,
    ) -> NTSTATUS;

    fn BCryptAddContextFunctionProvider(
        dwTable: u32,
        pszContext: PCWSTR,
        dwInterface: u32,
        pszFunction: PCWSTR,
        pszProvider: PCWSTR,
        dwPosition: u32,
    ) -> NTSTATUS;

    fn BCryptRemoveContextFunctionProvider(
        dwTable: u32,
        pszContext: PCWSTR,
        dwInterface: u32,
        pszFunction: PCWSTR,
        pszProvider: PCWSTR,
    ) -> NTSTATUS;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Register the Cosmian KMS KSP DLL via the official BCrypt registration APIs.
///
/// This performs the full registration sequence:
/// 1. Copies the DLL to `%SystemRoot%\System32` (CNG resolves images from there)
/// 2. `BCryptRegisterProvider` — creates the UM image + interface registry entries
/// 3. `BCryptAddContextFunction` — adds KEY_STORAGE to the local context
/// 4. `BCryptAddContextFunctionProvider` — links our provider to KEY_STORAGE
///
/// # Errors
/// Returns an error string if the copy or any BCrypt API call fails.
pub fn register_ksp(dll_path: &Path) -> Result<(), String> {
    let dll_abs = dll_path.canonicalize().map_err(|e| {
        format!(
            "Failed to canonicalize DLL path '{}': {e}",
            dll_path.display()
        )
    })?;
    debug!("CNG KSP register: source dll={}", dll_abs.display());

    // Step 0: Copy DLL to System32
    copy_dll_to_system32(&dll_abs)?;

    let provider_name_w = to_wide(KSP_PROVIDER_NAME);
    let mut dll_filename_w = to_wide(CNG_DLL_FILENAME);

    // Build the interface registration for NCRYPT_KEY_STORAGE_INTERFACE
    #[allow(clippy::as_ptr_cast_mut, clippy::as_conversions, clippy::ptr_cast_constness)]
    let mut key_storage_algo: *mut u16 = NCRYPT_KEY_STORAGE_ALGORITHM.as_ptr() as *mut u16;

    let mut interface_reg = CryptInterfaceReg {
        dw_interface: NCRYPT_KEY_STORAGE_INTERFACE,
        dw_flags: CRYPT_LOCAL,
        c_functions: 1,
        rgpsz_functions: &raw mut key_storage_algo,
    };

    let mut interface_ptr: *mut CryptInterfaceReg = &raw mut interface_reg;

    let mut image_reg = CryptImageReg {
        psz_image: dll_filename_w.as_mut_ptr(),
        c_interfaces: 1,
        rgp_interfaces: &raw mut interface_ptr,
    };

    let provider_reg = CryptProviderReg {
        c_aliases: 0,
        rgpsz_aliases: std::ptr::null_mut(),
        p_um: &raw mut image_reg,
        p_km: std::ptr::null_mut(),
    };

    unsafe {
        // Step 1: Register the provider (creates the UM\Image + interface keys)
        let status =
            BCryptRegisterProvider(provider_name_w.as_ptr(), 0, std::ptr::from_ref(&provider_reg));
        if status != STATUS_SUCCESS {
            return Err(format!(
                "BCryptRegisterProvider failed with NTSTATUS {status:#010x}"
            ));
        }

        // Step 2: Add the KEY_STORAGE function to the local context
        let status = BCryptAddContextFunction(
            CRYPT_LOCAL,
            std::ptr::null(), // default context
            NCRYPT_KEY_STORAGE_INTERFACE,
            NCRYPT_KEY_STORAGE_ALGORITHM.as_ptr(),
            CRYPT_PRIORITY_BOTTOM,
        );
        if status != STATUS_SUCCESS {
            // Non-fatal: may already exist from another provider
            debug!("BCryptAddContextFunction returned {status:#010x} (may already exist)");
        }

        // Step 3: Register our provider as implementing KEY_STORAGE
        let status = BCryptAddContextFunctionProvider(
            CRYPT_LOCAL,
            std::ptr::null(), // default context
            NCRYPT_KEY_STORAGE_INTERFACE,
            NCRYPT_KEY_STORAGE_ALGORITHM.as_ptr(),
            provider_name_w.as_ptr(),
            CRYPT_PRIORITY_BOTTOM,
        );
        if status != STATUS_SUCCESS {
            return Err(format!(
                "BCryptAddContextFunctionProvider failed with NTSTATUS {status:#010x}"
            ));
        }
    }

    Ok(())
}

/// Unregister the Cosmian KMS KSP via the official BCrypt APIs.
///
/// Reverses the registration by:
/// 1. `BCryptRemoveContextFunctionProvider` — unlinks from KEY_STORAGE
/// 2. `BCryptUnregisterProvider` — removes the provider registry entries
/// 3. Deletes the DLL from System32
pub fn unregister_ksp() -> Result<(), String> {
    debug!("CNG KSP unregister");

    let provider_name_w = to_wide(KSP_PROVIDER_NAME);

    unsafe {
        // Step 1: Remove our provider from the KEY_STORAGE context function
        let status = BCryptRemoveContextFunctionProvider(
            CRYPT_LOCAL,
            std::ptr::null(), // default context
            NCRYPT_KEY_STORAGE_INTERFACE,
            NCRYPT_KEY_STORAGE_ALGORITHM.as_ptr(),
            provider_name_w.as_ptr(),
        );
        if status != STATUS_SUCCESS {
            debug!("BCryptRemoveContextFunctionProvider returned {status:#010x}");
        }

        // Step 2: Unregister the provider entirely
        let status = BCryptUnregisterProvider(provider_name_w.as_ptr());
        if status != STATUS_SUCCESS {
            // STATUS_NOT_FOUND = 0xC0000225 — already gone
            if status != -0x3FFF_FDDB_i32 {
                return Err(format!(
                    "BCryptUnregisterProvider failed with NTSTATUS {status:#010x}"
                ));
            }
        }
    }

    // Step 3: Remove DLL from System32
    remove_dll_from_system32();

    Ok(())
}

/// Check whether the KSP is currently registered by querying the registry
/// structure that `BCryptRegisterProvider` creates.
pub fn is_ksp_registered() -> bool {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, KEY_READ, RegOpenKeyExW};

    let key_path =
        format!(r"SYSTEM\CurrentControlSet\Control\Cryptography\Providers\{KSP_PROVIDER_NAME}\UM");
    let key_path_w = to_wide(&key_path);

    unsafe {
        let mut hkey: windows_sys::Win32::System::Registry::HKEY = std::ptr::null_mut();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_path_w.as_ptr(),
            0,
            KEY_READ,
            &raw mut hkey,
        );
        if status != 0 {
            return false;
        }
        windows_sys::Win32::System::Registry::RegCloseKey(hkey);
        true
    }
}

// ─── System32 copy helpers ───────────────────────────────────────────────────

fn get_system32_dll_path() -> Result<std::path::PathBuf, String> {
    let sys_dir = std::env::var("SystemRoot")
        .map_err(|_e| "SystemRoot environment variable not set".to_owned())?;
    Ok(std::path::PathBuf::from(sys_dir)
        .join("System32")
        .join(CNG_DLL_FILENAME))
}

fn copy_dll_to_system32(source: &Path) -> Result<(), String> {
    let dest = get_system32_dll_path()?;
    debug!("Copying {} -> {}", source.display(), dest.display());
    std::fs::copy(source, &dest).map_err(|e| {
        format!(
            "Failed to copy DLL to '{}': {e} — run as Administrator?",
            dest.display()
        )
    })?;
    Ok(())
}

fn remove_dll_from_system32() {
    if let Ok(path) = get_system32_dll_path() {
        drop(std::fs::remove_file(&path));
    }
}

// ─── Wide-string helpers ──────────────────────────────────────────────────────

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
