/// Windows Registry helpers for registering and unregistering the CNG KSP.
///
/// KSP registration writes to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Providers`.
/// The subkey name is the provider name; the values `DllFileName` and
/// `Capabilities` describe the DLL location and supported operations.
///
/// These helpers are called by the CLI `ckms cng register/unregister` commands.
#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
use cosmian_logger::debug;
#[cfg(windows)]
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ, KEY_WRITE, REG_DWORD, REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegOpenKeyExW, RegSetValueExW,
    REG_OPTION_NON_VOLATILE,
};

use crate::provider::KSP_PROVIDER_NAME;

/// Registry path to all CNG KSP providers (without trailing `\`).
const KSP_REGISTRY_PATH: &str =
    r"SYSTEM\CurrentControlSet\Control\Cryptography\Providers";

/// Registry flag: NCRYPT_IMPL_HARDWARE_FLAG(1) | NCRYPT_IMPL_SOFTWARE_FLAG(2)
/// We advertise software-only.
const KSP_CAPABILITIES: u32 = 2u32; // NCRYPT_IMPL_SOFTWARE_FLAG

// ─── Public API ──────────────────────────────────────────────────────────────

/// Register the Cosmian KMS KSP DLL in the Windows Registry.
///
/// Creates the subkey `<KSP_REGISTRY_PATH>\<KSP_PROVIDER_NAME>` and writes
/// the `DllFileName` and `Type` values.
///
/// # Errors
/// Returns an error string (suitable for display) if the registry write fails.
#[cfg(windows)]
pub fn register_ksp(dll_path: &Path) -> Result<(), String> {
    let dll_path_str = dll_path
        .to_str()
        .ok_or_else(|| "DLL path is not valid UTF-8".to_owned())?;
    debug!("CNG KSP register: dll_path={dll_path_str}");

    let key_path = format!("{KSP_REGISTRY_PATH}\\{KSP_PROVIDER_NAME}");
    let key_path_w = to_wide(&key_path);

    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let mut disposition: u32 = 0;

        let status = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            key_path_w.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            std::ptr::null(),
            &mut hkey,
            &mut disposition,
        );
        if status != 0 {
            return Err(format!(
                "RegCreateKeyExW failed with code {status:#010x} for key '{key_path}'"
            ));
        }

        // DllFileName (REG_SZ)
        let dll_w = to_wide(dll_path_str);
        let dll_bytes = wide_as_bytes(&dll_w);
        let s = RegSetValueExW(
            hkey,
            str_to_wide("DllFileName").as_ptr(),
            0,
            REG_SZ,
            dll_bytes.as_ptr(),
            u32::try_from(dll_bytes.len()).unwrap_or(u32::MAX),
        );
        if s != 0 {
            let _ = RegCloseKey(hkey);
            return Err(format!("RegSetValueExW(DllFileName) failed with {s:#010x}"));
        }

        // Type / Capabilities (REG_DWORD)
        let cap_bytes = KSP_CAPABILITIES.to_le_bytes();
        let s = RegSetValueExW(
            hkey,
            str_to_wide("Capabilities").as_ptr(),
            0,
            REG_DWORD,
            cap_bytes.as_ptr(),
            4,
        );
        if s != 0 {
            let _ = RegCloseKey(hkey);
            return Err(format!(
                "RegSetValueExW(Capabilities) failed with {s:#010x}"
            ));
        }

        let _ = RegCloseKey(hkey);
    }
    Ok(())
}

/// Unregister the Cosmian KMS KSP by removing its registry subkey.
#[cfg(windows)]
pub fn unregister_ksp() -> Result<(), String> {
    debug!("CNG KSP unregister");

    let key_path = to_wide(KSP_REGISTRY_PATH);

    unsafe {
        let mut hroot: HKEY = std::ptr::null_mut();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_path.as_ptr(),
            0,
            KEY_ALL_ACCESS,
            &mut hroot,
        );
        if status != 0 {
            return Err(format!(
                "RegOpenKeyExW('{KSP_REGISTRY_PATH}') failed with code {status:#010x}"
            ));
        }

        let subkey_w = to_wide(KSP_PROVIDER_NAME);
        let s = RegDeleteKeyW(hroot, subkey_w.as_ptr());
        let _ = RegCloseKey(hroot);
        if s != 0 && s != 0x2 {
            // 0x2 = ERROR_FILE_NOT_FOUND — already gone, treat as success
            return Err(format!(
                "RegDeleteKeyW('{KSP_PROVIDER_NAME}') failed with code {s:#010x}"
            ));
        }
    }
    Ok(())
}

/// Check whether the KSP is currently registered (key exists and `DllFileName` is present).
#[cfg(windows)]
pub fn is_ksp_registered() -> bool {
    let key_path = format!("{KSP_REGISTRY_PATH}\\{KSP_PROVIDER_NAME}");
    let key_path_w = to_wide(&key_path);

    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_path_w.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );
        if status != 0 {
            return false;
        }
        let _ = RegCloseKey(hkey);
    }
    true
}

// ─── Registry helpers for non-Windows builds (stubs) ─────────────────────────

#[cfg(not(windows))]
pub fn register_ksp(_dll_path: &Path) -> Result<(), String> {
    Err("KSP registration is only supported on Windows".to_owned())
}

#[cfg(not(windows))]
pub fn unregister_ksp() -> Result<(), String> {
    Err("KSP unregistration is only supported on Windows".to_owned())
}

#[cfg(not(windows))]
pub fn is_ksp_registered() -> bool {
    false
}

// ─── Wide-string helpers ──────────────────────────────────────────────────────

/// Encode a Rust `&str` as a null-terminated UTF-16 `Vec<u16>`.
#[allow(dead_code)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Convenience alias for `to_wide`.
#[allow(dead_code)]
fn str_to_wide(s: &str) -> Vec<u16> {
    to_wide(s)
}

/// Reinterpret a `&[u16]` as a byte slice for `RegSetValueExW`.
/// Includes the null terminator so the registry stores a well-formed wide string.
#[cfg(windows)]
#[allow(unsafe_code)]
fn wide_as_bytes(wide: &[u16]) -> Vec<u8> {
    wide.iter()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}
