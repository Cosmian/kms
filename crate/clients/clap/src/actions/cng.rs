/// CLI commands for managing the Cosmian KMS CNG Key Storage Provider (KSP).
///
/// These commands are Windows-only and allow registering, unregistering, and
/// listing keys managed by the CNG KSP.
use std::path::PathBuf;

use clap::Subcommand;

use crate::error::{KmsCliError, result::KmsCliResult};

// ─── Command enum ─────────────────────────────────────────────────────────────

/// Commands for managing the Cosmian KMS CNG Key Storage Provider.
///
/// The CNG KSP DLL must be registered in the Windows Registry before Windows
/// can use it to store device certificate private keys in Cosmian KMS.
#[derive(Subcommand, Debug)]
pub enum CngCommands {
    /// Register the Cosmian KMS CNG Key Storage Provider DLL in the Windows Registry.
    ///
    /// Requires elevated (Administrator) privileges.
    ///
    /// Example:
    ///   `ckms cng register --dll "C:\Program Files\Cosmian\Kms\cosmian_kms_cng_ksp.dll"`
    Register {
        /// Full path to the `cosmian_kms_cng_ksp.dll` file.
        #[arg(long, short = 'd')]
        dll: PathBuf,
    },
    /// Unregister the Cosmian KMS CNG Key Storage Provider from the Windows Registry.
    ///
    /// Requires elevated (Administrator) privileges.
    Unregister,
    /// Show the CNG KSP registration status (is the provider registered?).
    Status,
    /// List all private keys stored in Cosmian KMS that belong to this CNG KSP.
    ListKeys,
}

impl CngCommands {
    /// Execute the CNG command.
    ///
    /// # Errors
    /// Returns an error if the registry operation or KMS query fails.
    pub async fn process(
        &self,
        kms_rest_client: cosmian_kms_client::KmsClient,
    ) -> KmsCliResult<()> {
        match self {
            Self::Register { dll } => register(dll),
            Self::Unregister => unregister(),
            Self::Status => status(),
            Self::ListKeys => list_keys(kms_rest_client).await,
        }
    }
}

// ─── KMS tag prefix (mirrored from cosmian_kms_cng_ksp::backend) ─────────────

const CNG_KSP_TAG: &str = "cng-ksp";

// ─── Register ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
#[allow(clippy::print_stdout)]
fn register(dll: &PathBuf) -> KmsCliResult<()> {
    let dll_str = dll
        .to_str()
        .ok_or_else(|| KmsCliError::Default("DLL path contains non-UTF-8 characters".to_owned()))?;
    if !dll.exists() {
        return Err(KmsCliError::Default(format!(
            "DLL not found: {}",
            dll.display()
        )));
    }
    write_ksp_registry(dll_str).map_err(KmsCliError::Default)?;
    println!("Cosmian KMS CNG KSP registered successfully.");
    println!("DLL: {dll_str}");
    Ok(())
}

#[cfg(not(windows))]
fn register(_dll: &PathBuf) -> KmsCliResult<()> {
    Err(KmsCliError::Default(
        "CNG KSP registration is only supported on Windows".to_owned(),
    ))
}

// ─── Unregister ───────────────────────────────────────────────────────────────

#[cfg(windows)]
#[allow(clippy::print_stdout)]
fn unregister() -> KmsCliResult<()> {
    delete_ksp_registry().map_err(KmsCliError::Default)?;
    println!("Cosmian KMS CNG KSP unregistered successfully.");
    Ok(())
}

#[cfg(not(windows))]
fn unregister() -> KmsCliResult<()> {
    Err(KmsCliError::Default(
        "CNG KSP unregistration is only supported on Windows".to_owned(),
    ))
}

// ─── Status ───────────────────────────────────────────────────────────────────

#[cfg(windows)]
#[allow(clippy::print_stdout)]
fn status() -> KmsCliResult<()> {
    if ksp_is_registered() {
        println!("Cosmian KMS CNG KSP: REGISTERED");
    } else {
        println!("Cosmian KMS CNG KSP: NOT registered");
    }
    Ok(())
}

#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps, clippy::print_stdout)]
fn status() -> KmsCliResult<()> {
    println!("CNG KSP status is only available on Windows");
    Ok(())
}

// ─── List-keys ────────────────────────────────────────────────────────────────

#[allow(clippy::print_stdout)]
async fn list_keys(kms_rest_client: cosmian_kms_client::KmsClient) -> KmsCliResult<()> {
    use cosmian_kmip::kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN, kmip_attributes::Attributes, kmip_operations::Locate,
    };

    let mut attrs = Attributes::default();
    attrs
        .set_tags(VENDOR_ID_COSMIAN, [CNG_KSP_TAG])
        .map_err(|e| KmsCliError::Default(format!("Failed to set tags: {e}")))?;

    let locate = Locate {
        attributes: attrs,
        ..Default::default()
    };
    let resp = kms_rest_client
        .locate(locate)
        .await
        .map_err(|e| KmsCliError::Default(format!("KMS locate failed: {e}")))?;

    let ids = resp.unique_identifier.unwrap_or_default();
    if ids.is_empty() {
        println!("No CNG KSP keys found in the KMS.");
    } else {
        println!("CNG KSP keys in the KMS:");
        for id in &ids {
            println!("  {id}");
        }
    }
    Ok(())
}

// ─── Windows Registry helpers ─────────────────────────────────────────────────

#[cfg(windows)]
const KSP_PROVIDER_NAME: &str = "Cosmian KMS Key Storage Provider";
#[cfg(windows)]
const KSP_REGISTRY_PATH: &str = r"SYSTEM\CurrentControlSet\Control\Cryptography\Providers";
/// `NCRYPT_IMPL_SOFTWARE_FLAG`
#[cfg(windows)]
const KSP_CAPABILITIES: u32 = 2_u32;

#[cfg(windows)]
#[allow(unsafe_code)]
fn write_ksp_registry(dll_path: &str) -> Result<(), String> {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
        RegCloseKey, RegCreateKeyExW, RegSetValueExW,
    };

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
                "RegCreateKeyExW failed with code {status:#010x} for key '{key_path}' — run as Administrator?"
            ));
        }

        // DllFileName (REG_SZ)
        let dll_w = to_wide(dll_path);
        let dll_bytes: Vec<u8> = dll_w.iter().flat_map(|c| c.to_le_bytes()).collect();
        let s = RegSetValueExW(
            hkey,
            to_wide("DllFileName").as_ptr(),
            0,
            REG_SZ,
            dll_bytes.as_ptr(),
            u32::try_from(dll_bytes.len()).unwrap_or(u32::MAX),
        );
        if s != 0 {
            let _ = RegCloseKey(hkey);
            return Err(format!("RegSetValueExW(DllFileName) failed with {s:#010x}"));
        }

        // Capabilities (REG_DWORD)
        let cap_bytes = KSP_CAPABILITIES.to_le_bytes();
        let s = RegSetValueExW(
            hkey,
            to_wide("Capabilities").as_ptr(),
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

#[cfg(windows)]
#[allow(unsafe_code)]
fn delete_ksp_registry() -> Result<(), String> {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, RegCloseKey, RegDeleteKeyW, RegOpenKeyExW,
    };

    let base_w = to_wide(KSP_REGISTRY_PATH);
    unsafe {
        let mut hroot: HKEY = std::ptr::null_mut();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            base_w.as_ptr(),
            0,
            KEY_ALL_ACCESS,
            &mut hroot,
        );
        if status != 0 {
            return Err(format!(
                "RegOpenKeyExW failed with {status:#010x} — run as Administrator?"
            ));
        }
        let name_w = to_wide(KSP_PROVIDER_NAME);
        let s = RegDeleteKeyW(hroot, name_w.as_ptr());
        let _ = RegCloseKey(hroot);
        if s != 0 && s != 0x2 {
            // 0x2 = ERROR_FILE_NOT_FOUND — already gone
            return Err(format!(
                "RegDeleteKeyW failed with {s:#010x} for '{KSP_PROVIDER_NAME}'"
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn ksp_is_registered() -> bool {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW,
    };

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

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
