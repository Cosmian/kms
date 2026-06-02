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
    ///   `ckms cng register --dll "$env:LOCALAPPDATA\Cosmian KMS CLI\cosmian_cng.dll"`
    Register {
        /// Full path to the `cosmian_cng.dll` file.
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
    /// Load the CNG KSP DLL and exercise all `NCrypt` function-table entry points.
    ///
    /// This tests key creation, signing, encryption, export, delete, property queries,
    /// algorithm enumeration, and more against a live KMS server.
    Verify {
        /// Full path to the `cosmian_cng.dll` file to verify.
        #[arg(long, short = 'd')]
        dll: PathBuf,
    },
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
            Self::Verify { dll } => verify(dll),
        }
    }
}

// ─── KMS tag prefix (mirrored from cosmian_cng::backend) ─────────────

const CNG_KSP_TAG: &str = "cng-ksp";

// ─── Register ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
#[allow(clippy::print_stdout, clippy::ptr_arg)]
fn register(dll: &PathBuf) -> KmsCliResult<()> {
    if !dll.exists() {
        return Err(KmsCliError::Default(format!(
            "DLL not found: {}",
            dll.display()
        )));
    }
    bcrypt_register_ksp(dll).map_err(KmsCliError::Default)?;
    println!("Cosmian KMS CNG KSP registered successfully.");
    println!("DLL: {}", dll.display());
    Ok(())
}

#[cfg(not(windows))]
#[allow(clippy::ptr_arg)]
fn register(_dll: &PathBuf) -> KmsCliResult<()> {
    Err(KmsCliError::Default(
        "CNG KSP registration is only supported on Windows".to_owned(),
    ))
}

// ─── Unregister ───────────────────────────────────────────────────────────────

#[cfg(windows)]
#[allow(clippy::print_stdout)]
fn unregister() -> KmsCliResult<()> {
    bcrypt_unregister_ksp().map_err(KmsCliError::Default)?;
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
#[allow(clippy::print_stdout, clippy::unnecessary_wraps)]
fn status() -> KmsCliResult<()> {
    if bcrypt_is_ksp_registered() {
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

// ─── Verify ───────────────────────────────────────────────────────────────────

#[allow(clippy::ptr_arg)]
fn verify(dll: &PathBuf) -> KmsCliResult<()> {
    crate::actions::cng_verify::win::run_verify(dll)
}

// ─── Windows BCrypt registration helpers ─────────────────────────────────────
// Uses the official BCrypt APIs (BCryptRegisterProvider, BCryptAddContextFunction,
// BCryptAddContextFunctionProvider) to properly register the KSP so it appears
// in certutil -csplist and is usable by NCryptOpenStorageProvider / Intune.

#[cfg(windows)]
const KSP_PROVIDER_NAME: &str = "Cosmian KMS Key Storage Provider";

#[cfg(windows)]
#[allow(clippy::upper_case_acronyms)]
type Ntstatus = i32;
#[cfg(windows)]
#[allow(clippy::upper_case_acronyms)]
type Pcwstr = *const u16;
#[cfg(windows)]
#[allow(clippy::upper_case_acronyms)]
type Pwstr = *mut u16;

#[cfg(windows)]
const CRYPT_LOCAL: u32 = 1;
#[cfg(windows)]
const CRYPT_PRIORITY_BOTTOM: u32 = 0xFFFF_FFFF;
#[cfg(windows)]
const NCRYPT_KEY_STORAGE_INTERFACE: u32 = 0x0001_0001;

#[cfg(windows)]
#[allow(clippy::as_conversions)]
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

#[cfg(windows)]
#[repr(C)]
struct CryptInterfaceReg {
    dw_interface: u32,
    dw_flags: u32,
    c_functions: u32,
    rgpsz_functions: *mut Pwstr,
}

#[cfg(windows)]
#[repr(C)]
struct CryptImageReg {
    psz_image: Pwstr,
    c_interfaces: u32,
    rgp_interfaces: *mut *mut CryptInterfaceReg,
}

#[cfg(windows)]
#[repr(C)]
struct CryptProviderReg {
    c_aliases: u32,
    rgpsz_aliases: *mut Pwstr,
    p_um: *mut CryptImageReg,
    p_km: *mut CryptImageReg,
}

#[cfg(windows)]
#[link(name = "bcrypt")]
#[allow(unsafe_code)]
unsafe extern "system" {
    fn BCryptRegisterProvider(
        pszProvider: Pcwstr,
        dwFlags: u32,
        pReg: *const CryptProviderReg,
    ) -> Ntstatus;
    fn BCryptUnregisterProvider(pszProvider: Pcwstr) -> Ntstatus;
    fn BCryptAddContextFunction(
        dwTable: u32,
        pszContext: Pcwstr,
        dwInterface: u32,
        pszFunction: Pcwstr,
        dwPosition: u32,
    ) -> Ntstatus;
    fn BCryptAddContextFunctionProvider(
        dwTable: u32,
        pszContext: Pcwstr,
        dwInterface: u32,
        pszFunction: Pcwstr,
        pszProvider: Pcwstr,
        dwPosition: u32,
    ) -> Ntstatus;
    fn BCryptRemoveContextFunctionProvider(
        dwTable: u32,
        pszContext: Pcwstr,
        dwInterface: u32,
        pszFunction: Pcwstr,
        pszProvider: Pcwstr,
    ) -> Ntstatus;
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn bcrypt_register_ksp(dll: &std::path::Path) -> Result<(), String> {
    let dll_abs = dll
        .canonicalize()
        .map_err(|e| format!("Failed to canonicalize DLL path '{}': {e}", dll.display()))?;

    // CNG resolves provider DLLs from System32 — copy there first
    let sys_dir = std::env::var("SystemRoot")
        .map_err(|_e| "SystemRoot environment variable not set".to_owned())?;
    let dest = std::path::PathBuf::from(&sys_dir)
        .join("System32")
        .join("cosmian_cng.dll");
    std::fs::copy(&dll_abs, &dest).map_err(|e| {
        format!(
            "Failed to copy DLL to '{}': {e} — run as Administrator?",
            dest.display()
        )
    })?;

    let provider_name_w = to_wide(KSP_PROVIDER_NAME);
    let mut dll_filename_w = to_wide("cosmian_cng.dll");
    #[allow(
        clippy::as_ptr_cast_mut,
        clippy::as_conversions,
        clippy::ptr_cast_constness
    )]
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
        let status = BCryptRegisterProvider(
            provider_name_w.as_ptr(),
            0,
            std::ptr::from_ref(&provider_reg),
        );
        if status != 0 {
            return Err(format!(
                "BCryptRegisterProvider failed with NTSTATUS {status:#010x}"
            ));
        }

        let _ = BCryptAddContextFunction(
            CRYPT_LOCAL,
            std::ptr::null(),
            NCRYPT_KEY_STORAGE_INTERFACE,
            NCRYPT_KEY_STORAGE_ALGORITHM.as_ptr(),
            CRYPT_PRIORITY_BOTTOM,
        );

        let status = BCryptAddContextFunctionProvider(
            CRYPT_LOCAL,
            std::ptr::null(),
            NCRYPT_KEY_STORAGE_INTERFACE,
            NCRYPT_KEY_STORAGE_ALGORITHM.as_ptr(),
            provider_name_w.as_ptr(),
            CRYPT_PRIORITY_BOTTOM,
        );
        if status != 0 {
            return Err(format!(
                "BCryptAddContextFunctionProvider failed with NTSTATUS {status:#010x}"
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn bcrypt_unregister_ksp() -> Result<(), String> {
    let provider_name_w = to_wide(KSP_PROVIDER_NAME);
    unsafe {
        let _ = BCryptRemoveContextFunctionProvider(
            CRYPT_LOCAL,
            std::ptr::null(),
            NCRYPT_KEY_STORAGE_INTERFACE,
            NCRYPT_KEY_STORAGE_ALGORITHM.as_ptr(),
            provider_name_w.as_ptr(),
        );
        let status = BCryptUnregisterProvider(provider_name_w.as_ptr());
        // STATUS_NOT_FOUND = 0xC0000225 — already gone
        if status != 0 && status != -0x3FFF_FDDB_i32 {
            return Err(format!(
                "BCryptUnregisterProvider failed with NTSTATUS {status:#010x}"
            ));
        }
    }
    // Remove DLL from System32
    if let Ok(sys_root) = std::env::var("SystemRoot") {
        let dll_path = std::path::PathBuf::from(sys_root)
            .join("System32")
            .join("cosmian_cng.dll");
        drop(std::fs::remove_file(dll_path));
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn bcrypt_is_ksp_registered() -> bool {
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW,
    };

    let key_path =
        format!(r"SYSTEM\CurrentControlSet\Control\Cryptography\Providers\{KSP_PROVIDER_NAME}\UM");
    let key_path_w = to_wide(&key_path);

    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
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
        let _ = RegCloseKey(hkey);
        true
    }
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
