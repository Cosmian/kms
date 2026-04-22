/// Windows CNG Key Storage Provider (KSP) function table implementation.
///
/// This module defines the `NCRYPT_KEY_STORAGE_FUNCTION_TABLE` exported via
/// `GetKeyStorageInterface`.  Each function pointer maps a Windows NCrypt
/// operation to a Cosmian KMS REST API call.
///
/// Design notes:
/// - Provider and key contexts are heap-allocated Rust structs; their raw
///   addresses are cast to the opaque `NCRYPT_PROV_HANDLE` / `NCRYPT_KEY_HANDLE`
///   (`usize`) types that Windows expects.
/// - No panics across FFI boundaries — errors are converted to
///   `SECURITY_STATUS` codes and logged.
/// - The shared Tokio runtime in `backend.rs` handles all async I/O.
#[cfg(windows)]
use std::{path::PathBuf, sync::Arc};

#[cfg(windows)]
use cosmian_logger::error;
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    BCryptBufferDesc,
    NCryptAlgorithmName, NCryptKeyName,
    NCRYPT_IMPL_SOFTWARE_FLAG,
    NCRYPT_ALLOW_EXPORT_FLAG, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG,
};

// NCrypt constants not provided by windows-sys — values from ncryptprovider.h
#[cfg(windows)]
const NCRYPT_IMPL_HARDWARE_FLAG: u32 = 0x0000_0001;
#[cfg(windows)]
const NCRYPT_SIGN_OPERATION: u32 = 0x0000_0001;
#[cfg(windows)]
const NCRYPT_DECRYPT_OPERATION: u32 = 0x0000_0002;
#[cfg(windows)]
const NCRYPT_ENCRYPT_OPERATION: u32 = 0x0000_0004;
#[cfg(windows)]
const NCRYPT_KEY_NAME_PROPERTY: *const u16 = {
    // "Name\0" as UTF-16LE  — same value as NCRYPT_NAME_PROPERTY
    // We cast the NCRYPT_NAME_PROPERTY wide-string constant.
    // We can just use NCRYPT_NAME_PROPERTY for key name queries.
    std::ptr::null()
};
#[cfg(windows)]
const NCRYPT_MAX_NAME_LEN_PROPERTY: u32 = 260;
#[cfg(windows)]
const NCRYPT_ALGORITHM_OPERATIONS_PARAMETER: u32 = 0x0000_0002;
#[cfg(windows)]
const NCRYPT_EXPORT_LEGACY_ALLOW_EXPORT_FLAG: u32 = 0x0000_0400;

// CNG padding flag constants
#[cfg(windows)]
const BCRYPT_PAD_NONE: u32 = 0x0000_0001;
#[cfg(windows)]
const BCRYPT_PAD_PKCS1: u32 = 0x0000_0002;
#[cfg(windows)]
const BCRYPT_PAD_OAEP: u32 = 0x0000_0004;
#[cfg(windows)]
const BCRYPT_PAD_PSS: u32 = 0x0000_0008;

// ─── Padding info structures (not provided by windows-sys) ───────────────────

/// `BCRYPT_PKCS1_PADDING_INFO` — passed for PKCS#1 v1.5 sign/verify.
/// Layout: { LPCWSTR pszAlgId; }
#[cfg(windows)]
#[repr(C)]
struct BcryptPkcs1PaddingInfo {
    psz_alg_id: *const u16,
}

/// `BCRYPT_PSS_PADDING_INFO` — passed for PSS sign/verify.
/// Layout: { LPCWSTR pszAlgId; ULONG cbSalt; }
#[cfg(windows)]
#[repr(C)]
struct BcryptPssPaddingInfo {
    psz_alg_id: *const u16,
    cb_salt: u32,
}

/// `BCRYPT_OAEP_PADDING_INFO` — passed for OAEP encrypt/decrypt.
/// Layout: { LPCWSTR pszAlgId; PUCHAR pbLabel; ULONG cbLabel; }
#[cfg(windows)]
#[repr(C)]
struct BcryptOaepPaddingInfo {
    psz_alg_id: *const u16,
    _pb_label: *const u8,
    _cb_label: u32,
}

#[cfg(windows)]
use crate::{
    backend,
    error::{
        KspError, KspResult, SecurityStatus, ERROR_SUCCESS, NTE_BAD_ALGID,
        NTE_BUFFER_TOO_SMALL, NTE_FAIL, NTE_INVALID_HANDLE, NTE_INVALID_PARAMETER, NTE_NOT_SUPPORTED,
        NTE_NO_KEY, NTE_PERM, STATUS_SUCCESS_VAL,
    },
    key::{CngKeyCtx, ExportPolicy, KeyAlgorithm, KeyState, KeyUsage, PendingCreation},
};

// ─── Provider name ────────────────────────────────────────────────────────────

/// The display name of this KSP as registered in the Windows Registry.
pub const KSP_PROVIDER_NAME: &str = "Cosmian KMS Key Storage Provider";
pub const KSP_PROVIDER_NAME_W: &[u16] = &[
    0x0043, 0x006F, 0x0073, 0x006D, 0x0069, 0x0061, 0x006E, 0x0020, 0x004B, 0x004D, 0x0053,
    0x0020, 0x004B, 0x0065, 0x0079, 0x0020, 0x0053, 0x0074, 0x006F, 0x0072, 0x0061, 0x0067,
    0x0065, 0x0020, 0x0050, 0x0072, 0x006F, 0x0076, 0x0069, 0x0064, 0x0065, 0x0072, 0x0000,
];

// ─── Provider context ─────────────────────────────────────────────────────────

pub const PROVIDER_CTX_MAGIC: u32 = 0xC0_5A_1A_AC;

/// Heap-allocated provider context.  Address cast to `NCRYPT_PROV_HANDLE`.
#[cfg(windows)]
pub struct CngProviderCtx {
    pub magic: u32,
    pub client: Arc<ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kms_client::KmsClient>,
}

#[cfg(windows)]
impl CngProviderCtx {
    unsafe fn from_handle(handle: usize) -> KspResult<&'static mut Self> {
        if handle == 0 {
            return Err(KspError::InvalidHandle);
        }
        #[allow(clippy::as_conversions)]
        let ptr = handle as *mut Self;
        let ctx = unsafe { &mut *ptr };
        if ctx.magic != PROVIDER_CTX_MAGIC {
            return Err(KspError::InvalidHandle);
        }
        Ok(ctx)
    }
}

// ─── Helper: write bytes into output buffer with size check ──────────────────

/// Copy `data` into `pb_output/cb_output` and write the actual size to
/// `*pcb_result`.  If `pb_output` is null, only fill `*pcb_result`.
#[cfg(windows)]
unsafe fn write_output(
    pb_output: *mut u8,
    cb_output: u32,
    pcb_result: *mut u32,
    data: &[u8],
) -> SecurityStatus {
    let needed = u32::try_from(data.len()).unwrap_or(u32::MAX);
    if !pcb_result.is_null() {
        unsafe { *pcb_result = needed; }
    }
    if pb_output.is_null() {
        return ERROR_SUCCESS;
    }
    if cb_output < needed {
        return NTE_BUFFER_TOO_SMALL;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), pb_output, data.len());
    }
    ERROR_SUCCESS
}

/// Encode a Rust `&str` as a null-terminated UTF-16 little-endian byte slice.
#[cfg(windows)]
fn str_to_wide_bytes(s: &str) -> Vec<u8> {
    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    wide.iter()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

/// Decode a null-terminated UTF-16 wide string from a raw pointer.
#[cfg(windows)]
unsafe fn wide_ptr_to_string(ptr: *const u16) -> KspResult<String> {
    if ptr.is_null() {
        return Err(KspError::InvalidParameter("null wide string".to_owned()));
    }
    let mut len = 0_usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
    }
    #[allow(clippy::as_conversions)]
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16(slice).map_err(|_| KspError::StringConversion)
}

/// Parse a CNG hash algorithm name (wide string) into a `HashingAlgorithm`.
/// Returns `None` if the pointer is null or the algorithm is unknown.
#[cfg(windows)]
unsafe fn parse_hash_alg_from_wide(ptr: *const u16) -> Option<ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm> {
    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm;
    if ptr.is_null() {
        return None;
    }
    let name = unsafe { wide_ptr_to_string(ptr) }.ok()?;
    match name.to_ascii_uppercase().as_str() {
        "SHA1" => Some(HashingAlgorithm::SHA1),
        "SHA224" | "SHA-224" => Some(HashingAlgorithm::SHA224),
        "SHA256" | "SHA-256" => Some(HashingAlgorithm::SHA256),
        "SHA384" | "SHA-384" => Some(HashingAlgorithm::SHA384),
        "SHA512" | "SHA-512" => Some(HashingAlgorithm::SHA512),
        _ => None,
    }
}

// ─── KSP function implementations ────────────────────────────────────────────

/// `NCryptOpenStorageProvider` — initialise a provider session.
#[cfg(windows)]
unsafe extern "system" fn open_provider(
    ph_provider: *mut usize,
    _psz_provider_name: *const u16,
    _dw_flags: u32,
) -> SecurityStatus {
    if ph_provider.is_null() {
        return NTE_INVALID_PARAMETER;
    }

    // Locate ckms.toml: check DLL directory first, then default search.
    #[cfg(windows)]
    let dll_dir = crate::dll_directory();
    #[cfg(not(windows))]
    let dll_dir: Option<PathBuf> = None;

    let explicit_conf: Option<PathBuf> = dll_dir.as_deref().and_then(|dir| {
        let candidate = dir.join("ckms.toml");
        if candidate.exists() { Some(candidate) } else { None }
    });

    match backend::get_kms_client(explicit_conf) {
        Ok(client) => {
            let ctx = Box::new(CngProviderCtx {
                magic: PROVIDER_CTX_MAGIC,
                client: Arc::new(client),
            });
            let raw = Box::into_raw(ctx);
            #[allow(clippy::as_conversions)]
            unsafe { *ph_provider = raw as usize; }
            ERROR_SUCCESS
        }
        Err(e) => {
            error!("CNG KSP open_provider: {e}");
            NTE_FAIL
        }
    }
}

/// `NCryptFreeProvider`
#[cfg(windows)]
unsafe extern "system" fn free_provider(h_provider: usize) -> SecurityStatus {
    if h_provider == 0 {
        return NTE_INVALID_HANDLE;
    }
    #[allow(clippy::as_conversions)]
    let ptr = h_provider as *mut CngProviderCtx;
    let mut ctx = unsafe { Box::from_raw(ptr) };
    ctx.magic = 0;
    ERROR_SUCCESS
}

/// `NCryptOpenKey` — open an existing named key from the KMS.
#[cfg(windows)]
unsafe extern "system" fn open_key(
    h_provider: usize,
    ph_key: *mut usize,
    psz_key_name: *const u16,
    _dw_legacy_key_spec: u32,
    _dw_flags: u32,
) -> SecurityStatus {
    if ph_key.is_null() || psz_key_name.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let prov = match unsafe { CngProviderCtx::from_handle(h_provider) } {
        Ok(p) => p,
        Err(_) => return NTE_INVALID_HANDLE,
    };
    let name = match unsafe { wide_ptr_to_string(psz_key_name) } {
        Ok(n) => n,
        Err(_) => return NTE_INVALID_PARAMETER,
    };

    let priv_uid = match backend::locate_key_by_name(&prov.client, &name) {
        Ok(uid) => uid,
        Err(KspError::KeyNotFound(_)) => return NTE_NO_KEY,
        Err(e) => {
            error!("CNG KSP open_key({name}): {e}");
            return NTE_FAIL;
        }
    };

    // Fetch attributes to determine algorithm and usage
    let attrs = match backend::get_key_attributes(&prov.client, &priv_uid) {
        Ok(a) => a,
        Err(e) => {
            error!("CNG KSP open_key attrs({name}): {e}");
            return NTE_FAIL;
        }
    };

    let algorithm = attrs_to_algorithm(&attrs);
    let usage = attrs_to_usage(&attrs);

    let ctx = CngKeyCtx::new_persisted(
        Arc::clone(&prov.client),
        priv_uid.clone(),
        None,
        algorithm,
        name,
        usage,
        ExportPolicy::default(),
    );
    let raw = Box::into_raw(ctx);
    #[allow(clippy::as_conversions)]
    unsafe { *ph_key = raw as usize; }
    ERROR_SUCCESS
}

/// `NCryptCreatePersistedKey` — stage a key for creation (finalized later).
#[cfg(windows)]
unsafe extern "system" fn create_persisted_key(
    h_provider: usize,
    ph_key: *mut usize,
    psz_alg_id: *const u16,
    psz_key_name: *const u16,
    _dw_legacy_key_spec: u32,
    _dw_flags: u32,
) -> SecurityStatus {
    if ph_key.is_null() || psz_alg_id.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let prov = match unsafe { CngProviderCtx::from_handle(h_provider) } {
        Ok(p) => p,
        Err(_) => return NTE_INVALID_HANDLE,
    };
    let alg_name = match unsafe { wide_ptr_to_string(psz_alg_id) } {
        Ok(n) => n,
        Err(_) => return NTE_INVALID_PARAMETER,
    };
    let key_name: String = if psz_key_name.is_null() {
        uuid::Uuid::new_v4().to_string()
    } else {
        match unsafe { wide_ptr_to_string(psz_key_name) } {
            Ok(n) => n,
            Err(_) => uuid::Uuid::new_v4().to_string(),
        }
    };

    let algorithm = match KeyAlgorithm::from_cng_name(&alg_name, 0) {
        Ok(a) => a,
        Err(_) => return NTE_BAD_ALGID,
    };

    let pending = PendingCreation {
        algorithm,
        key_name,
        usage: KeyUsage::SIGN | KeyUsage::DECRYPT,
        export_policy: ExportPolicy::default(),
    };
    let ctx = CngKeyCtx::new_pending(Arc::clone(&prov.client), pending);
    let raw = Box::into_raw(ctx);
    #[allow(clippy::as_conversions)]
    unsafe { *ph_key = raw as usize; }
    ERROR_SUCCESS
}

/// `NCryptFinalizeKey` — commit a pending key to the KMS.
#[cfg(windows)]
unsafe extern "system" fn finalize_key(
    _h_provider: usize,
    h_key: usize,
    _dw_flags: u32,
) -> SecurityStatus {
    let ctx = match unsafe { CngKeyCtx::from_handle(h_key) } {
        Ok(c) => c,
        Err(_) => return NTE_INVALID_HANDLE,
    };
    match ctx.finalize() {
        Ok(()) => ERROR_SUCCESS,
        Err(e) => {
            error!("CNG KSP finalize_key: {e}");
            e.to_security_status()
        }
    }
}

/// `NCryptDeleteKey` — revoke + destroy a key from the KMS and free the context.
#[cfg(windows)]
unsafe extern "system" fn delete_key(
    _h_provider: usize,
    h_key: usize,
    _dw_flags: u32,
) -> SecurityStatus {
    let ctx = match unsafe { CngKeyCtx::from_handle(h_key) } {
        Ok(c) => c,
        Err(_) => return NTE_INVALID_HANDLE,
    };
    let result = match &ctx.state {
        KeyState::Persisted { priv_uid, pub_uid, .. } => {
            // Revoke both keys first (Active keys require revocation before destroy)
            drop(backend::revoke_key(&ctx.client, priv_uid));
            if let Some(pub_id) = pub_uid {
                drop(backend::revoke_key(&ctx.client, pub_id));
            }
            // Now destroy
            let r = match backend::destroy_key(&ctx.client, priv_uid) {
                Ok(()) => ERROR_SUCCESS,
                Err(e) => {
                    error!("CNG KSP delete_key: {e}");
                    e.to_security_status()
                }
            };
            if let Some(pub_id) = pub_uid {
                drop(backend::destroy_key(&ctx.client, pub_id));
            }
            r
        }
        KeyState::Pending(_) => ERROR_SUCCESS,
    };
    unsafe { CngKeyCtx::free(h_key) };
    result
}

/// `NCryptFreeKey`
#[cfg(windows)]
unsafe extern "system" fn free_key(
    _h_provider: usize,
    h_key: usize,
) -> SecurityStatus {
    unsafe { CngKeyCtx::free(h_key) };
    ERROR_SUCCESS
}

/// `NCryptFreeBuffer` — free a buffer allocated by the KSP (e.g. in EnumKeys).
#[cfg(windows)]
unsafe extern "system" fn free_buffer(_pv_input: *mut core::ffi::c_void) -> SecurityStatus {
    // Buffers we allocate are Vec<u8> turned into raw pointers via Box.
    // For simplicity, any buffer we hand out is a Box<[u8]> leaked.
    // We can't safely free unknown pointers; caller is responsible.
    // Return success; memory is managed by Windows-allocated heap in production.
    ERROR_SUCCESS
}

/// `NCryptGetKeyProperty`
#[cfg(windows)]
unsafe extern "system" fn get_key_property(
    _h_provider: usize,
    h_key: usize,
    psz_property: *const u16,
    pb_output: *mut u8,
    cb_output: u32,
    pcb_result: *mut u32,
    _dw_flags: u32,
) -> SecurityStatus {
    if psz_property.is_null() || pcb_result.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let ctx = match unsafe { CngKeyCtx::from_handle(h_key) } {
        Ok(c) => c,
        Err(_) => return NTE_INVALID_HANDLE,
    };
    let prop = match unsafe { wide_ptr_to_string(psz_property) } {
        Ok(p) => p,
        Err(_) => return NTE_INVALID_PARAMETER,
    };

    match prop.as_str() {
        "Algorithm" => {
            let alg = match ctx.algorithm() {
                Ok(a) => a.cng_alg_id(),
                Err(_) => return NTE_INVALID_PARAMETER,
            };
            let data = str_to_wide_bytes(alg);
            unsafe { write_output(pb_output, cb_output, pcb_result, &data) }
        }
        "Algorithm Group" => {
            let group = match ctx.algorithm() {
                Ok(KeyAlgorithm::Rsa { .. }) => "RSA",
                Ok(KeyAlgorithm::Ec { .. }) => "ECDSA",
                Err(_) => return NTE_INVALID_PARAMETER,
            };
            let data = str_to_wide_bytes(group);
            unsafe { write_output(pb_output, cb_output, pcb_result, &data) }
        }
        "Length" | "KeyLength" => {
            let bits: u32 = match ctx.algorithm() {
                Ok(KeyAlgorithm::Rsa { bits }) => *bits,
                Ok(KeyAlgorithm::Ec { curve }) => {
                    u32::try_from(curve.coord_size() * 8).unwrap_or(0)
                }
                Err(_) => return NTE_INVALID_PARAMETER,
            };
            let data = bits.to_le_bytes();
            unsafe { write_output(pb_output, cb_output, pcb_result, &data) }
        }
        "Name" => {
            let data = str_to_wide_bytes(ctx.key_name());
            unsafe { write_output(pb_output, cb_output, pcb_result, &data) }
        }
        "UniqueName" => {
            let uid_or_name = ctx
                .priv_uid()
                .unwrap_or_else(|_| ctx.key_name())
                .to_owned();
            let data = str_to_wide_bytes(&uid_or_name);
            unsafe { write_output(pb_output, cb_output, pcb_result, &data) }
        }
        "KeyUsageProperty" => {
            let bits = ctx.usage().bits();
            let data = bits.to_le_bytes();
            unsafe { write_output(pb_output, cb_output, pcb_result, &data) }
        }
        "Export Policy" => {
            let ep = ctx.export_policy();
            let mut bits: u32 = 0;
            if ep.allow_export {
                bits |= NCRYPT_ALLOW_EXPORT_FLAG;
            }
            if ep.allow_plaintext_export {
                bits |= NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            }
            let data = bits.to_le_bytes();
            unsafe { write_output(pb_output, cb_output, pcb_result, &data) }
        }
        _ => NTE_NOT_SUPPORTED,
    }
}

/// `NCryptSetKeyProperty`
#[cfg(windows)]
unsafe extern "system" fn set_key_property(
    _h_provider: usize,
    h_key: usize,
    psz_property: *const u16,
    pb_input: *const u8,
    cb_input: u32,
    _dw_flags: u32,
) -> SecurityStatus {
    if psz_property.is_null() || pb_input.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let ctx = match unsafe { CngKeyCtx::from_handle(h_key) } {
        Ok(c) => c,
        Err(_) => return NTE_INVALID_HANDLE,
    };
    let prop = match unsafe { wide_ptr_to_string(psz_property) } {
        Ok(p) => p,
        Err(_) => return NTE_INVALID_PARAMETER,
    };
    let input = unsafe { std::slice::from_raw_parts(pb_input, cb_input as usize) };

    match prop.as_str() {
        "KeyUsageProperty" => {
            if input.len() < 4 {
                return NTE_INVALID_PARAMETER;
            }
            let bits = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
            let usage = KeyUsage::from_bits_truncate(bits);
            match &mut ctx.state {
                KeyState::Pending(p) => p.usage = usage,
                KeyState::Persisted { usage: u, .. } => *u = usage,
            }
            ERROR_SUCCESS
        }
        "Export Policy" => {
            if input.len() < 4 {
                return NTE_INVALID_PARAMETER;
            }
            let bits = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
            let ep = ExportPolicy {
                allow_export: bits & NCRYPT_ALLOW_EXPORT_FLAG != 0,
                allow_plaintext_export: bits & NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG != 0,
            };
            match &mut ctx.state {
                KeyState::Pending(p) => p.export_policy = ep,
                KeyState::Persisted {
                    export_policy,
                    ..
                } => *export_policy = ep,
            }
            ERROR_SUCCESS
        }
        "Length" | "KeyLength" => {
            if input.len() < 4 {
                return NTE_INVALID_PARAMETER;
            }
            let bits = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
            if let KeyState::Pending(p) = &mut ctx.state {
                if let KeyAlgorithm::Rsa { bits: b } = &mut p.algorithm {
                    *b = bits;
                }
            }
            ERROR_SUCCESS
        }
        _ => NTE_NOT_SUPPORTED,
    }
}

/// `NCryptGetProviderProperty`
#[cfg(windows)]
unsafe extern "system" fn get_provider_property(
    _h_provider: usize,
    psz_property: *const u16,
    pb_output: *mut u8,
    cb_output: u32,
    pcb_result: *mut u32,
    _dw_flags: u32,
) -> SecurityStatus {
    if psz_property.is_null() || pcb_result.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let prop = match unsafe { wide_ptr_to_string(psz_property) } {
        Ok(p) => p,
        Err(_) => return NTE_INVALID_PARAMETER,
    };

    match prop.as_str() {
        "Name" => {
            let data = str_to_wide_bytes(KSP_PROVIDER_NAME);
            unsafe { write_output(pb_output, cb_output, pcb_result, &data) }
        }
        "Implementation Type" => {
            // NCRYPT_IMPL_SOFTWARE_FLAG = 1; we advertise software (the KMS backend)
            let bits: u32 = NCRYPT_IMPL_SOFTWARE_FLAG;
            let data = bits.to_le_bytes();
            unsafe { write_output(pb_output, cb_output, pcb_result, &data) }
        }
        "Max Name Length" => {
            let max: u32 = 260; // MAX_PATH
            let data = max.to_le_bytes();
            unsafe { write_output(pb_output, cb_output, pcb_result, &data) }
        }
        _ => NTE_NOT_SUPPORTED,
    }
}

/// `NCryptSetProviderProperty` — not needed for a software KSP.
#[cfg(windows)]
unsafe extern "system" fn set_provider_property(
    _h_provider: usize,
    _psz_property: *const u16,
    _pb_input: *const u8,
    _cb_input: u32,
    _dw_flags: u32,
) -> SecurityStatus {
    NTE_NOT_SUPPORTED
}

/// `NCryptSignHash`
#[cfg(windows)]
unsafe extern "system" fn sign_hash(
    _h_provider: usize,
    h_key: usize,
    pv_padding_info: *const core::ffi::c_void,
    pb_hash_value: *const u8,
    cb_hash_value: u32,
    pb_signature: *mut u8,
    cb_signature: u32,
    pcb_result: *mut u32,
    dw_flags: u32,
) -> SecurityStatus {
    if pb_hash_value.is_null() || pcb_result.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let ctx = match unsafe { CngKeyCtx::from_handle(h_key) } {
        Ok(c) => c,
        Err(_) => return NTE_INVALID_HANDLE,
    };
    let uid = match ctx.priv_uid() {
        Ok(u) => u.to_owned(),
        Err(e) => return e.to_security_status(),
    };
    let hash = unsafe { std::slice::from_raw_parts(pb_hash_value, cb_hash_value as usize) };

    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::PaddingMethod;

    // dw_flags: BCRYPT_PAD_PSS = 0x8, BCRYPT_PAD_PKCS1 = 0x2
    let (padding, hash_alg, salt_len) = match dw_flags & 0xF {
        x if x == BCRYPT_PAD_PSS => {
            // Read hash algorithm and salt length from BCRYPT_PSS_PADDING_INFO
            let (alg, salt) = if !pv_padding_info.is_null() {
                let info = unsafe { &*(pv_padding_info as *const BcryptPssPaddingInfo) };
                let alg = unsafe { parse_hash_alg_from_wide(info.psz_alg_id) };
                (alg, Some(info.cb_salt as i32))
            } else {
                (None, Some(hash.len() as i32))
            };
            let alg = alg.unwrap_or_else(|| hash_alg_from_digest_len(hash.len()));
            (Some(PaddingMethod::PSS), alg, salt)
        }
        x if x == BCRYPT_PAD_PKCS1 => {
            // Read hash algorithm from BCRYPT_PKCS1_PADDING_INFO
            let alg = if !pv_padding_info.is_null() {
                let info = unsafe { &*(pv_padding_info as *const BcryptPkcs1PaddingInfo) };
                unsafe { parse_hash_alg_from_wide(info.psz_alg_id) }
            } else {
                None
            };
            let alg = alg.unwrap_or_else(|| hash_alg_from_digest_len(hash.len()));
            (Some(PaddingMethod::PKCS1v15), alg, None)
        }
        _ => {
            // No padding (ECDSA) or unknown — infer from hash length
            let alg = hash_alg_from_digest_len(hash.len());
            (None, alg, None)
        }
    };

    match backend::sign_hash(&ctx.client, &uid, hash, hash_alg, padding, salt_len) {
        Ok(sig) => unsafe { write_output(pb_signature, cb_signature, pcb_result, &sig) },
        Err(e) => {
            error!("CNG KSP sign_hash: {e}");
            e.to_security_status()
        }
    }
}

/// `NCryptVerifySignature` — verify a signature using the public key in the KMS.
#[cfg(windows)]
unsafe extern "system" fn verify_signature(
    _h_provider: usize,
    h_key: usize,
    pv_padding_info: *const core::ffi::c_void,
    pb_hash_value: *const u8,
    cb_hash_value: u32,
    pb_signature: *const u8,
    cb_signature: u32,
    dw_flags: u32,
) -> SecurityStatus {
    if pb_hash_value.is_null() || pb_signature.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let ctx = match unsafe { CngKeyCtx::from_handle(h_key) } {
        Ok(c) => c,
        Err(_) => return NTE_INVALID_HANDLE,
    };
    // For verification, use the public key if available, otherwise fall back to private key
    let uid = match &ctx.state {
        KeyState::Persisted { pub_uid: Some(uid), .. } => uid.clone(),
        KeyState::Persisted { priv_uid, .. } => priv_uid.clone(),
        KeyState::Pending(_) => return NTE_INVALID_PARAMETER,
    };
    let hash = unsafe { std::slice::from_raw_parts(pb_hash_value, cb_hash_value as usize) };
    let signature = unsafe { std::slice::from_raw_parts(pb_signature, cb_signature as usize) };

    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::PaddingMethod;

    let (padding, hash_alg, salt_len) = match dw_flags & 0xF {
        x if x == BCRYPT_PAD_PSS => {
            let (alg, salt) = if !pv_padding_info.is_null() {
                let info = unsafe { &*(pv_padding_info as *const BcryptPssPaddingInfo) };
                let alg = unsafe { parse_hash_alg_from_wide(info.psz_alg_id) };
                (alg, Some(info.cb_salt as i32))
            } else {
                (None, Some(hash.len() as i32))
            };
            let alg = alg.unwrap_or_else(|| hash_alg_from_digest_len(hash.len()));
            (Some(PaddingMethod::PSS), alg, salt)
        }
        x if x == BCRYPT_PAD_PKCS1 => {
            let alg = if !pv_padding_info.is_null() {
                let info = unsafe { &*(pv_padding_info as *const BcryptPkcs1PaddingInfo) };
                unsafe { parse_hash_alg_from_wide(info.psz_alg_id) }
            } else {
                None
            };
            let alg = alg.unwrap_or_else(|| hash_alg_from_digest_len(hash.len()));
            (Some(PaddingMethod::PKCS1v15), alg, None)
        }
        _ => {
            let alg = hash_alg_from_digest_len(hash.len());
            (None, alg, None)
        }
    };

    match backend::verify_signature(&ctx.client, &uid, hash, signature, hash_alg, padding, salt_len) {
        Ok(true) => ERROR_SUCCESS,
        Ok(false) => {
            // NTE_BAD_SIGNATURE
            0x8009_0006_u32 as i32
        }
        Err(e) => {
            error!("CNG KSP verify_signature: {e}");
            e.to_security_status()
        }
    }
}

/// `NCryptEncrypt`
#[cfg(windows)]
unsafe extern "system" fn encrypt(
    _h_provider: usize,
    h_key: usize,
    pb_input: *const u8,
    cb_input: u32,
    pv_padding_info: *const core::ffi::c_void,
    pb_output: *mut u8,
    cb_output: u32,
    pcb_result: *mut u32,
    dw_flags: u32,
) -> SecurityStatus {
    if pb_input.is_null() || pcb_result.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let ctx = match unsafe { CngKeyCtx::from_handle(h_key) } {
        Ok(c) => c,
        Err(_) => return NTE_INVALID_HANDLE,
    };
    // Encryption uses the public key.
    let uid = match ctx.pub_uid() {
        Ok(u) => u.to_owned(),
        Err(e) => return e.to_security_status(),
    };
    let plaintext = unsafe { std::slice::from_raw_parts(pb_input, cb_input as usize) };

    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::{
        HashingAlgorithm, PaddingMethod,
    };
    let (padding, hash_alg) = match dw_flags & 0xF {
        x if x == BCRYPT_PAD_OAEP => {
            // Read hash algorithm from BCRYPT_OAEP_PADDING_INFO
            let alg = if !pv_padding_info.is_null() {
                let info = unsafe { &*(pv_padding_info as *const BcryptOaepPaddingInfo) };
                unsafe { parse_hash_alg_from_wide(info.psz_alg_id) }
            } else {
                None
            };
            (PaddingMethod::OAEP, Some(alg.unwrap_or(HashingAlgorithm::SHA256)))
        }
        _ => (PaddingMethod::PKCS1v15, None),
    };

    match backend::encrypt_data(&ctx.client, &uid, plaintext, padding, hash_alg) {
        Ok(ct) => unsafe { write_output(pb_output, cb_output, pcb_result, &ct) },
        Err(e) => {
            error!("CNG KSP encrypt: {e}");
            e.to_security_status()
        }
    }
}

/// `NCryptDecrypt`
#[cfg(windows)]
unsafe extern "system" fn decrypt(
    _h_provider: usize,
    h_key: usize,
    pb_input: *const u8,
    cb_input: u32,
    pv_padding_info: *const core::ffi::c_void,
    pb_output: *mut u8,
    cb_output: u32,
    pcb_result: *mut u32,
    dw_flags: u32,
) -> SecurityStatus {
    if pb_input.is_null() || pcb_result.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let ctx = match unsafe { CngKeyCtx::from_handle(h_key) } {
        Ok(c) => c,
        Err(_) => return NTE_INVALID_HANDLE,
    };
    let uid = match ctx.priv_uid() {
        Ok(u) => u.to_owned(),
        Err(e) => return e.to_security_status(),
    };
    let ciphertext = unsafe { std::slice::from_raw_parts(pb_input, cb_input as usize) };

    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::{
        HashingAlgorithm, PaddingMethod,
    };
    let (padding, hash_alg) = match dw_flags & 0xF {
        x if x == BCRYPT_PAD_OAEP => {
            let alg = if !pv_padding_info.is_null() {
                let info = unsafe { &*(pv_padding_info as *const BcryptOaepPaddingInfo) };
                unsafe { parse_hash_alg_from_wide(info.psz_alg_id) }
            } else {
                None
            };
            (PaddingMethod::OAEP, Some(alg.unwrap_or(HashingAlgorithm::SHA256)))
        }
        _ => (PaddingMethod::PKCS1v15, None),
    };

    match backend::decrypt_data(&ctx.client, &uid, ciphertext, padding, hash_alg) {
        Ok(pt) => unsafe { write_output(pb_output, cb_output, pcb_result, &pt) },
        Err(e) => {
            error!("CNG KSP decrypt: {e}");
            e.to_security_status()
        }
    }
}

/// `NCryptExportKey`
#[cfg(windows)]
unsafe extern "system" fn export_key(
    _h_provider: usize,
    h_key: usize,
    _h_export_key: usize,
    psz_blob_type: *const u16,
    _p_parameter_list: *const BCryptBufferDesc,
    pb_output: *mut u8,
    cb_output: u32,
    pcb_result: *mut u32,
    _dw_flags: u32,
) -> SecurityStatus {
    if pcb_result.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let ctx = match unsafe { CngKeyCtx::from_handle(h_key) } {
        Ok(c) => c,
        Err(_) => return NTE_INVALID_HANDLE,
    };
    let blob_type = if psz_blob_type.is_null() {
        String::new()
    } else {
        match unsafe { wide_ptr_to_string(psz_blob_type) } {
            Ok(b) => b,
            Err(_) => return NTE_INVALID_PARAMETER,
        }
    };

    // Only public key blobs are exported; private blobs require explicit allow-export
    match blob_type.as_str() {
        "RSAPUBLICBLOB" | "ECCPUBLICBLOB" | "" => {
            match ctx.export_public_blob() {
                Ok(blob) => unsafe { write_output(pb_output, cb_output, pcb_result, &blob) },
                Err(e) => {
                    error!("CNG KSP export_key: {e}");
                    e.to_security_status()
                }
            }
        }
        "PRIVATEKEYBLOB" | "RSAPRIVATEBLOB" | "ECCPRIVATEBLOB" => {
            if !ctx.export_policy().allow_export {
                return NTE_PERM;
            }
            NTE_NOT_SUPPORTED
        }
        _ => NTE_NOT_SUPPORTED,
    }
}

/// `NCryptImportKey` — import a key blob into the KMS.
#[cfg(windows)]
unsafe extern "system" fn import_key(
    _h_provider: usize,
    _h_import_key: usize,
    _psz_blob_type: *const u16,
    _p_parameter_list: *const BCryptBufferDesc,
    _ph_key: *mut usize,
    _pb_data: *const u8,
    _cb_data: u32,
    _dw_flags: u32,
) -> SecurityStatus {
    NTE_NOT_SUPPORTED
}

/// `NCryptIsAlgSupported`
#[cfg(windows)]
unsafe extern "system" fn is_alg_supported(
    _h_provider: usize,
    psz_alg_id: *const u16,
    _dw_flags: u32,
) -> SecurityStatus {
    if psz_alg_id.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let alg = match unsafe { wide_ptr_to_string(psz_alg_id) } {
        Ok(a) => a,
        Err(_) => return NTE_INVALID_PARAMETER,
    };
    match alg.to_ascii_uppercase().as_str() {
        "RSA" | "ECDSA_P256" | "ECDSA_P384" | "ECDSA_P521" | "ECDH_P256" | "ECDH_P384"
        | "ECDH_P521" => ERROR_SUCCESS,
        _ => NTE_BAD_ALGID,
    }
}

/// `NCryptEnumAlgorithms` — return a list of supported algorithms.
///
/// Allocates an array of `NCryptAlgorithmName` structs filtered by the
/// requested operation class.
#[cfg(windows)]
unsafe extern "system" fn enum_algorithms(
    _h_provider: usize,
    dw_alg_class: u32,
    pdw_alg_count: *mut u32,
    pp_alg_list: *mut *mut NCryptAlgorithmName,
    _dw_flags: u32,
) -> SecurityStatus {
    if pdw_alg_count.is_null() || pp_alg_list.is_null() {
        return NTE_INVALID_PARAMETER;
    }

    // Algorithm definitions: (name, operations)
    // Operations: SIGN=1, DECRYPT=2 (asymmetric encryption), ENCRYPT=4
    struct AlgDef {
        name: &'static [u16],
        ops: u32,
    }

    // UTF-16LE null-terminated algorithm names
    static RSA_W: &[u16] = &[0x52, 0x53, 0x41, 0x00]; // "RSA\0"
    static ECDSA_P256_W: &[u16] = &[0x45, 0x43, 0x44, 0x53, 0x41, 0x5F, 0x50, 0x32, 0x35, 0x36, 0x00]; // "ECDSA_P256\0"
    static ECDSA_P384_W: &[u16] = &[0x45, 0x43, 0x44, 0x53, 0x41, 0x5F, 0x50, 0x33, 0x38, 0x34, 0x00]; // "ECDSA_P384\0"
    static ECDSA_P521_W: &[u16] = &[0x45, 0x43, 0x44, 0x53, 0x41, 0x5F, 0x50, 0x35, 0x32, 0x31, 0x00]; // "ECDSA_P521\0"
    static ECDH_P256_W: &[u16] = &[0x45, 0x43, 0x44, 0x48, 0x5F, 0x50, 0x32, 0x35, 0x36, 0x00]; // "ECDH_P256\0"
    static ECDH_P384_W: &[u16] = &[0x45, 0x43, 0x44, 0x48, 0x5F, 0x50, 0x33, 0x38, 0x34, 0x00]; // "ECDH_P384\0"
    static ECDH_P521_W: &[u16] = &[0x45, 0x43, 0x44, 0x48, 0x5F, 0x50, 0x35, 0x32, 0x31, 0x00]; // "ECDH_P521\0"

    let all_algs: &[AlgDef] = &[
        AlgDef { name: RSA_W, ops: NCRYPT_SIGN_OPERATION | NCRYPT_DECRYPT_OPERATION | NCRYPT_ENCRYPT_OPERATION },
        AlgDef { name: ECDSA_P256_W, ops: NCRYPT_SIGN_OPERATION },
        AlgDef { name: ECDSA_P384_W, ops: NCRYPT_SIGN_OPERATION },
        AlgDef { name: ECDSA_P521_W, ops: NCRYPT_SIGN_OPERATION },
        AlgDef { name: ECDH_P256_W, ops: 0 }, // key agreement — no CNG operation flag
        AlgDef { name: ECDH_P384_W, ops: 0 },
        AlgDef { name: ECDH_P521_W, ops: 0 },
    ];

    // Filter by requested operation class (0 = all)
    let filtered: Vec<&AlgDef> = if dw_alg_class == 0 {
        all_algs.iter().collect()
    } else {
        all_algs.iter().filter(|a| a.ops & dw_alg_class != 0).collect()
    };

    if filtered.is_empty() {
        unsafe {
            *pdw_alg_count = 0;
            *pp_alg_list = std::ptr::null_mut();
        }
        return ERROR_SUCCESS;
    }

    // Allocate array (callers free via NCryptFreeBuffer)
    let count = filtered.len();
    let layout = std::alloc::Layout::array::<NCryptAlgorithmName>(count)
        .unwrap_or(std::alloc::Layout::new::<NCryptAlgorithmName>());
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) } as *mut NCryptAlgorithmName;
    if ptr.is_null() {
        return NTE_FAIL;
    }

    for (i, alg) in filtered.iter().enumerate() {
        unsafe {
            let entry = &mut *ptr.add(i);
            entry.pszName = alg.name.as_ptr() as *mut u16;
            entry.dwClass = alg.ops;
            entry.dwAlgOperations = alg.ops;
            entry.dwFlags = 0;
        }
    }

    unsafe {
        *pdw_alg_count = count as u32;
        *pp_alg_list = ptr;
    }
    ERROR_SUCCESS
}

/// `NCryptEnumKeys` — enumerate CNG KSP keys from the KMS.
#[cfg(windows)]
unsafe extern "system" fn enum_keys(
    h_provider: usize,
    _psz_scope: *const u16,
    pp_key_name: *mut *mut NCryptKeyName,
    pp_enum_state: *mut *mut core::ffi::c_void,
    _dw_flags: u32,
) -> SecurityStatus {
    if pp_key_name.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let prov = match unsafe { CngProviderCtx::from_handle(h_provider) } {
        Ok(p) => p,
        Err(_) => return NTE_INVALID_HANDLE,
    };

    // Use enum state as index into a heap-allocated Vec of names
    let idx_ptr = pp_enum_state as *mut *mut usize;
    let idx: usize = if idx_ptr.is_null() || unsafe { *idx_ptr }.is_null() {
        0
    } else {
        unsafe { *(*idx_ptr as *mut usize) }
    };

    let keys = match backend::list_cng_keys(&prov.client) {
        Ok(k) => k,
        Err(e) => {
            error!("CNG KSP enum_keys: {e}");
            return NTE_FAIL;
        }
    };

    if idx >= keys.len() {
        // Signal end of enumeration per CNG convention
        return 0x8009_002A_u32 as i32; // NTE_FAIL acts as end signal when no more keys
    }

    let (name, _uid) = &keys[idx];
    // Allocate a NCRYPT_KEY_NAME struct (simplified: just the name pointer)
    // For full compliance we'd use CoTaskMemAlloc; here we leak a Box and
    // callers call NCryptFreeBuffer which is a no-op in our impl.
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let leaked = wide.into_boxed_slice();
    let ptr = Box::into_raw(leaked) as *mut NCryptKeyName;
    unsafe { *pp_key_name = ptr; }

    // Advance enum state
    if !idx_ptr.is_null() {
        let new_idx = Box::new(idx + 1);
        unsafe { *idx_ptr = Box::into_raw(new_idx) as *mut usize; }
    }

    ERROR_SUCCESS
}

/// `NCryptGenRandom` — delegate to Windows BCryptGenRandom.
#[cfg(windows)]
unsafe extern "system" fn gen_random(
    _h_provider: usize,
    pb_buffer: *mut u8,
    cb_buffer: u32,
    _dw_flags: u32,
) -> SecurityStatus {
    use windows_sys::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
    if pb_buffer.is_null() {
        return NTE_INVALID_PARAMETER;
    }
    let status = unsafe { BCryptGenRandom(std::ptr::null_mut(), pb_buffer, cb_buffer, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status == STATUS_SUCCESS_VAL {
        ERROR_SUCCESS
    } else {
        NTE_FAIL
    }
}

/// `NCryptNotifyChangeKey` — stub returning success (no event plumbing needed).
#[cfg(windows)]
unsafe extern "system" fn notify_change_key(
    _h_provider: usize,
    _ph_event: *mut windows_sys::Win32::Foundation::HANDLE,
    _dw_flags: u32,
) -> SecurityStatus {
    ERROR_SUCCESS
}

/// `NCryptSecretAgreement` — not supported.
#[cfg(windows)]
unsafe extern "system" fn secret_agreement(
    _h_provider: usize,
    _h_priv_key: usize,
    _h_pub_key: usize,
    _ph_agreed_secret: *mut usize,
    _dw_flags: u32,
) -> SecurityStatus {
    NTE_NOT_SUPPORTED
}

/// `NCryptDeriveKey` — not supported.
#[cfg(windows)]
unsafe extern "system" fn derive_key(
    _h_provider: usize,
    _h_shared_secret: usize,
    _pwsz_kdf: *const u16,
    _p_parameter_list: *const BCryptBufferDesc,
    _pb_derived_key: *mut u8,
    _cb_derived_key: u32,
    _pcb_result: *mut u32,
    _dw_flags: u32,
) -> SecurityStatus {
    NTE_NOT_SUPPORTED
}

/// `NCryptFreeSecret` — no-op.
#[cfg(windows)]
unsafe extern "system" fn free_secret(
    _h_provider: usize,
    _h_shared_secret: usize,
) -> SecurityStatus {
    ERROR_SUCCESS
}

/// `NCryptPromptUser` — interactive PIN dialog; not needed for automated KMS access.
#[cfg(windows)]
unsafe extern "system" fn prompt_user(
    _h_provider: usize,
    _h_key: usize,
    _psz_operation: *const u16,
    _dw_flags: u32,
) -> SecurityStatus {
    NTE_NOT_SUPPORTED
}

/// `NCryptKeyDerivation` — not supported.
#[cfg(windows)]
unsafe extern "system" fn key_derivation(
    _h_provider: usize,
    _h_key: usize,
    _p_parameter_list: *const BCryptBufferDesc,
    _pb_derived_key: *mut u8,
    _cb_derived_key: u32,
    _pcb_result: *mut u32,
    _dw_flags: u32,
) -> i32 {
    NTE_NOT_SUPPORTED
}

/// `NCryptCreateClaim` — not supported.
#[cfg(windows)]
unsafe extern "system" fn create_claim(
    _h_prov: usize,
    _h_subject_key: usize,
    _h_authority_key: usize,
    _dw_claim_type: u32,
    _p_parameter_list: *const BCryptBufferDesc,
    _pb_claim_blob: *mut u8,
    _cb_claim_blob: u32,
    _pcb_result: *mut u32,
    _dw_flags: u32,
) -> i32 {
    NTE_NOT_SUPPORTED
}

/// `NCryptVerifyClaim` — not supported.
#[cfg(windows)]
unsafe extern "system" fn verify_claim(
    _h_prov: usize,
    _h_subject_key: usize,
    _h_authority_key: usize,
    _dw_claim_type: u32,
    _p_parameter_list: *const BCryptBufferDesc,
    _pb_claim_blob: *const u8,
    _cb_claim_blob: u32,
    _p_output: *mut BCryptBufferDesc,
    _dw_flags: u32,
) -> i32 {
    NTE_NOT_SUPPORTED
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Infer hashing algorithm from digest byte length (fallback heuristic).
#[cfg(windows)]
fn hash_alg_from_digest_len(len: usize) -> ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm {
    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm;
    match len {
        20 => HashingAlgorithm::SHA1,
        28 => HashingAlgorithm::SHA224,
        32 => HashingAlgorithm::SHA256,
        48 => HashingAlgorithm::SHA384,
        64 => HashingAlgorithm::SHA512,
        _ => HashingAlgorithm::SHA256,
    }
}

// ─── Function table ───────────────────────────────────────────────────────────

/// The static `NCRYPT_KEY_STORAGE_FUNCTION_TABLE` returned by `GetKeyStorageInterface`.
///
/// Fields follow the exact order mandated by the header:
/// OpenProvider, OpenKey, CreatePersistedKey, GetProviderProperty, GetKeyProperty,
/// SetProviderProperty, SetKeyProperty, FinalizeKey, DeleteKey, FreeProvider, FreeKey,
/// FreeBuffer, Encrypt, Decrypt, IsAlgSupported, EnumAlgorithms, EnumKeys, ImportKey,
/// ExportKey, SignHash, VerifySignature, PromptUser, NotifyChangeKey, SecretAgreement,
/// DeriveKey, FreeSecret.
#[cfg(windows)]
pub static KSP_FUNCTION_TABLE: windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_STORAGE_FUNCTION_TABLE =
    windows_sys::Win32::Security::Cryptography::NCRYPT_KEY_STORAGE_FUNCTION_TABLE {
        Version: windows_sys::Win32::Security::Cryptography::BCRYPT_INTERFACE_VERSION {
            MajorVersion: 1,
            MinorVersion: 0,
        },
        OpenProvider: Some(open_provider),
        OpenKey: Some(open_key),
        CreatePersistedKey: Some(create_persisted_key),
        GetProviderProperty: Some(get_provider_property),
        GetKeyProperty: Some(get_key_property),
        SetProviderProperty: Some(set_provider_property),
        SetKeyProperty: Some(set_key_property),
        FinalizeKey: Some(finalize_key),
        DeleteKey: Some(delete_key),
        FreeProvider: Some(free_provider),
        FreeKey: Some(free_key),
        FreeBuffer: Some(free_buffer),
        Encrypt: Some(encrypt),
        Decrypt: Some(decrypt),
        IsAlgSupported: Some(is_alg_supported),
        EnumAlgorithms: Some(enum_algorithms),
        EnumKeys: Some(enum_keys),
        ImportKey: Some(import_key),
        ExportKey: Some(export_key),
        SignHash: Some(sign_hash),
        VerifySignature: Some(verify_signature),
        PromptUser: Some(prompt_user),
        NotifyChangeKey: Some(notify_change_key),
        SecretAgreement: Some(secret_agreement),
        DeriveKey: Some(derive_key),
        FreeSecret: Some(free_secret),
        KeyDerivation: Some(key_derivation),
        CreateClaim: Some(create_claim),
        VerifyClaim: Some(verify_claim),
    };

// ─── Attribute helpers ────────────────────────────────────────────────────────

/// Convert KMS `Attributes` to a `KeyAlgorithm`.
#[cfg(windows)]
fn attrs_to_algorithm(
    attrs: &ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attributes,
) -> KeyAlgorithm {
    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_2_1::kmip_types::{
        CryptographicAlgorithm, RecommendedCurve,
    };
    match attrs.cryptographic_algorithm {
        Some(CryptographicAlgorithm::RSA) => {
            let bits = u32::try_from(attrs.cryptographic_length.unwrap_or(2048)).unwrap_or(2048);
            KeyAlgorithm::Rsa { bits }
        }
        Some(CryptographicAlgorithm::EC) => {
            let curve = match attrs
                .cryptographic_domain_parameters
                .as_ref()
                .and_then(|p| p.recommended_curve)
            {
                Some(RecommendedCurve::P384) => EcCurve::P384,
                Some(RecommendedCurve::P521) => EcCurve::P521,
                _ => EcCurve::P256,
            };
            KeyAlgorithm::Ec { curve }
        }
        _ => KeyAlgorithm::Rsa { bits: 2048 },
    }
}

/// Convert KMS `Attributes` to `KeyUsage` flags.
#[cfg(windows)]
fn attrs_to_usage(
    attrs: &ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attributes,
) -> KeyUsage {
    use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_0::kmip_types::CryptographicUsageMask;
    let mut usage = KeyUsage::empty();
    if let Some(mask) = attrs.cryptographic_usage_mask {
        if mask.contains(CryptographicUsageMask::Sign) {
            usage |= KeyUsage::SIGN;
        }
        if mask.contains(CryptographicUsageMask::Decrypt) {
            usage |= KeyUsage::DECRYPT;
        }
        if mask.contains(CryptographicUsageMask::KeyAgreement) {
            usage |= KeyUsage::KEY_AGREEMENT;
        }
    }
    usage
}

// Re-export for use in blob.rs helpers called from key.rs
use crate::blob::EcCurve;
