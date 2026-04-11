//! Shared PKCS#11 helper functions used by both the `cosmian_pkcs11_verify`
//! binary and the integration test suite.
//!
//! The binary (`main.rs`) imports these via `use cosmian_pkcs11_verify::*`.
//! The integration tests live in `tests.rs` and reference them via `crate::`.

#![allow(
    unsafe_code,
    clippy::print_stdout,          // diagnostic binary — stdout output is intentional
    clippy::multiple_crate_versions,
    clippy::cargo_common_metadata,
    clippy::exhaustive_structs,    // clap derive structs are internal only
    clippy::std_instead_of_core,
)]

use std::{ffi::c_void, ptr};

use libloading::{Library, Symbol};
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_FLAGS, CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR_PTR, CK_KEY_TYPE,
    CK_MECHANISM, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_TRUE,
    CK_ULONG, CKA_CLASS, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL, CKA_SENSITIVE, CKA_VALUE_LEN,
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CKK_AES, CKM_AES_CBC_PAD, CKM_AES_KEY_GEN, CKO_CERTIFICATE,
    CKO_DATA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY, CKR_OK, CKU_USER,
};

// ---------------------------------------------------------------------------
// Step C helper
// ---------------------------------------------------------------------------

pub type GetFunctionListFn = unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;

pub fn call_get_function_list(lib: &Library) -> Result<*mut CK_FUNCTION_LIST, String> {
    // Safety: the symbol lookup and the call are both unsafe; we ensure the
    // library is live for the duration of the returned pointer's use in `run()`.
    let get_func_list: Symbol<GetFunctionListFn> = unsafe { lib.get(b"C_GetFunctionList\0") }
        .map_err(|e| format!("FAIL [C_GetFunctionList]: symbol not found in .so: {e}"))?;

    let mut func_list_ptr: *mut CK_FUNCTION_LIST = ptr::null_mut();
    // &raw mut avoids creating a reference to a potentially-uninitialised pointer.
    let rv = unsafe { get_func_list(&raw mut func_list_ptr) };

    if rv != CKR_OK {
        return Err(format!(
            "FAIL [C_GetFunctionList]: returned {} (0x{rv:08X})\n  \
             Hint: verify that ckms.toml exists, is valid TOML, and contains a \
             reachable [http_config].server_url.",
            ckr_name(rv)
        ));
    }

    if func_list_ptr.is_null() {
        return Err(
            "FAIL [C_GetFunctionList]: returned CKR_OK but function list pointer is null"
                .to_owned(),
        );
    }

    Ok(func_list_ptr)
}

// ---------------------------------------------------------------------------
// Step E helper
// ---------------------------------------------------------------------------

pub fn call_get_slot_list(func_list: &CK_FUNCTION_LIST) -> Result<CK_SLOT_ID, String> {
    let c_get_slot_list = func_list
        .C_GetSlotList
        .ok_or_else(|| "FAIL [C_GetSlotList]: not present in function list".to_owned())?;

    // First call: query the slot count.
    let token_present: CK_BBOOL = CK_TRUE;
    let mut count: CK_ULONG = 0;
    let rv = unsafe { c_get_slot_list(token_present, ptr::null_mut(), &raw mut count) };
    check_rv(rv, "C_GetSlotList (count)")?;

    if count == 0 {
        return Err("FAIL [C_GetSlotList]: provider reports zero slots".to_owned());
    }

    let slot_count = usize::try_from(count).map_err(|e| {
        format!("FAIL [C_GetSlotList]: slot count value out of range for usize: {e}")
    })?;

    // Second call: fill the slot buffer.
    let mut slots: Vec<CK_SLOT_ID> = vec![0; slot_count];
    let rv = unsafe { c_get_slot_list(token_present, slots.as_mut_ptr(), &raw mut count) };
    check_rv(rv, "C_GetSlotList (fill)")?;

    slots
        .first()
        .copied()
        .ok_or_else(|| "FAIL [C_GetSlotList]: slot list is empty after fill".to_owned())
}

// ---------------------------------------------------------------------------
// Step F helper
// ---------------------------------------------------------------------------

pub fn call_open_session(
    func_list: &CK_FUNCTION_LIST,
    slot_id: CK_SLOT_ID,
) -> Result<CK_SESSION_HANDLE, String> {
    let c_open_session = func_list
        .C_OpenSession
        .ok_or_else(|| "FAIL [C_OpenSession]: not present in function list".to_owned())?;

    let flags: CK_FLAGS = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    let mut session: CK_SESSION_HANDLE = 0;

    let rv = unsafe {
        c_open_session(
            slot_id,
            flags,
            ptr::null_mut::<c_void>(), // pApplication — not used
            None,                      // Notify callback — not used
            &raw mut session,
        )
    };

    if rv != CKR_OK {
        return Err(format!(
            "FAIL [C_OpenSession]: returned {} (0x{rv:08X})\n  \
             Hint: the KMS server at the URL in ckms.toml may not be running or reachable.",
            ckr_name(rv)
        ));
    }

    Ok(session)
}

// ---------------------------------------------------------------------------
// Step F½ helper — C_Login
// ---------------------------------------------------------------------------

pub fn call_login(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    token: &str,
) -> Result<(), String> {
    let c_login = func_list
        .C_Login
        .ok_or_else(|| "FAIL [C_Login]: not present in function list".to_owned())?;

    let token_bytes = token.as_bytes();
    let pin_len = CK_ULONG::try_from(token_bytes.len())
        .map_err(|e| format!("FAIL [C_Login]: token length out of CK_ULONG range: {e}"))?;

    // CKU_USER = 1 per PKCS#11 spec.
    // Safety: token_bytes is valid for the duration of this call; the provider
    // treats the pPin pointer as read-only.
    let rv = unsafe { c_login(session, CKU_USER, token_bytes.as_ptr().cast_mut(), pin_len) };

    if rv != CKR_OK {
        return Err(format!(
            "FAIL [C_Login]: returned {} (0x{rv:08X})\n  \
             Hint: verify the JWT is valid and not expired. \
             The KMS server must accept it as a bearer token.",
            ckr_name(rv)
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Steps G–I helpers
// ---------------------------------------------------------------------------

/// PKCS#11 object classes to enumerate in order.
///
/// The Cosmian provider requires a non-null attribute template for `C_FindObjectsInit`;
/// passing a null pointer ("find all") returns `CKR_GENERAL_ERROR`. We therefore run
/// one `C_FindObjectsInit` → `C_FindObjects`* → `C_FindObjectsFinal` cycle per class and sum the results.
pub const OBJECT_CLASSES: &[(CK_OBJECT_CLASS, &str)] = &[
    (CKO_DATA, "CKO_DATA"),
    (CKO_CERTIFICATE, "CKO_CERTIFICATE"),
    (CKO_PUBLIC_KEY, "CKO_PUBLIC_KEY"),
    (CKO_PRIVATE_KEY, "CKO_PRIVATE_KEY"),
    (CKO_SECRET_KEY, "CKO_SECRET_KEY"),
];

/// Maximum number of PKCS#11 object handles requested in a single `C_FindObjects` call.
pub const MAX_OBJECTS: usize = 64;

#[must_use]
pub fn call_find_objects(func_list: &CK_FUNCTION_LIST, session: CK_SESSION_HANDLE) -> usize {
    println!("[C_FindObjects] Enumerating objects by class:");
    let mut grand_total: usize = 0;

    for &(class, class_name) in OBJECT_CLASSES {
        match count_objects_by_class(func_list, session, class, class_name) {
            Ok(count) => {
                println!("  {class_name}: {count}");
                grand_total += count;
            }
            // Per-class errors are non-fatal: the provider may reject certain classes
            // (e.g. CKO_CERTIFICATE when the KMS contains objects whose attributes
            // cannot be exported in the requested format). Print a diagnostic message
            // and continue with the remaining classes. The session state is unchanged
            // after a failed C_FindObjectsInit (PKCS#11 spec §5.13).
            Err(e) => {
                println!("  {class_name}: unavailable — {e}");
            }
        }
    }

    grand_total
}

/// Run one `C_FindObjectsInit` → `C_FindObjects`* → `C_FindObjectsFinal` cycle for a
/// single object class and return the total number of matching handles.
///
/// PKCS#11 spec §5.13: `C_FindObjects` returns at most `ulMaxObjectCount` handles per
/// call. The loop continues until the batch is smaller than the requested maximum.
pub fn count_objects_by_class(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    class: CK_OBJECT_CLASS,
    class_name: &str,
) -> Result<usize, String> {
    // Safety: `object_class` is a stack variable that outlives every PKCS#11 call below.
    let mut object_class: CK_OBJECT_CLASS = class;
    let object_class_len =
        CK_ULONG::try_from(std::mem::size_of::<CK_OBJECT_CLASS>()).map_err(|e| {
            format!("FAIL [C_FindObjectsInit({class_name})]: size_of overflows CK_ULONG: {e}")
        })?;
    let mut template = CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: (&raw mut object_class).cast::<std::ffi::c_void>(),
        ulValueLen: object_class_len,
    };

    let c_find_objects_init = func_list
        .C_FindObjectsInit
        .ok_or_else(|| "FAIL [C_FindObjectsInit]: not present in function list".to_owned())?;
    let rv = unsafe { c_find_objects_init(session, &raw mut template, 1) };
    check_rv(rv, &format!("C_FindObjectsInit({class_name})"))?;

    let c_find_objects = func_list
        .C_FindObjects
        .ok_or_else(|| "FAIL [C_FindObjects]: not present in function list".to_owned())?;
    let max_ck = CK_ULONG::try_from(MAX_OBJECTS)
        .map_err(|e| format!("FAIL [C_FindObjects]: MAX_OBJECTS out of CK_ULONG range: {e}"))?;

    let mut total: usize = 0;
    loop {
        let mut handles: Vec<CK_OBJECT_HANDLE> = vec![0; MAX_OBJECTS];
        let mut found: CK_ULONG = 0;
        let rv = unsafe { c_find_objects(session, handles.as_mut_ptr(), max_ck, &raw mut found) };
        check_rv(rv, &format!("C_FindObjects({class_name})"))?;

        let batch = usize::try_from(found).map_err(|e| {
            format!("FAIL [C_FindObjects({class_name})]: found-count out of usize range: {e}")
        })?;
        total += batch;

        if batch < MAX_OBJECTS {
            break;
        }
    }

    let c_find_objects_final = func_list
        .C_FindObjectsFinal
        .ok_or_else(|| "FAIL [C_FindObjectsFinal]: not present in function list".to_owned())?;
    let rv = unsafe { c_find_objects_final(session) };
    check_rv(rv, &format!("C_FindObjectsFinal({class_name})"))?;

    Ok(total)
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

pub fn check_rv(rv: CK_RV, step: &str) -> Result<(), String> {
    if rv == CKR_OK {
        Ok(())
    } else {
        Err(format!(
            "FAIL [{step}]: returned {} (0x{rv:08X})",
            ckr_name(rv)
        ))
    }
}

/// Return a human-readable name for a `CK_RV` return value.
#[must_use]
pub const fn ckr_name(rv: CK_RV) -> &'static str {
    match rv {
        0 => "CKR_OK",
        1 => "CKR_CANCEL",
        2 => "CKR_HOST_MEMORY",
        3 => "CKR_SLOT_ID_INVALID",
        5 => "CKR_GENERAL_ERROR",
        6 => "CKR_FUNCTION_FAILED",
        7 => "CKR_ARGUMENTS_BAD",
        10 => "CKR_NO_EVENT",
        11 => "CKR_NEED_TO_CREATE_THREADS",
        12 => "CKR_CANT_LOCK",
        16 => "CKR_ATTRIBUTE_READ_ONLY",
        17 => "CKR_ATTRIBUTE_SENSITIVE",
        18 => "CKR_ATTRIBUTE_TYPE_INVALID",
        19 => "CKR_ATTRIBUTE_VALUE_INVALID",
        32 => "CKR_DATA_INVALID",
        33 => "CKR_DATA_LEN_RANGE",
        48 => "CKR_DEVICE_ERROR",
        49 => "CKR_DEVICE_MEMORY",
        50 => "CKR_DEVICE_REMOVED",
        64 => "CKR_ENCRYPTED_DATA_INVALID",
        65 => "CKR_ENCRYPTED_DATA_LEN_RANGE",
        80 => "CKR_FUNCTION_CANCELED",
        81 => "CKR_FUNCTION_NOT_PARALLEL",
        84 => "CKR_FUNCTION_NOT_SUPPORTED",
        96 => "CKR_KEY_HANDLE_INVALID",
        98 => "CKR_KEY_SIZE_RANGE",
        99 => "CKR_KEY_TYPE_INCONSISTENT",
        160 => "CKR_PIN_INCORRECT",
        161 => "CKR_PIN_LOCKED",
        176 => "CKR_OBJECT_HANDLE_INVALID",
        208 => "CKR_SESSION_CLOSED",
        209 => "CKR_SESSION_COUNT",
        211 => "CKR_SESSION_HANDLE_INVALID",
        213 => "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
        214 => "CKR_SESSION_READ_ONLY",
        215 => "CKR_SESSION_EXISTS",
        224 => "CKR_TOKEN_NOT_PRESENT",
        225 => "CKR_TOKEN_NOT_RECOGNIZED",
        226 => "CKR_TOKEN_WRITE_PROTECTED",
        240 => "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
        241 => "CKR_UNWRAPPING_KEY_SIZE_RANGE",
        242 => "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
        256 => "CKR_USER_ALREADY_LOGGED_IN",
        257 => "CKR_USER_NOT_LOGGED_IN",
        258 => "CKR_USER_PIN_NOT_INITIALIZED",
        259 => "CKR_USER_TYPE_INVALID",
        272 => "CKR_WRAPPED_KEY_INVALID",
        274 => "CKR_WRAPPED_KEY_LEN_RANGE",
        288 => "CKR_WRAPPING_KEY_HANDLE_INVALID",
        289 => "CKR_WRAPPING_KEY_SIZE_RANGE",
        290 => "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
        304 => "CKR_RANDOM_SEED_NOT_SUPPORTED",
        305 => "CKR_RANDOM_NO_RNG",
        320 => "CKR_DOMAIN_PARAMS_INVALID",
        400 => "CKR_CRYPTOKI_NOT_INITIALIZED",
        401 => "CKR_CRYPTOKI_ALREADY_INITIALIZED",
        _ => "CKR_UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// Oracle TDE migration helpers
// ---------------------------------------------------------------------------

/// Generate an AES-256 key in the token with the given label.
///
/// Calls `C_GenerateKey` with a `CKM_AES_KEY_GEN` mechanism and a minimal
/// attribute template (`CKA_KEY_TYPE`, `CKA_LABEL`, `CKA_SENSITIVE`,
/// `CKA_VALUE_LEN=32`, `CKA_EXTRACTABLE=CK_TRUE`).
/// This mirrors what Oracle TDE does during `ADMINISTER KEY MANAGEMENT SET
/// ENCRYPTION KEY ... MIGRATE`.
pub fn call_generate_aes_key(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    label: &str,
) -> Result<CK_OBJECT_HANDLE, String> {
    let c_generate_key = func_list
        .C_GenerateKey
        .ok_or_else(|| "FAIL [C_GenerateKey]: not present in function list".to_owned())?;

    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let key_type: CK_KEY_TYPE = CKK_AES;
    let sensitive: CK_BBOOL = CK_TRUE;
    let extractable: CK_BBOOL = CK_TRUE;
    let value_len: CK_ULONG = 32; // AES-256
    let label_len = CK_ULONG::try_from(label.len())
        .map_err(|e| format!("FAIL [C_GenerateKey]: label length out of range: {e}"))?;
    let key_type_len = CK_ULONG::try_from(std::mem::size_of::<CK_KEY_TYPE>())
        .map_err(|e| format!("FAIL [C_GenerateKey]: size_of::<CK_KEY_TYPE> overflow: {e}"))?;
    let bbool_len = CK_ULONG::try_from(std::mem::size_of::<CK_BBOOL>())
        .map_err(|e| format!("FAIL [C_GenerateKey]: size_of::<CK_BBOOL> overflow: {e}"))?;
    let ulong_len = CK_ULONG::try_from(std::mem::size_of::<CK_ULONG>())
        .map_err(|e| format!("FAIL [C_GenerateKey]: size_of::<CK_ULONG> overflow: {e}"))?;

    let mut template = [
        CK_ATTRIBUTE {
            type_: CKA_KEY_TYPE,
            pValue: std::ptr::from_ref(&key_type).cast::<c_void>().cast_mut(),
            ulValueLen: key_type_len,
        },
        CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: label.as_ptr().cast::<c_void>().cast_mut(),
            ulValueLen: label_len,
        },
        CK_ATTRIBUTE {
            type_: CKA_SENSITIVE,
            pValue: std::ptr::from_ref(&sensitive).cast::<c_void>().cast_mut(),
            ulValueLen: bbool_len,
        },
        CK_ATTRIBUTE {
            type_: CKA_VALUE_LEN,
            pValue: std::ptr::from_ref(&value_len).cast::<c_void>().cast_mut(),
            ulValueLen: ulong_len,
        },
        CK_ATTRIBUTE {
            type_: CKA_EXTRACTABLE,
            pValue: std::ptr::from_ref(&extractable).cast::<c_void>().cast_mut(),
            ulValueLen: bbool_len,
        },
    ];
    let template_len = CK_ULONG::try_from(template.len())
        .map_err(|e| format!("FAIL [C_GenerateKey]: template length overflow: {e}"))?;

    let mut key_handle: CK_OBJECT_HANDLE = 0;
    let rv = unsafe {
        c_generate_key(
            session,
            &raw mut mechanism,
            template.as_mut_ptr(),
            template_len,
            &raw mut key_handle,
        )
    };
    check_rv(rv, "C_GenerateKey")?;
    Ok(key_handle)
}

/// Encrypt `plaintext` using the AES-CBC-PAD mechanism with a zero 16-byte IV.
///
/// Calls `C_EncryptInit` followed by `C_Encrypt` using the supplied `key_handle`.
/// This mirrors the DEK-wrapping step Oracle performs during wallet migration.
pub fn call_encrypt_aes_cbc_pad(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    key_handle: CK_OBJECT_HANDLE,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let c_encrypt_init = func_list
        .C_EncryptInit
        .ok_or_else(|| "FAIL [C_EncryptInit]: not present in function list".to_owned())?;
    let c_encrypt = func_list
        .C_Encrypt
        .ok_or_else(|| "FAIL [C_Encrypt]: not present in function list".to_owned())?;

    let mut iv = [0_u8; 16];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        pParameter: iv.as_mut_ptr().cast::<c_void>(),
        ulParameterLen: 16,
    };

    let rv = unsafe { c_encrypt_init(session, &raw mut mechanism, key_handle) };
    check_rv(rv, "C_EncryptInit")?;

    // Allocate a generous output buffer (input + 32 bytes covers any PKCS#7 padding).
    let mut out_buf: Vec<u8> = vec![0_u8; plaintext.len() + 32];
    let mut out_len = CK_ULONG::try_from(out_buf.len())
        .map_err(|e| format!("FAIL [C_Encrypt]: output buffer length overflow: {e}"))?;
    let plain_len = CK_ULONG::try_from(plaintext.len())
        .map_err(|e| format!("FAIL [C_Encrypt]: plaintext length overflow: {e}"))?;

    let rv = unsafe {
        c_encrypt(
            session,
            plaintext.as_ptr().cast_mut(),
            plain_len,
            out_buf.as_mut_ptr(),
            &raw mut out_len,
        )
    };
    check_rv(rv, "C_Encrypt")?;

    let final_len = usize::try_from(out_len)
        .map_err(|e| format!("FAIL [C_Encrypt]: returned length overflow: {e}"))?;
    out_buf.truncate(final_len);
    Ok(out_buf)
}

/// Decrypt `ciphertext` using the AES-CBC-PAD mechanism with a zero 16-byte IV.
///
/// Calls `C_DecryptInit` followed by `C_Decrypt` using the supplied `key_handle`.
/// This mirrors the DEK-unwrapping step Oracle performs during reverse wallet migration.
pub fn call_decrypt_aes_cbc_pad(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    key_handle: CK_OBJECT_HANDLE,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let c_decrypt_init = func_list
        .C_DecryptInit
        .ok_or_else(|| "FAIL [C_DecryptInit]: not present in function list".to_owned())?;
    let c_decrypt = func_list
        .C_Decrypt
        .ok_or_else(|| "FAIL [C_Decrypt]: not present in function list".to_owned())?;

    let mut iv = [0_u8; 16];
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD,
        pParameter: iv.as_mut_ptr().cast::<c_void>(),
        ulParameterLen: 16,
    };

    let rv = unsafe { c_decrypt_init(session, &raw mut mechanism, key_handle) };
    check_rv(rv, "C_DecryptInit")?;

    // Allocate output buffer equal to ciphertext length; plaintext is always shorter.
    let mut out_buf: Vec<u8> = vec![0_u8; ciphertext.len()];
    let mut out_len = CK_ULONG::try_from(out_buf.len())
        .map_err(|e| format!("FAIL [C_Decrypt]: output buffer length overflow: {e}"))?;
    let cipher_len = CK_ULONG::try_from(ciphertext.len())
        .map_err(|e| format!("FAIL [C_Decrypt]: ciphertext length overflow: {e}"))?;

    let rv = unsafe {
        c_decrypt(
            session,
            ciphertext.as_ptr().cast_mut(),
            cipher_len,
            out_buf.as_mut_ptr(),
            &raw mut out_len,
        )
    };
    check_rv(rv, "C_Decrypt")?;

    let final_len = usize::try_from(out_len)
        .map_err(|e| format!("FAIL [C_Decrypt]: returned length overflow: {e}"))?;
    out_buf.truncate(final_len);
    Ok(out_buf)
}

#[cfg(test)]
mod tests;
