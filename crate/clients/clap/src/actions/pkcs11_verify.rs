//! PKCS#11 shared-library verification logic for `ckms pkcs11 verify`.
//!
//! Dynamically loads a PKCS#11 `.so`/`.dylib`/`.dll` and walks through the
//! standard API sequence to verify connectivity and correctness.

#![allow(unsafe_code, clippy::print_stdout)]

use std::{env, ffi::c_void, path::Path, ptr};

use libloading::{Library, Symbol};
use pkcs11_sys::{
    CK_BBOOL, CK_FLAGS, CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR_PTR, CK_OBJECT_CLASS,
    CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_TRUE, CK_ULONG, CKA_CLASS,
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CKO_CERTIFICATE, CKO_DATA, CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY, CKO_SECRET_KEY, CKR_OK, CKU_USER, CK_ATTRIBUTE,
};

use crate::error::{KmsCliError, result::KmsCliResult};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the full PKCS#11 verification sequence.
///
/// # Errors
/// Returns an error if any PKCS#11 call fails or the library cannot be loaded.
pub(crate) fn run_verify(so_path: &Path, conf: Option<&Path>, token: Option<&str>) -> KmsCliResult<()> {
    // ── Step A: Determine which ckms.toml will be used ──────────────────────
    describe_config(so_path, conf);

    // Set CKMS_CONF *before* opening the .so so that C_GetFunctionList can
    // read the requested configuration path.
    if let Some(conf_path) = conf {
        // Safety: single-threaded at this point; no other threads are running yet,
        // so mutating the environment is safe.
        unsafe { env::set_var("CKMS_CONF", conf_path) };
    }

    // ── Step B: Load the shared library ────────────────────────────────────
    println!("[load] Opening: {}", so_path.display());
    let lib = unsafe { Library::new(so_path) }.map_err(|e| {
        KmsCliError::Default(format!(
            "FAIL [load]: cannot open '{}': {e}\n  \
             Hint: make sure the path is correct and the library has the right \
             architecture for this platform.",
            so_path.display()
        ))
    })?;
    println!("[load] OK: shared library opened");
    println!();

    // ── Step C: C_GetFunctionList ───────────────────────────────────────────
    let func_list_ptr = call_get_function_list(&lib)?;
    let func_list: &CK_FUNCTION_LIST = unsafe { &*func_list_ptr };
    println!("[C_GetFunctionList] OK: ckms.toml parsed");
    println!();

    // ── Step D: C_Initialize ────────────────────────────────────────────────
    let c_initialize = func_list
        .C_Initialize
        .ok_or_else(|| {
            KmsCliError::Default(
                "FAIL [C_Initialize]: not present in function list".to_owned(),
            )
        })?;
    let rv = unsafe { c_initialize(ptr::null_mut::<c_void>()) };
    check_rv(rv, "C_Initialize")?;
    println!("[C_Initialize] OK");
    println!();

    // ── Step E: C_GetSlotList ───────────────────────────────────────────────
    let slot_id = call_get_slot_list(func_list)?;
    println!("[C_GetSlotList] OK: using slot ID {slot_id}");
    println!();

    // ── Step F: C_OpenSession ───────────────────────────────────────────────
    let session = call_open_session(func_list, slot_id)?;
    println!("[C_OpenSession] OK: session opened on slot {slot_id}");
    println!();

    // ── Step F½: C_Login (when --token is supplied) ─────────────────────────
    if let Some(tok) = token {
        call_login(func_list, session, tok)?;
        println!("[C_Login] OK: session authenticated with provided token");
        println!();
    }

    // ── Steps G–I: Enumerate objects by class ───────────────────────────────
    let found_count = call_find_objects(func_list, session);
    println!("[C_FindObjects] OK: {found_count} PKCS#11 object(s) visible on KMS");
    println!();

    // ── Step J: C_CloseSession ──────────────────────────────────────────────
    let c_close_session = func_list
        .C_CloseSession
        .ok_or_else(|| {
            KmsCliError::Default(
                "FAIL [C_CloseSession]: not present in function list".to_owned(),
            )
        })?;
    let rv = unsafe { c_close_session(session) };
    check_rv(rv, "C_CloseSession")?;
    println!("[C_CloseSession] OK");

    // ── Step K: C_Finalize ──────────────────────────────────────────────────
    let c_finalize = func_list
        .C_Finalize
        .ok_or_else(|| {
            KmsCliError::Default(
                "FAIL [C_Finalize]: not present in function list".to_owned(),
            )
        })?;
    let rv = unsafe { c_finalize(ptr::null_mut::<c_void>()) };
    check_rv(rv, "C_Finalize")?;
    println!("[C_Finalize] OK");

    println!();
    println!("All checks passed.");

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

type GetFunctionListFn = unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;

fn call_get_function_list(lib: &Library) -> KmsCliResult<*mut CK_FUNCTION_LIST> {
    let get_func_list: Symbol<GetFunctionListFn> = unsafe { lib.get(b"C_GetFunctionList\0") }
        .map_err(|e| {
            KmsCliError::Default(format!(
                "FAIL [C_GetFunctionList]: symbol not found in .so: {e}"
            ))
        })?;

    let mut func_list_ptr: *mut CK_FUNCTION_LIST = ptr::null_mut();
    let rv = unsafe { get_func_list(&raw mut func_list_ptr) };

    if rv != CKR_OK {
        return Err(KmsCliError::Default(format!(
            "FAIL [C_GetFunctionList]: returned {} (0x{rv:08X})\n  \
             Hint: verify that ckms.toml exists, is valid TOML, and contains a \
             reachable [http_config].server_url.",
            ckr_name(rv)
        )));
    }

    if func_list_ptr.is_null() {
        return Err(KmsCliError::Default(
            "FAIL [C_GetFunctionList]: returned CKR_OK but function list pointer is null"
                .to_owned(),
        ));
    }

    Ok(func_list_ptr)
}

fn call_get_slot_list(func_list: &CK_FUNCTION_LIST) -> KmsCliResult<CK_SLOT_ID> {
    let c_get_slot_list = func_list.C_GetSlotList.ok_or_else(|| {
        KmsCliError::Default("FAIL [C_GetSlotList]: not present in function list".to_owned())
    })?;

    let token_present: CK_BBOOL = CK_TRUE;
    let mut count: CK_ULONG = 0;
    let rv = unsafe { c_get_slot_list(token_present, ptr::null_mut(), &raw mut count) };
    check_rv(rv, "C_GetSlotList (count)")?;

    if count == 0 {
        return Err(KmsCliError::Default(
            "FAIL [C_GetSlotList]: provider reports zero slots".to_owned(),
        ));
    }

    let slot_count = usize::try_from(count).map_err(|e| {
        KmsCliError::Default(format!(
            "FAIL [C_GetSlotList]: slot count value out of range for usize: {e}"
        ))
    })?;

    let mut slots: Vec<CK_SLOT_ID> = vec![0; slot_count];
    let rv = unsafe { c_get_slot_list(token_present, slots.as_mut_ptr(), &raw mut count) };
    check_rv(rv, "C_GetSlotList (fill)")?;

    slots.first().copied().ok_or_else(|| {
        KmsCliError::Default("FAIL [C_GetSlotList]: slot list is empty after fill".to_owned())
    })
}

fn call_open_session(
    func_list: &CK_FUNCTION_LIST,
    slot_id: CK_SLOT_ID,
) -> KmsCliResult<CK_SESSION_HANDLE> {
    let c_open_session = func_list.C_OpenSession.ok_or_else(|| {
        KmsCliError::Default("FAIL [C_OpenSession]: not present in function list".to_owned())
    })?;

    let flags: CK_FLAGS = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    let mut session: CK_SESSION_HANDLE = 0;

    let rv = unsafe {
        c_open_session(
            slot_id,
            flags,
            ptr::null_mut::<c_void>(),
            None,
            &raw mut session,
        )
    };

    if rv != CKR_OK {
        return Err(KmsCliError::Default(format!(
            "FAIL [C_OpenSession]: returned {} (0x{rv:08X})\n  \
             Hint: the KMS server at the URL in ckms.toml may not be running or reachable.",
            ckr_name(rv)
        )));
    }

    Ok(session)
}

fn call_login(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    token: &str,
) -> KmsCliResult<()> {
    let c_login = func_list.C_Login.ok_or_else(|| {
        KmsCliError::Default("FAIL [C_Login]: not present in function list".to_owned())
    })?;

    let token_bytes = token.as_bytes();
    let pin_len = CK_ULONG::try_from(token_bytes.len()).map_err(|e| {
        KmsCliError::Default(format!(
            "FAIL [C_Login]: token length out of CK_ULONG range: {e}"
        ))
    })?;

    let rv = unsafe { c_login(session, CKU_USER, token_bytes.as_ptr().cast_mut(), pin_len) };

    if rv != CKR_OK {
        return Err(KmsCliError::Default(format!(
            "FAIL [C_Login]: returned {} (0x{rv:08X})\n  \
             Hint: verify the JWT is valid and not expired. \
             The KMS server must accept it as a bearer token.",
            ckr_name(rv)
        )));
    }

    Ok(())
}

/// PKCS#11 object classes to enumerate.
const OBJECT_CLASSES: &[(CK_OBJECT_CLASS, &str)] = &[
    (CKO_DATA, "CKO_DATA"),
    (CKO_CERTIFICATE, "CKO_CERTIFICATE"),
    (CKO_PUBLIC_KEY, "CKO_PUBLIC_KEY"),
    (CKO_PRIVATE_KEY, "CKO_PRIVATE_KEY"),
    (CKO_SECRET_KEY, "CKO_SECRET_KEY"),
];

const MAX_OBJECTS: usize = 64;

fn call_find_objects(func_list: &CK_FUNCTION_LIST, session: CK_SESSION_HANDLE) -> usize {
    println!("[C_FindObjects] Enumerating objects by class:");
    let mut grand_total: usize = 0;

    for &(class, class_name) in OBJECT_CLASSES {
        match count_objects_by_class(func_list, session, class, class_name) {
            Ok(count) => {
                println!("  {class_name}: {count}");
                grand_total += count;
            }
            Err(e) => {
                println!("  {class_name}: unavailable — {e}");
            }
        }
    }

    grand_total
}

fn count_objects_by_class(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    class: CK_OBJECT_CLASS,
    class_name: &str,
) -> Result<usize, String> {
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
    check_rv_raw(rv, &format!("C_FindObjectsInit({class_name})"))?;

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
        check_rv_raw(rv, &format!("C_FindObjects({class_name})"))?;

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
    check_rv_raw(rv, &format!("C_FindObjectsFinal({class_name})"))?;

    Ok(total)
}

fn check_rv(rv: CK_RV, step: &str) -> KmsCliResult<()> {
    if rv == CKR_OK {
        Ok(())
    } else {
        Err(KmsCliError::Default(format!(
            "FAIL [{step}]: returned {} (0x{rv:08X})",
            ckr_name(rv)
        )))
    }
}

/// Internal variant used in contexts that return `Result<_, String>`.
fn check_rv_raw(rv: CK_RV, step: &str) -> Result<(), String> {
    if rv == CKR_OK {
        Ok(())
    } else {
        Err(format!(
            "FAIL [{step}]: returned {} (0x{rv:08X})",
            ckr_name(rv)
        ))
    }
}

const fn ckr_name(rv: CK_RV) -> &'static str {
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
// Step A helper – describe config location
// ---------------------------------------------------------------------------

fn describe_config(so_path: &Path, conf: Option<&Path>) {
    if let Some(p) = conf {
        println!("[conf] Will use --conf: {}", p.display());
    } else if let Ok(v) = env::var("CKMS_CONF") {
        println!("[conf] Will use CKMS_CONF env: {v}");
    } else {
        // Check alongside the .so
        let adjacent = so_path
            .parent()
            .map(|d| d.join("ckms.toml"))
            .filter(|p| p.exists());

        if let Some(ref p) = adjacent {
            println!("[conf] Will use ckms.toml adjacent to .so: {}", p.display());
        } else {
            // Default search order mirrors ClientConfig::location()
            let home_conf = env::var("HOME")
                .ok()
                .map(|h| std::path::PathBuf::from(h).join(".cosmian").join("ckms.toml"));
            let system_conf = std::path::PathBuf::from("/etc/cosmian/ckms.toml");

            if home_conf.as_ref().is_some_and(|p| p.exists()) {
                println!(
                    "[conf] Will use default home config: {}",
                    home_conf
                        .as_ref()
                        .map_or_else(std::path::PathBuf::new, Clone::clone)
                        .display()
                );
            } else if system_conf.exists() {
                println!("[conf] Will use system config: {}", system_conf.display());
            } else {
                println!(
                    "[conf] WARNING: no ckms.toml found at any standard location \
                     (~/.cosmian/ckms.toml, /etc/cosmian/ckms.toml).\n  \
                     C_GetFunctionList will fail unless CKMS_CONF is set or \
                     a ckms.toml sits next to the .so."
                );
            }
        }
    }
    println!();
}
