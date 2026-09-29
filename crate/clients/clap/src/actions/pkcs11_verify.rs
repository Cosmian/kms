//! PKCS#11 shared-library verification logic for `ckms pkcs11 verify`.
//!
//! Dynamically loads a PKCS#11 `.so`/`.dylib`/`.dll` and walks through the
//! standard API sequence to verify connectivity and correctness.

#![allow(unsafe_code, clippy::print_stdout)]

use std::{env, ffi::c_void, path::Path, ptr, sync::Mutex};

use libloading::{Library, Symbol};
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_FLAGS, CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR_PTR, CK_OBJECT_CLASS,
    CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_TRUE, CK_ULONG, CKA_CLASS,
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CKO_CERTIFICATE, CKO_DATA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY,
    CKO_SECRET_KEY, CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL, CKR_CANCEL, CKR_CANT_LOCK, CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DOMAIN_PARAMS_INVALID,
    CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE, CKR_EXCEEDED_MAX_ITERATIONS,
    CKR_FIPS_SELF_TEST_FAILED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_PARALLEL, CKR_FUNCTION_NOT_SUPPORTED, CKR_FUNCTION_REJECTED,
    CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_INFORMATION_SENSITIVE, CKR_KEY_CHANGED,
    CKR_KEY_EXHAUSTED, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID,
    CKR_KEY_INDIGESTIBLE, CKR_KEY_NEEDED, CKR_KEY_NOT_NEEDED, CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_SIZE_RANGE, CKR_KEY_TYPE_INCONSISTENT, CKR_KEY_UNEXTRACTABLE, CKR_LIBRARY_LOAD_FAILED,
    CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_MUTEX_BAD, CKR_MUTEX_NOT_LOCKED,
    CKR_NEED_TO_CREATE_THREADS, CKR_NO_EVENT, CKR_OBJECT_HANDLE_INVALID, CKR_OK,
    CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED, CKR_PIN_EXPIRED, CKR_PIN_INCORRECT,
    CKR_PIN_INVALID, CKR_PIN_LEN_RANGE, CKR_PIN_LOCKED, CKR_PIN_TOO_WEAK, CKR_PUBLIC_KEY_INVALID,
    CKR_RANDOM_NO_RNG, CKR_RANDOM_SEED_NOT_SUPPORTED, CKR_SAVED_STATE_INVALID, CKR_SESSION_CLOSED,
    CKR_SESSION_COUNT, CKR_SESSION_EXISTS, CKR_SESSION_HANDLE_INVALID,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SESSION_READ_ONLY, CKR_SESSION_READ_ONLY_EXISTS,
    CKR_SESSION_READ_WRITE_SO_EXISTS, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE,
    CKR_SLOT_ID_INVALID, CKR_STATE_UNSAVEABLE, CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT,
    CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_TOKEN_RESOURCE_EXCEEDED,
    CKR_TOKEN_WRITE_PROTECTED, CKR_UNWRAPPING_KEY_HANDLE_INVALID, CKR_UNWRAPPING_KEY_SIZE_RANGE,
    CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN, CKR_USER_NOT_LOGGED_IN, CKR_USER_PIN_NOT_INITIALIZED,
    CKR_USER_TOO_MANY_TYPES, CKR_USER_TYPE_INVALID, CKR_VENDOR_DEFINED, CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE, CKR_WRAPPING_KEY_HANDLE_INVALID, CKR_WRAPPING_KEY_SIZE_RANGE,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT, CKU_USER,
};

use crate::error::{KmsCliError, result::KmsCliResult};

// Thread-safe configuration for CKMS_CONF environment variable
static CKMS_CONF_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the full PKCS#11 verification sequence.
///
/// # Errors
/// Returns an error if any PKCS#11 call fails or the library cannot be loaded.
pub(crate) fn run_verify(
    so_path: &Path,
    conf: Option<&Path>,
    token: Option<&str>,
) -> KmsCliResult<()> {
    // ── Step A: Determine which ckms.toml will be used ──────────────────────
    describe_config(so_path, conf);

    // Set CKMS_CONF in a thread-safe manner using a mutex to coordinate access
    // and prevent race conditions in multi-threaded Tokio runtime contexts.
    let _guard = CKMS_CONF_LOCK
        .lock()
        .map_err(|_lock_err| KmsCliError::Default("CKMS_CONF_LOCK poisoned".to_owned()))?;
    if let Some(conf_path) = conf {
        // Safety: protected by mutex to ensure exclusive access to environment variables
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
    let c_initialize = func_list.C_Initialize.ok_or_else(|| {
        KmsCliError::Default("FAIL [C_Initialize]: not present in function list".to_owned())
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
    let (found_count, error_count) = call_find_objects(func_list, session);
    if error_count > 0 {
        println!(
            "[C_FindObjects] WARN: {error_count} class(es) returned errors — \
             the KMS server may be unreachable or misconfigured"
        );
    }
    println!("[C_FindObjects] OK: {found_count} PKCS#11 object(s) visible on KMS");
    println!();

    // ── Step J: C_CloseSession ──────────────────────────────────────────────
    let c_close_session = func_list.C_CloseSession.ok_or_else(|| {
        KmsCliError::Default("FAIL [C_CloseSession]: not present in function list".to_owned())
    })?;
    let rv = unsafe { c_close_session(session) };
    check_rv(rv, "C_CloseSession")?;
    println!("[C_CloseSession] OK");

    // ── Step K: C_Finalize ──────────────────────────────────────────────────
    let c_finalize = func_list.C_Finalize.ok_or_else(|| {
        KmsCliError::Default("FAIL [C_Finalize]: not present in function list".to_owned())
    })?;
    let rv = unsafe { c_finalize(ptr::null_mut::<c_void>()) };
    check_rv(rv, "C_Finalize")?;
    println!("[C_Finalize] OK");

    if error_count > 0 {
        println!();
        return Err(KmsCliError::Default(format!(
            "FAIL: {error_count} object class(es) could not be enumerated. \
             The KMS server may be unreachable or misconfigured."
        )));
    }

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

fn call_find_objects(func_list: &CK_FUNCTION_LIST, session: CK_SESSION_HANDLE) -> (usize, usize) {
    println!("[C_FindObjects] Enumerating objects by class:");
    let mut grand_total: usize = 0;
    let mut error_count: usize = 0;

    for &(class, class_name) in OBJECT_CLASSES {
        match count_objects_by_class(func_list, session, class, class_name) {
            Ok(count) => {
                println!("  {class_name}: {count}");
                grand_total += count;
            }
            Err(e) => {
                println!("  {class_name}: unavailable — {e}");
                error_count += 1;
            }
        }
    }

    (grand_total, error_count)
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

/// Map a PKCS#11 return value to its symbolic name using imported constants.
///
/// Uses a macro to avoid repeating each constant name as both pattern and string.
macro_rules! ckr_match {
    ($rv:expr; $($name:ident),+ $(,)?) => {
        match $rv {
            $( $name => stringify!($name), )+
            _ => "CKR_UNKNOWN",
        }
    };
}

const fn ckr_name(rv: CK_RV) -> &'static str {
    ckr_match!(rv;
        CKR_OK,
        CKR_CANCEL,
        CKR_HOST_MEMORY,
        CKR_SLOT_ID_INVALID,
        CKR_GENERAL_ERROR,
        CKR_FUNCTION_FAILED,
        CKR_ARGUMENTS_BAD,
        CKR_NO_EVENT,
        CKR_NEED_TO_CREATE_THREADS,
        CKR_CANT_LOCK,
        CKR_ATTRIBUTE_READ_ONLY,
        CKR_ATTRIBUTE_SENSITIVE,
        CKR_ATTRIBUTE_TYPE_INVALID,
        CKR_ATTRIBUTE_VALUE_INVALID,
        CKR_ACTION_PROHIBITED,
        CKR_DATA_INVALID,
        CKR_DATA_LEN_RANGE,
        CKR_DEVICE_ERROR,
        CKR_DEVICE_MEMORY,
        CKR_DEVICE_REMOVED,
        CKR_ENCRYPTED_DATA_INVALID,
        CKR_ENCRYPTED_DATA_LEN_RANGE,
        CKR_FUNCTION_CANCELED,
        CKR_FUNCTION_NOT_PARALLEL,
        CKR_FUNCTION_NOT_SUPPORTED,
        CKR_KEY_HANDLE_INVALID,
        CKR_KEY_SIZE_RANGE,
        CKR_KEY_TYPE_INCONSISTENT,
        CKR_KEY_NOT_NEEDED,
        CKR_KEY_CHANGED,
        CKR_KEY_NEEDED,
        CKR_KEY_INDIGESTIBLE,
        CKR_KEY_FUNCTION_NOT_PERMITTED,
        CKR_KEY_NOT_WRAPPABLE,
        CKR_KEY_UNEXTRACTABLE,
        CKR_MECHANISM_INVALID,
        CKR_MECHANISM_PARAM_INVALID,
        CKR_OBJECT_HANDLE_INVALID,
        CKR_OPERATION_ACTIVE,
        CKR_OPERATION_NOT_INITIALIZED,
        CKR_PIN_INCORRECT,
        CKR_PIN_INVALID,
        CKR_PIN_LEN_RANGE,
        CKR_PIN_EXPIRED,
        CKR_PIN_LOCKED,
        CKR_SESSION_CLOSED,
        CKR_SESSION_COUNT,
        CKR_SESSION_HANDLE_INVALID,
        CKR_SESSION_PARALLEL_NOT_SUPPORTED,
        CKR_SESSION_READ_ONLY,
        CKR_SESSION_EXISTS,
        CKR_SESSION_READ_ONLY_EXISTS,
        CKR_SESSION_READ_WRITE_SO_EXISTS,
        CKR_SIGNATURE_INVALID,
        CKR_SIGNATURE_LEN_RANGE,
        CKR_TEMPLATE_INCOMPLETE,
        CKR_TEMPLATE_INCONSISTENT,
        CKR_TOKEN_NOT_PRESENT,
        CKR_TOKEN_NOT_RECOGNIZED,
        CKR_TOKEN_WRITE_PROTECTED,
        CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        CKR_UNWRAPPING_KEY_SIZE_RANGE,
        CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        CKR_USER_ALREADY_LOGGED_IN,
        CKR_USER_NOT_LOGGED_IN,
        CKR_USER_PIN_NOT_INITIALIZED,
        CKR_USER_TYPE_INVALID,
        CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
        CKR_USER_TOO_MANY_TYPES,
        CKR_WRAPPED_KEY_INVALID,
        CKR_WRAPPED_KEY_LEN_RANGE,
        CKR_WRAPPING_KEY_HANDLE_INVALID,
        CKR_WRAPPING_KEY_SIZE_RANGE,
        CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
        CKR_RANDOM_SEED_NOT_SUPPORTED,
        CKR_RANDOM_NO_RNG,
        CKR_DOMAIN_PARAMS_INVALID,
        CKR_CURVE_NOT_SUPPORTED,
        CKR_BUFFER_TOO_SMALL,
        CKR_SAVED_STATE_INVALID,
        CKR_INFORMATION_SENSITIVE,
        CKR_STATE_UNSAVEABLE,
        CKR_CRYPTOKI_NOT_INITIALIZED,
        CKR_CRYPTOKI_ALREADY_INITIALIZED,
        CKR_MUTEX_BAD,
        CKR_MUTEX_NOT_LOCKED,
        CKR_EXCEEDED_MAX_ITERATIONS,
        CKR_FIPS_SELF_TEST_FAILED,
        CKR_LIBRARY_LOAD_FAILED,
        CKR_PIN_TOO_WEAK,
        CKR_PUBLIC_KEY_INVALID,
        CKR_FUNCTION_REJECTED,
        CKR_TOKEN_RESOURCE_EXCEEDED,
        CKR_KEY_EXHAUSTED,
        CKR_VENDOR_DEFINED,
    )
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
            let home_conf = env::var("HOME").ok().map(|h| {
                std::path::PathBuf::from(h)
                    .join(".cosmian")
                    .join("ckms.toml")
            });
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
