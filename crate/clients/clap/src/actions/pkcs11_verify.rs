//! PKCS#11 shared-library verification logic for `ckms pkcs11 verify`.
//!
//! Dynamically loads a PKCS#11 `.so`/`.dylib`/`.dll` and walks through the
//! full PKCS#11 v3.1 API surface this provider implements: legacy
//! `C_GetFunctionList` initialization, the v3.0 `C_GetInterfaceList`/
//! `C_GetInterface` interface-negotiation entry points, `C_GetInfo` version
//! reporting, `C_GetMechanismList`/`C_GetMechanismInfo` capability-flag
//! conformance, standard object enumeration, and `CKO_PROFILE`
//! conformance-profile self-declaration — to verify connectivity and
//! correctness end to end.

#![allow(unsafe_code, clippy::print_stdout)]

use std::{env, ffi::c_void, mem::size_of, path::Path, ptr, sync::Mutex};

use libloading::{Library, Symbol};
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_FLAGS, CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR_PTR, CK_INFO,
    CK_INTERFACE, CK_INTERFACE_PTR, CK_INTERFACE_PTR_PTR, CK_MECHANISM_INFO, CK_MECHANISM_TYPE,
    CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_TRUE, CK_ULONG,
    CK_UTF8CHAR_PTR, CK_VERSION, CK_VERSION_PTR, CKA_CLASS, CKA_PROFILE_ID, CKF_DECRYPT,
    CKF_ENCRYPT, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKF_SIGN, CKF_VERIFY, CKM_AES_GCM, CKM_ECDSA,
    CKM_EDDSA, CKM_RSA_PKCS_PSS, CKO_CERTIFICATE, CKO_DATA, CKO_PRIVATE_KEY, CKO_PROFILE,
    CKO_PUBLIC_KEY, CKO_SECRET_KEY, CKP_AUTHENTICATION_TOKEN, CKP_BASELINE_PROVIDER,
    CKP_EXTENDED_PROVIDER, CKP_PUBLIC_CERTIFICATES_TOKEN, CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID, CKR_BUFFER_TOO_SMALL, CKR_CANCEL, CKR_CANT_LOCK,
    CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED,
    CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
    CKR_DOMAIN_PARAMS_INVALID, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_EXCEEDED_MAX_ITERATIONS, CKR_FIPS_SELF_TEST_FAILED, CKR_FUNCTION_CANCELED,
    CKR_FUNCTION_FAILED, CKR_FUNCTION_NOT_PARALLEL, CKR_FUNCTION_NOT_SUPPORTED,
    CKR_FUNCTION_REJECTED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_INFORMATION_SENSITIVE,
    CKR_KEY_CHANGED, CKR_KEY_EXHAUSTED, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID,
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
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT, CKU_USER, CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR,
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

    // ── Step B½: C_GetInterfaceList / C_GetInterface (PKCS#11 v3.0 Interfaces API,
    // §5.2) ──────────────────────────────────────────────────────────────────
    // A v3-aware client is expected to be able to negotiate the standard "PKCS 11"
    // interface through these two top-level entry points instead of (or in addition
    // to) the legacy `C_GetFunctionList`. Both are mandatory exports of this library.
    call_verify_interfaces(&lib)?;
    println!("[C_GetInterfaceList/C_GetInterface] OK: v3.0 interface negotiation conformant");
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

    // ── Step D½: C_GetInfo ──────────────────────────────────────────────────
    call_get_info(func_list)?;
    println!();

    // ── Step E: C_GetSlotList ───────────────────────────────────────────────
    let slot_id = call_get_slot_list(func_list)?;
    println!("[C_GetSlotList] OK: using slot ID {slot_id}");
    println!();

    // ── Step E½: C_GetMechanismList / C_GetMechanismInfo ─────────────────────
    // PKCS#11 v3.1 §5.2 Table 3: mechanism-capability flags must be accurate — a
    // spec-following client relies on them to decide which operations to attempt.
    call_verify_mechanisms(func_list, slot_id)?;
    println!("[C_GetMechanismList/C_GetMechanismInfo] OK: v3 mechanism set conformant");
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

    // ── Step I½: CKO_PROFILE self-declaration (PKCS#11 v3.0 Profiles, §4.5) ──
    // A v3-conformant token/slot MUST self-declare every conformance profile it
    // implements via `CKO_PROFILE` objects, discoverable through `C_FindObjects`
    // even before login.
    call_verify_profiles(func_list, session)?;
    println!("[CKO_PROFILE] OK: conformance profile(s) self-declared correctly");
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

// ---------------------------------------------------------------------------
// PKCS#11 v3.0 Interfaces API (§5.2): C_GetInterfaceList / C_GetInterface
// ---------------------------------------------------------------------------

type GetInterfaceListFn = unsafe extern "C" fn(CK_INTERFACE_PTR, *mut CK_ULONG) -> CK_RV;
type GetInterfaceFn =
    unsafe extern "C" fn(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS) -> CK_RV;

/// The one interface name this provider is required to expose (see
/// `cosmian_pkcs11_provider::PKCS11_INTERFACE_NAME`), NUL-terminated.
const PKCS11_INTERFACE_NAME: &[u8] = b"PKCS 11\0";

/// Exercises the v3.0 Interfaces API surface: `C_GetInterfaceList` (two-call convention) and
/// `C_GetInterface` (default lookup, exact-name lookup, backward-compatible v3.0 version
/// request, and a negative unknown-name lookup). Both symbols are exported at the top level of
/// the shared library, exactly like `C_GetFunctionList`, so a v3-only client that never calls
/// `C_GetFunctionList` can still fully initialize and use this provider.
fn call_verify_interfaces(lib: &Library) -> KmsCliResult<()> {
    let get_interface_list: Symbol<GetInterfaceListFn> =
        unsafe { lib.get(b"C_GetInterfaceList\0") }.map_err(|e| {
            KmsCliError::Default(format!(
                "FAIL [C_GetInterfaceList]: symbol not found in .so: {e}"
            ))
        })?;
    let get_interface: Symbol<GetInterfaceFn> =
        unsafe { lib.get(b"C_GetInterface\0") }.map_err(|e| {
            KmsCliError::Default(format!(
                "FAIL [C_GetInterface]: symbol not found in .so: {e}"
            ))
        })?;

    // Two-call convention: first learn the count, then fill a caller-allocated buffer.
    let mut count: CK_ULONG = 0;
    let rv = unsafe { get_interface_list(ptr::null_mut(), &raw mut count) };
    check_rv(rv, "C_GetInterfaceList (count)")?;
    if count == 0 {
        return Err(KmsCliError::Default(
            "FAIL [C_GetInterfaceList]: provider reports zero interfaces".to_owned(),
        ));
    }
    let interface_count = usize::try_from(count).map_err(|e| {
        KmsCliError::Default(format!(
            "FAIL [C_GetInterfaceList]: interface count out of range for usize: {e}"
        ))
    })?;

    let mut interfaces: Vec<CK_INTERFACE> = vec![
        CK_INTERFACE {
            pInterfaceName: ptr::null_mut(),
            pFunctionList: ptr::null_mut(),
            flags: 0,
        };
        interface_count
    ];
    let rv = unsafe { get_interface_list(interfaces.as_mut_ptr(), &raw mut count) };
    check_rv(rv, "C_GetInterfaceList (fill)")?;

    let first = interfaces.first().ok_or_else(|| {
        KmsCliError::Default("FAIL [C_GetInterfaceList]: interface list is empty".to_owned())
    })?;
    if first.pInterfaceName.is_null() || first.pFunctionList.is_null() {
        return Err(KmsCliError::Default(
            "FAIL [C_GetInterfaceList]: returned CKR_OK but interface fields are null".to_owned(),
        ));
    }
    // SAFETY: `pInterfaceName` is guaranteed non-null above and, per spec, must reference a
    // valid NUL-terminated string for the lifetime of the interface.
    let name_matches = unsafe {
        std::ffi::CStr::from_ptr(first.pInterfaceName.cast()).to_bytes_with_nul()
            == PKCS11_INTERFACE_NAME
    };
    if !name_matches {
        return Err(KmsCliError::Default(format!(
            "FAIL [C_GetInterfaceList]: expected interface name \"PKCS 11\", got a mismatched \
             or malformed name (raw bytes did not match {PKCS11_INTERFACE_NAME:?})"
        )));
    }

    // Default lookup: both name and version null must succeed and return the same interface.
    let mut iface_ptr: CK_INTERFACE_PTR = ptr::null_mut();
    let rv = unsafe { get_interface(ptr::null_mut(), ptr::null_mut(), &raw mut iface_ptr, 0) };
    check_rv(rv, "C_GetInterface (default lookup)")?;
    if iface_ptr.is_null() {
        return Err(KmsCliError::Default(
            "FAIL [C_GetInterface]: default lookup returned CKR_OK but a null interface pointer"
                .to_owned(),
        ));
    }

    // Exact-name lookup must also succeed.
    let name_ptr = PKCS11_INTERFACE_NAME.as_ptr().cast_mut();
    let rv = unsafe { get_interface(name_ptr, ptr::null_mut(), &raw mut iface_ptr, 0) };
    check_rv(rv, "C_GetInterface (exact-name lookup)")?;

    // Backward-compatible v3.0 request: a v3.1 implementation must still satisfy a caller
    // that explicitly asks for {major: 3, minor: 0}.
    let mut v3_0 = CK_VERSION { major: 3, minor: 0 };
    let rv = unsafe { get_interface(name_ptr, &raw mut v3_0, &raw mut iface_ptr, 0) };
    check_rv(rv, "C_GetInterface (v3.0 backward-compat request)")?;

    // Negative check: an unknown interface name must be rejected, not silently accepted.
    let bogus_name = c"NOT PKCS 11"
        .as_ptr()
        .cast_mut()
        .cast::<pkcs11_sys::CK_UTF8CHAR>();
    let rv = unsafe { get_interface(bogus_name, ptr::null_mut(), &raw mut iface_ptr, 0) };
    if rv == CKR_OK {
        return Err(KmsCliError::Default(
            "FAIL [C_GetInterface]: an unknown interface name must be rejected, but CKR_OK was \
             returned"
                .to_owned(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// C_GetInfo
// ---------------------------------------------------------------------------

/// Truncates a fixed-size, space-padded PKCS#11 UTF8 byte array (e.g. `manufacturerID`,
/// `libraryDescription`) at the first trailing space, per PKCS#11 v3.1 §5.2 formatting rules.
fn trim_padded_ck_string(bytes: &[u8]) -> String {
    let trimmed = bytes
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |i| i + 1);
    String::from_utf8_lossy(bytes.get(..trimmed).unwrap_or(&[])).into_owned()
}

/// Calls `C_GetInfo` and asserts the reported `cryptokiVersion` is v3.x — a hard requirement
/// for this provider, which only ever advertises v3.1 support.
fn call_get_info(func_list: &CK_FUNCTION_LIST) -> KmsCliResult<()> {
    let c_get_info = func_list.C_GetInfo.ok_or_else(|| {
        KmsCliError::Default("FAIL [C_GetInfo]: not present in function list".to_owned())
    })?;

    let mut info = CK_INFO::default();
    let rv = unsafe { c_get_info(&raw mut info) };
    check_rv(rv, "C_GetInfo")?;

    if info.cryptokiVersion.major != CRYPTOKI_VERSION_MAJOR {
        return Err(KmsCliError::Default(format!(
            "FAIL [C_GetInfo]: expected Cryptoki major version {CRYPTOKI_VERSION_MAJOR}, got \
             {}.{}",
            info.cryptokiVersion.major, info.cryptokiVersion.minor
        )));
    }
    if info.cryptokiVersion.minor > CRYPTOKI_VERSION_MINOR {
        return Err(KmsCliError::Default(format!(
            "FAIL [C_GetInfo]: reported minor version {}.{} exceeds this provider's known-\
             implemented v{CRYPTOKI_VERSION_MAJOR}.{CRYPTOKI_VERSION_MINOR}",
            info.cryptokiVersion.major, info.cryptokiVersion.minor
        )));
    }

    let manufacturer = trim_padded_ck_string(&info.manufacturerID);
    let description = trim_padded_ck_string(&info.libraryDescription);
    println!(
        "[C_GetInfo] OK: Cryptoki v{}.{}",
        info.cryptokiVersion.major, info.cryptokiVersion.minor
    );
    println!("  manufacturerID:      {manufacturer}");
    println!("  libraryDescription:  {description}");
    println!(
        "  libraryVersion:      {}.{}",
        info.libraryVersion.major, info.libraryVersion.minor
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// C_GetMechanismList / C_GetMechanismInfo
// ---------------------------------------------------------------------------

/// PKCS#11 v3 mechanisms this provider must advertise, and the capability flags each must
/// report in `C_GetMechanismInfo` (PKCS#11 v3.1 §5.2 Table 3). Mirrors
/// `cosmian_pkcs11_module::core::mechanism::SUPPORTED_SIGNATURE_MECHANISMS`.
const REQUIRED_MECHANISMS: &[(CK_MECHANISM_TYPE, &str, CK_FLAGS)] = &[
    (CKM_AES_GCM, "CKM_AES_GCM", CKF_ENCRYPT | CKF_DECRYPT),
    (CKM_RSA_PKCS_PSS, "CKM_RSA_PKCS_PSS", CKF_SIGN | CKF_VERIFY),
    (CKM_ECDSA, "CKM_ECDSA", CKF_SIGN | CKF_VERIFY),
    (CKM_EDDSA, "CKM_EDDSA", CKF_SIGN | CKF_VERIFY),
];

/// Enumerates the mechanism list for `slot_id` and asserts that every mechanism in
/// [`REQUIRED_MECHANISMS`] is both advertised and reports the expected capability flags.
fn call_verify_mechanisms(func_list: &CK_FUNCTION_LIST, slot_id: CK_SLOT_ID) -> KmsCliResult<()> {
    let c_get_mechanism_list = func_list.C_GetMechanismList.ok_or_else(|| {
        KmsCliError::Default("FAIL [C_GetMechanismList]: not present in function list".to_owned())
    })?;

    let mut count: CK_ULONG = 0;
    let rv = unsafe { c_get_mechanism_list(slot_id, ptr::null_mut(), &raw mut count) };
    check_rv(rv, "C_GetMechanismList (count)")?;

    let mechanism_count = usize::try_from(count).map_err(|e| {
        KmsCliError::Default(format!(
            "FAIL [C_GetMechanismList]: mechanism count out of range for usize: {e}"
        ))
    })?;
    let mut mechanisms: Vec<CK_MECHANISM_TYPE> = vec![0; mechanism_count];
    let rv = unsafe { c_get_mechanism_list(slot_id, mechanisms.as_mut_ptr(), &raw mut count) };
    check_rv(rv, "C_GetMechanismList (fill)")?;

    println!("[C_GetMechanismList] {mechanism_count} mechanism(s) advertised");

    let c_get_mechanism_info = func_list.C_GetMechanismInfo.ok_or_else(|| {
        KmsCliError::Default("FAIL [C_GetMechanismInfo]: not present in function list".to_owned())
    })?;

    for &(mechanism, name, expected_flags) in REQUIRED_MECHANISMS {
        if !mechanisms.contains(&mechanism) {
            return Err(KmsCliError::Default(format!(
                "FAIL [C_GetMechanismList]: required PKCS#11 v3 mechanism {name} is not \
                 advertised for slot {slot_id}"
            )));
        }

        let mut info = CK_MECHANISM_INFO::default();
        let rv = unsafe { c_get_mechanism_info(slot_id, mechanism, &raw mut info) };
        check_rv(rv, &format!("C_GetMechanismInfo({name})"))?;

        if info.flags & expected_flags != expected_flags {
            return Err(KmsCliError::Default(format!(
                "FAIL [C_GetMechanismInfo({name})]: expected flags 0x{expected_flags:08X}, got \
                 0x{:08X}",
                info.flags
            )));
        }
        println!("  {name}: flags=0x{:08X}", info.flags);
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
    Ok(find_handles_by_class(func_list, session, class, class_name)?.len())
}

/// Runs the standard `C_FindObjectsInit`/`C_FindObjects`/`C_FindObjectsFinal` sequence for a
/// single object class and returns every matching object handle. Shared by the summary counter
/// (`count_objects_by_class`) and the `CKO_PROFILE` attribute-level checks
/// (`call_verify_profiles`), which need the handles themselves, not just a count.
fn find_handles_by_class(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
    class: CK_OBJECT_CLASS,
    class_name: &str,
) -> Result<Vec<CK_OBJECT_HANDLE>, String> {
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

    let mut all_handles: Vec<CK_OBJECT_HANDLE> = Vec::new();
    loop {
        let mut handles: Vec<CK_OBJECT_HANDLE> = vec![0; MAX_OBJECTS];
        let mut found: CK_ULONG = 0;
        let rv = unsafe { c_find_objects(session, handles.as_mut_ptr(), max_ck, &raw mut found) };
        check_rv_raw(rv, &format!("C_FindObjects({class_name})"))?;

        let batch = usize::try_from(found).map_err(|e| {
            format!("FAIL [C_FindObjects({class_name})]: found-count out of usize range: {e}")
        })?;
        if let Some(slice) = handles.get(..batch) {
            all_handles.extend_from_slice(slice);
        }

        if batch < MAX_OBJECTS {
            break;
        }
    }

    let c_find_objects_final = func_list
        .C_FindObjectsFinal
        .ok_or_else(|| "FAIL [C_FindObjectsFinal]: not present in function list".to_owned())?;
    let rv = unsafe { c_find_objects_final(session) };
    check_rv_raw(rv, &format!("C_FindObjectsFinal({class_name})"))?;

    Ok(all_handles)
}

/// PKCS#11 v3.0 conformance profiles known to be self-declared by this provider (see
/// `CKO_PROFILE` handling in `cosmian_pkcs11_module::core::object`).
const KNOWN_PROFILES: &[(CK_ULONG, &str)] = &[
    (CKP_BASELINE_PROVIDER, "CKP_BASELINE_PROVIDER"),
    (CKP_EXTENDED_PROVIDER, "CKP_EXTENDED_PROVIDER"),
    (CKP_AUTHENTICATION_TOKEN, "CKP_AUTHENTICATION_TOKEN"),
    (
        CKP_PUBLIC_CERTIFICATES_TOKEN,
        "CKP_PUBLIC_CERTIFICATES_TOKEN",
    ),
];

/// Verifies PKCS#11 v3.0 profile self-declaration (§4.5): at least one `CKO_PROFILE` object
/// must be discoverable, and each one's `CKA_PROFILE_ID` must be a value this provider is
/// actually known to implement.
fn call_verify_profiles(
    func_list: &CK_FUNCTION_LIST,
    session: CK_SESSION_HANDLE,
) -> KmsCliResult<()> {
    let handles = find_handles_by_class(func_list, session, CKO_PROFILE, "CKO_PROFILE")
        .map_err(KmsCliError::Default)?;

    if handles.is_empty() {
        return Err(KmsCliError::Default(
            "FAIL [CKO_PROFILE]: no conformance-profile object found — a PKCS#11 v3 provider \
             MUST self-declare at least one profile via an object with CKA_CLASS = CKO_PROFILE"
                .to_owned(),
        ));
    }

    let c_get_attribute_value = func_list.C_GetAttributeValue.ok_or_else(|| {
        KmsCliError::Default("FAIL [C_GetAttributeValue]: not present in function list".to_owned())
    })?;

    let profile_id_len = CK_ULONG::try_from(size_of::<CK_ULONG>()).map_err(|e| {
        KmsCliError::Default(format!(
            "FAIL [CKO_PROFILE]: size_of overflows CK_ULONG: {e}"
        ))
    })?;

    for handle in handles {
        let mut profile_id: CK_ULONG = 0;
        let mut template = CK_ATTRIBUTE {
            type_: CKA_PROFILE_ID,
            pValue: (&raw mut profile_id).cast::<c_void>(),
            ulValueLen: profile_id_len,
        };
        let rv = unsafe { c_get_attribute_value(session, handle, &raw mut template, 1) };
        check_rv(rv, "C_GetAttributeValue(CKA_PROFILE_ID)")?;

        match KNOWN_PROFILES.iter().find(|(id, _)| *id == profile_id) {
            Some((_, name)) => println!("  profile: {name}"),
            None => {
                return Err(KmsCliError::Default(format!(
                    "FAIL [CKO_PROFILE]: object handle {handle} advertises unknown \
                     CKA_PROFILE_ID {profile_id}"
                )));
            }
        }
    }

    Ok(())
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
