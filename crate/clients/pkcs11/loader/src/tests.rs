//! Integration tests for the `cosmian_pkcs11_verify` loader.
//!
//! These tests exercise the full PKCS#11 ABI by dynamically loading
//! `libcosmian_pkcs11` and stepping through the same call sequence used by
//! the `cosmian_pkcs11_verify` CLI binary.
//!
//! The cdylib path is derived from `COSMIAN_PKCS11_LIB_DIR`, which is emitted
//! as a compile-time env var by `build.rs` (computed from `OUT_DIR`).  The
//! cdylib itself is built as a side-effect of the workspace build that runs
//! before the tests: `cargo test-non-fips` = `cargo test --lib --workspace
//! --features non-fips` builds ALL workspace members, including
//! `cosmian_pkcs11` (cdylib).
//!
//! All tests in this module require the `non-fips` feature and are therefore
//! compiled only when `cargo test --features non-fips` (or the `cargo
//! test-non-fips` alias) is used.

// ── OIDC / mode-2 integration test ─────────────────────────────────────────
//
// Guarded by `#[cfg(feature = "non-fips")]` so that the test (and its deps:
// test_kms_server, tokio, serial_test) are only compiled and run in non-fips
// mode.  In fips mode this file compiles as an empty module.
#[cfg(feature = "non-fips")]
mod pin_auth {
    //! Test the full PKCS#11 sequence with OIDC / JWT bearer-token
    //! authentication (mode 2: `pkcs11_use_pin_as_access_token = true`).

    use std::{env, ffi::c_void, ptr};

    use libloading::Library;
    use pkcs11_sys::{CK_FUNCTION_LIST, CKR_OK};
    use serial_test::serial;
    use test_kms_server::{AUTH0_TOKEN, start_default_test_kms_server_with_jwt_auth};
    use tokio::runtime::Runtime;

    use crate::{
        call_find_objects, call_get_function_list, call_get_slot_list, call_login,
        call_open_session, check_rv,
    };

    /// Returns the expected path to the `cosmian_pkcs11` cdylib for the
    /// current platform.
    ///
    /// `COSMIAN_PKCS11_LIB_DIR` is set at compile time by `build.rs` (derived
    /// from `OUT_DIR`) and points to the same `target/{profile}/` directory
    /// where `cargo build -p cosmian_pkcs11 --features non-fips` places its
    /// output.  When running `cargo test-non-fips` (which builds the whole
    /// workspace), the cdylib will already be present by the time this test
    /// runs.
    fn pkcs11_lib_path() -> std::path::PathBuf {
        let dir = env!("COSMIAN_PKCS11_LIB_DIR");
        #[cfg(target_os = "macos")]
        return std::path::PathBuf::from(dir).join("libcosmian_pkcs11.dylib");
        #[cfg(target_os = "linux")]
        return std::path::PathBuf::from(dir).join("libcosmian_pkcs11.so");
        #[cfg(target_os = "windows")]
        return std::path::PathBuf::from(dir).join("cosmian_pkcs11.dll");
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        panic!("unsupported platform for PKCS#11 cdylib path");
    }

    /// Full PKCS#11 sequence with OIDC / JWT bearer-token authentication.
    ///
    /// Mirrors exactly what the CLI command does:
    ///
    /// ```text
    /// cosmian_pkcs11_verify \
    ///   --so-path target/debug/libcosmian_pkcs11.dylib \
    ///   --conf test_data/configs/client/test/pkcs11_oidc.toml \
    ///   --token <JWT>
    /// ```
    ///
    /// but uses an in-process test KMS server (with JWT auth enabled) and the
    /// long-lived `AUTH0_TOKEN` constant instead of a live Auth0-issued JWT.
    ///
    /// Steps:
    ///  A. Start (or reuse) a JWT-auth test KMS server.
    ///  B. Write a mode-2 `ckms.toml` pointing at the server port.
    ///  C. Set `CKMS_CONF` so the provider finds the config.
    ///  D. Load `libcosmian_pkcs11`.
    ///  E–K. Walk through `C_GetFunctionList` → `C_Initialize` →
    ///       `C_GetSlotList` → `C_OpenSession` → **`C_Login`** →
    ///       `C_FindObjects` → `C_CloseSession` → `C_Finalize`.
    #[test]
    #[serial]
    #[allow(clippy::expect_used)]
    fn test_pkcs11_oidc_login_full_sequence() {
        // ── A: Start / reuse the JWT-auth test KMS server ───────────────────
        let rt = Runtime::new().expect("tokio runtime");
        let ctx = rt.block_on(async { start_default_test_kms_server_with_jwt_auth().await });
        let port = ctx.server_port;

        // ── B: Write a temporary mode-2 ckms.toml ───────────────────────────
        let conf_content = format!(
            "pkcs11_use_pin_as_access_token = true\n\n[http_config]\nserver_url = \
             \"http://localhost:{port}\"\n"
        );
        let conf_file = std::env::temp_dir().join(format!(
            "pkcs11_oidc_loader_test_{}.toml",
            std::process::id()
        ));
        std::fs::write(&conf_file, &conf_content).expect("write temp conf file");

        // ── C: Point the provider at the temp config ─────────────────────────
        // Safety: the test is `#[serial]`, so no concurrent threads mutate the
        // environment here.  This mirrors the unsafe set_var in main.rs::run().
        unsafe { env::set_var("CKMS_CONF", &conf_file) };

        // ── D: Load the cdylib ───────────────────────────────────────────────
        let lib_path = pkcs11_lib_path();
        assert!(
            lib_path.exists(),
            "cosmian_pkcs11 cdylib not found at {}: run `cargo build -p \
             cosmian_pkcs11 --features non-fips` first, or use `cargo \
             test-non-fips` which builds all workspace members",
            lib_path.display()
        );
        let lib = unsafe { Library::new(&lib_path) }.expect("failed to open cosmian_pkcs11 cdylib");

        // ── E: C_GetFunctionList ─────────────────────────────────────────────
        let func_list_ptr = call_get_function_list(&lib).expect("C_GetFunctionList");
        // Safety: C_GetFunctionList returned CKR_OK and wrote a non-null pointer;
        // the function list is valid for the lifetime of `lib`.
        let func_list: &CK_FUNCTION_LIST = unsafe { &*func_list_ptr };

        // ── F: C_Initialize ──────────────────────────────────────────────────
        let c_initialize = func_list
            .C_Initialize
            .expect("C_Initialize must be in the function list");
        let rv = unsafe { c_initialize(ptr::null_mut::<c_void>()) };
        assert_eq!(rv, CKR_OK, "C_Initialize failed with rv={rv:#010X}");

        // ── G: C_GetSlotList ─────────────────────────────────────────────────
        let slot_id = call_get_slot_list(func_list).expect("C_GetSlotList");

        // ── H: C_OpenSession ─────────────────────────────────────────────────
        let session = call_open_session(func_list, slot_id).expect("C_OpenSession");

        // ── I: C_Login — inject the JWT bearer token ─────────────────────────
        call_login(func_list, session, AUTH0_TOKEN)
            .expect("C_Login must succeed with a valid JWT bearer token");

        // ── J: C_FindObjects — enumerate all PKCS#11 object classes ──────────
        let _total = call_find_objects(func_list, session);

        // ── K: C_CloseSession ────────────────────────────────────────────────
        let c_close_session = func_list
            .C_CloseSession
            .expect("C_CloseSession must be in the function list");
        let rv = unsafe { c_close_session(session) };
        check_rv(rv, "C_CloseSession").expect("C_CloseSession");

        // ── L: C_Finalize ────────────────────────────────────────────────────
        let c_finalize = func_list
            .C_Finalize
            .expect("C_Finalize must be in the function list");
        let rv = unsafe { c_finalize(ptr::null_mut::<c_void>()) };
        check_rv(rv, "C_Finalize").expect("C_Finalize");

        // ── Cleanup ───────────────────────────────────────────────────────────
        // Best-effort cleanup: removing a temp file is non-critical.
        std::fs::remove_file(&conf_file).ok();
        // Safety: restoring env to a clean state while still single-threaded
        // (holding the `serial` lock).
        unsafe { env::remove_var("CKMS_CONF") };
    }
}
