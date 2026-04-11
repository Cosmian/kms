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
    use pkcs11_sys::{CK_FUNCTION_LIST, CK_INVALID_HANDLE, CKR_OK};
    use serial_test::serial;
    use test_kms_server::{AUTH0_TOKEN, start_default_test_kms_server_with_jwt_auth};
    use tokio::runtime::Runtime;

    use crate::{
        call_decrypt_aes_cbc_pad, call_encrypt_aes_cbc_pad, call_find_objects,
        call_generate_aes_key, call_get_function_list, call_get_slot_list, call_login,
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

    /// Forward wallet migration: Oracle TDE software wallet → HSM wallet.
    ///
    /// Verifies that after `C_Login` the provider can:
    /// 1. Accept `C_GenerateKey(CKM_AES_KEY_GEN, label="ORACLE.SECURITY.DB.…")` —
    ///    the call that Oracle issues during `ADMINISTER KEY MANAGEMENT SET ENCRYPTION
    ///    KEY … MIGRATE USING …`.
    /// 2. Accept `C_EncryptInit` + `C_Encrypt` on the newly-created key — the
    ///    call that re-wraps existing DEKs under the new HSM master key.
    ///
    /// The test would have failed before the fix that removed `CKF_WRITE_PROTECTED`
    /// from `C_GetTokenInfo` (Oracle skips `C_GenerateKey` when that flag is set)
    /// and before `CKM_AES_KEY_GEN` was added to `SUPPORTED_SIGNATURE_MECHANISMS`.
    #[test]
    #[serial]
    #[allow(clippy::expect_used)]
    fn test_pkcs11_migrate_software_to_hsm() {
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
            "pkcs11_migrate_sw_hsm_test_{}.toml",
            std::process::id()
        ));
        std::fs::write(&conf_file, &conf_content).expect("write temp conf file");
        unsafe { env::set_var("CKMS_CONF", &conf_file) };

        // ── C: Load cdylib and initialise ───────────────────────────────────
        let lib_path = pkcs11_lib_path();
        assert!(
            lib_path.exists(),
            "cdylib not found at {}",
            lib_path.display()
        );
        let lib = unsafe { Library::new(&lib_path) }.expect("load cdylib");

        let func_list_ptr = call_get_function_list(&lib).expect("C_GetFunctionList");
        let func_list: &CK_FUNCTION_LIST = unsafe { &*func_list_ptr };

        let c_initialize = func_list.C_Initialize.expect("C_Initialize");
        let rv = unsafe { c_initialize(ptr::null_mut::<c_void>()) };
        assert_eq!(rv, CKR_OK, "C_Initialize failed: {rv:#010X}");

        let slot_id = call_get_slot_list(func_list).expect("C_GetSlotList");
        let session = call_open_session(func_list, slot_id).expect("C_OpenSession");

        // ── D: C_Login with the OIDC bearer token ───────────────────────────
        call_login(func_list, session, AUTH0_TOKEN).expect("C_Login");

        // ── E: C_GenerateKey — Oracle TDE master key label format ───────────
        // This call previously returned CKR_TOKEN_WRITE_PROTECTED because
        // CKF_WRITE_PROTECTED was set in C_GetTokenInfo.
        let key_handle = call_generate_aes_key(
            func_list,
            session,
            "ORACLE.SECURITY.DB.ENCRYPTION.MASTERKEY.TEST_MIGRATE",
        )
        .expect("C_GenerateKey must succeed — token must not be CKF_WRITE_PROTECTED");
        assert_ne!(
            key_handle, CK_INVALID_HANDLE,
            "C_GenerateKey returned CK_INVALID_HANDLE"
        );

        // ── F: C_EncryptInit + C_Encrypt — simulate DEK wrapping ─────────────
        let fake_dek = b"test_dek_material_16";
        let ciphertext = call_encrypt_aes_cbc_pad(func_list, session, key_handle, fake_dek)
            .expect("C_Encrypt must succeed with the generated AES-256 key");
        assert!(
            !ciphertext.is_empty(),
            "C_Encrypt returned empty ciphertext"
        );

        // ── G: Teardown ───────────────────────────────────────────────────────
        let c_close_session = func_list.C_CloseSession.expect("C_CloseSession");
        let rv = unsafe { c_close_session(session) };
        check_rv(rv, "C_CloseSession").expect("C_CloseSession");

        let c_finalize = func_list.C_Finalize.expect("C_Finalize");
        let rv = unsafe { c_finalize(ptr::null_mut::<c_void>()) };
        check_rv(rv, "C_Finalize").expect("C_Finalize");

        std::fs::remove_file(&conf_file).ok();
        unsafe { env::remove_var("CKMS_CONF") };
    }

    /// Reverse wallet migration: Oracle TDE HSM wallet → software wallet.
    ///
    /// Verifies that after `C_GenerateKey` the provider can perform the
    /// full encrypt-then-decrypt round-trip on the newly-created HSM master key.
    ///
    /// This mirrors what Oracle does during `ADMINISTER KEY MANAGEMENT SET
    /// ENCRYPTION KEY … REVERSE MIGRATE USING …`:
    /// - `C_DecryptInit` + `C_Decrypt` on the current HSM key to obtain the
    ///   plaintext DEK, which Oracle then re-encrypts under the new software key.
    #[test]
    #[serial]
    #[allow(clippy::expect_used)]
    fn test_pkcs11_reverse_migrate_hsm_to_software() {
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
            "pkcs11_reverse_migrate_test_{}.toml",
            std::process::id()
        ));
        std::fs::write(&conf_file, &conf_content).expect("write temp conf file");
        unsafe { env::set_var("CKMS_CONF", &conf_file) };

        // ── C: Load cdylib and initialise ───────────────────────────────────
        let lib_path = pkcs11_lib_path();
        assert!(
            lib_path.exists(),
            "cdylib not found at {}",
            lib_path.display()
        );
        let lib = unsafe { Library::new(&lib_path) }.expect("load cdylib");

        let func_list_ptr = call_get_function_list(&lib).expect("C_GetFunctionList");
        let func_list: &CK_FUNCTION_LIST = unsafe { &*func_list_ptr };

        let c_initialize = func_list.C_Initialize.expect("C_Initialize");
        let rv = unsafe { c_initialize(ptr::null_mut::<c_void>()) };
        assert_eq!(rv, CKR_OK, "C_Initialize failed: {rv:#010X}");

        let slot_id = call_get_slot_list(func_list).expect("C_GetSlotList");
        let session = call_open_session(func_list, slot_id).expect("C_OpenSession");

        // ── D: C_Login with the OIDC bearer token ───────────────────────────
        call_login(func_list, session, AUTH0_TOKEN).expect("C_Login");

        // ── E: C_GenerateKey — create the HSM master key ────────────────────
        let key_handle = call_generate_aes_key(
            func_list,
            session,
            "ORACLE.SECURITY.DB.ENCRYPTION.MASTERKEY.TEST_REVMIG",
        )
        .expect("C_GenerateKey");
        assert_ne!(key_handle, CK_INVALID_HANDLE);

        // ── F: Simulate reverse migration: wrap then unwrap a DEK ────────────
        // During REVERSE MIGRATE, Oracle uses the HSM master key to decrypt
        // the existing wrapped DEK so it can re-encrypt it under the new
        // software key.  We simulate that with an encrypt-then-decrypt round-trip.
        let original_dek = b"test_dek_16bytes!!";
        let wrapped_dek = call_encrypt_aes_cbc_pad(func_list, session, key_handle, original_dek)
            .expect("C_Encrypt (DEK wrapping)");
        let recovered_dek = call_decrypt_aes_cbc_pad(func_list, session, key_handle, &wrapped_dek)
            .expect("C_Decrypt (DEK unwrapping — reverse migration)");
        assert_eq!(
            recovered_dek.as_slice(),
            original_dek.as_slice(),
            "Decrypted DEK does not match original — HSM key cannot unwrap DEKs for reverse \
             migration"
        );

        // ── G: Teardown ───────────────────────────────────────────────────────
        let c_close_session = func_list.C_CloseSession.expect("C_CloseSession");
        let rv = unsafe { c_close_session(session) };
        check_rv(rv, "C_CloseSession").expect("C_CloseSession");

        let c_finalize = func_list.C_Finalize.expect("C_Finalize");
        let rv = unsafe { c_finalize(ptr::null_mut::<c_void>()) };
        check_rv(rv, "C_Finalize").expect("C_Finalize");

        std::fs::remove_file(&conf_file).ok();
        unsafe { env::remove_var("CKMS_CONF") };
    }
}
