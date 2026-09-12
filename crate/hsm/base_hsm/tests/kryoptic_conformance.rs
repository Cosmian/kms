//! Real (not simulated) PKCS#11 v3.0/v3.1 conformance tests against the published
//! `kryoptic` software token (<https://github.com/latchset/kryoptic>), chosen as the
//! v3.0-capable test oracle for the `base_hsm` PKCS#11 v3 refactor.
//!
//! `kryoptic` is backed by Red Hat's `latchset` identity team (positioned as the RHEL
//! replacement for NSS softoken/SoftHSM2) and, unlike the existing SoftHSM2-based test
//! suites (PKCS#11 v2.40-only, see `softhsm2::tests`), genuinely implements v3.0
//! mechanisms (`CKM_EDDSA`, `CKM_HKDF_DERIVE`, message-based AEAD). This lets the
//! graceful-degradation paths regression-tested in `hsm_lib.rs` against a synthetic
//! C fixture also be exercised end-to-end against a real, spec-conformant v3.0
//! library.
//!
//! ("Craton HSM" was evaluated and rejected as the primary conformance oracle: a
//! ~5-month-old, low-adoption, unaudited pure-Rust PQC-focused implementation is not
//! an appropriate trusted reference for protocol conformance in a FIPS-140-3-oriented
//! KMS. It remains a candidate to revisit once more mature.)
//!
//! This test does **not** build `kryoptic` itself: it reads the path to an
//! already-built cdylib from the `KRYOPTIC_PKCS11_LIB` environment variable —
//! mirroring how the `SoftHSM2` test suite reads `SOFTHSM2_PKCS11_LIB` — set by the
//! `.mise/lib/kryoptic.sh::kryoptic_build_cdylib` helper, which downloads+builds
//! `kryoptic` out-of-tree on first run (network access + a working
//! `curl`/`tar`/`cargo` toolchain required). Run via:
//! ```sh
//! mise run test:hsm-kryoptic-conformance
//! ```
//! They are `#[ignore]`d by default, consistent with the other vendor HSM test
//! suites in this workspace.
#![expect(clippy::expect_used)]
#![expect(unsafe_code)]

use std::{
    collections::HashMap,
    ffi::c_void,
    fs,
    path::{Path, PathBuf},
    ptr,
};

use cosmian_kms_base_hsm::{
    AesKeySize, BaseHsm, HsmSigningAlgorithm,
    hsm_capabilities::{HsmCapabilities, HsmProvider},
};
use libloading::Library;
use pkcs11_sys::{
    CK_C_INITIALIZE_ARGS, CK_FUNCTION_LIST_PTR, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG,
    CKF_OS_LOCKING_OK, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKM_SHA256, CKR_OK, CKU_SO,
};

struct KryopticCapabilityProvider;

impl HsmProvider for KryopticCapabilityProvider {
    fn capabilities() -> HsmCapabilities {
        HsmCapabilities::default()
    }
}

/// `kryoptic` numbers its configured slots starting at 1 (slot 0 is reserved), per
/// its `testdata/test.conf` example (`[[slots]] slot = 1 ...`).
const SLOT_ID: usize = 1;
const SO_PIN: &str = "87654321";
const USER_PIN: &str = "12345678";

/// Writes a minimal `kryoptic` `KRYOPTIC_CONF` TOML file pointing at a fresh, unique
/// sqlite-backed token database under the system temp dir, and points the
/// `KRYOPTIC_CONF` environment variable at it.
///
/// # Safety
/// `std::env::set_var` is process-global and therefore only safe to call when no
/// other thread may concurrently read/write the environment. All the conformance
/// tests in this file are consolidated into a single `#[test]` function
/// (`test_kryoptic_pkcs11_v3_conformance_suite`) specifically so this is called
/// exactly once, before any other thread-spawning/env-reading code runs.
fn configure_kryoptic_token() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "cosmian-kms-kryoptic-conformance-token-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("failed to create kryoptic token directory");
    let db_path = dir.join("token.sql");
    let conf_path = dir.join("token.conf");
    fs::write(
        &conf_path,
        format!(
            "[[slots]]\nslot = {SLOT_ID}\ndbtype = \"sqlite\"\ndbargs = \"{}\"\n",
            db_path.display()
        ),
    )
    .expect("failed to write kryoptic token.conf");
    // SAFETY: see the function doc comment — called once, single-threaded, before
    // any BaseHsm/session code (which may spawn threads) runs.
    #[allow(
        unsafe_code,
        reason = "single-threaded, one-time env setup before any HSM code runs"
    )]
    unsafe {
        std::env::set_var("KRYOPTIC_CONF", &conf_path);
    }
    conf_path
}

/// Loads the `kryoptic` cdylib directly (bypassing `BaseHsm`/`Session`) to perform
/// the one-time SO (Security Officer) token bootstrap — `C_InitToken` followed by
/// `C_InitPIN` under an SO login — which every fresh PKCS#11 token requires before
/// any ordinary user session can be opened.
///
/// `base_hsm`'s `Session`/`SlotManager` API intentionally does not expose this flow:
/// production HSMs (SoftHSM2/Utimaco/Proteccio/etc.) are pre-provisioned by the
/// vendor's own tooling or a wizard step, never bootstrapped by the KMS itself. Only
/// this test-only conformance oracle needs to self-provision a token from scratch.
///
/// Note: `kryoptic`, like some strictly spec-conformant v3.0 libraries (see the
/// `hsm_lib.rs` function-table-fallback regression tests from Phase 0/1 of this
/// refactor), exports *only* `C_GetFunctionList` — individual `C_*` symbols are not
/// directly `dlsym`-able — so every call here goes through the resolved
/// `CK_FUNCTION_LIST` table, exactly like `HsmLib` does internally.
///
/// Returns the `Library` handle so the caller can keep it alive for the remainder of
/// the test: dropping it would `dlclose` the module and could reset its in-memory
/// state before `BaseHsm::instantiate` (which independently `dlopen`s the same path)
/// gets a chance to use it.
fn bootstrap_kryoptic_token(lib_path: &Path) -> Library {
    // SAFETY: loading a locally-built, version-pinned PKCS#11 library for a
    // dedicated, single-threaded conformance-test bootstrap sequence.
    let library = unsafe { Library::new(lib_path) }.expect("failed to load kryoptic cdylib");
    // SAFETY: macOS does not honor `.init_array`-based ctors, so `kryoptic`'s
    // logging initializer never runs automatically there (only on Linux); call
    // its exported `kryoptic_log_init` symbol directly so `KRYOPTIC_TRACE`/
    // `KRYOPTIC_TRACE_LEVEL` still work for local debugging on this platform.
    unsafe {
        if let Ok(log_init) = library.get::<unsafe extern "C" fn()>(b"kryoptic_log_init") {
            log_init();
        }
    }
    // SAFETY: `C_GetFunctionList`/the functions in the resolved table are the
    // standard PKCS#11 v2.01+ entry points; called here exactly once, sequentially,
    // before any other use of the library.
    unsafe {
        let get_function_list = library
            .get::<unsafe extern "C" fn(*mut CK_FUNCTION_LIST_PTR) -> CK_RV>(b"C_GetFunctionList")
            .expect("C_GetFunctionList symbol not found");
        let mut function_list_ptr: CK_FUNCTION_LIST_PTR = ptr::null_mut();
        let rv = get_function_list(&raw mut function_list_ptr);
        assert_eq!(rv, CKR_OK, "C_GetFunctionList failed with rv {rv}");
        let functions = &*function_list_ptr;

        let init = functions
            .C_Initialize
            .expect("C_Initialize function pointer is null");
        let mut init_args = CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: CKF_OS_LOCKING_OK,
            pReserved: ptr::null_mut(),
        };
        let rv = init((&raw mut init_args).cast::<c_void>());
        assert_eq!(rv, CKR_OK, "C_Initialize failed with rv {rv}");

        let init_token = functions
            .C_InitToken
            .expect("C_InitToken function pointer is null");
        let mut so_pin = SO_PIN.as_bytes().to_vec();
        // The PKCS#11 `pLabel` argument to `C_InitToken` is a fixed 32-byte,
        // space-padded (not NUL-terminated) UTF-8 buffer.
        let mut label = *b"Cosmian Kryoptic Conf           ";
        let rv = init_token(
            CK_SLOT_ID::try_from(SLOT_ID).expect("slot id out of range"),
            so_pin.as_mut_ptr(),
            CK_ULONG::try_from(so_pin.len()).expect("SO PIN length out of range"),
            label.as_mut_ptr(),
        );
        assert_eq!(rv, CKR_OK, "C_InitToken failed with rv {rv}");

        let open_session = functions
            .C_OpenSession
            .expect("C_OpenSession function pointer is null");
        let mut session_handle: CK_SESSION_HANDLE = 0;
        let rv = open_session(
            CK_SLOT_ID::try_from(SLOT_ID).expect("slot id out of range"),
            CKF_RW_SESSION | CKF_SERIAL_SESSION,
            ptr::null_mut(),
            None,
            &raw mut session_handle,
        );
        assert_eq!(rv, CKR_OK, "C_OpenSession (bootstrap) failed with rv {rv}");

        let login = functions.C_Login.expect("C_Login function pointer is null");
        let rv = login(
            session_handle,
            CKU_SO,
            so_pin.as_mut_ptr(),
            CK_ULONG::try_from(so_pin.len()).expect("SO PIN length out of range"),
        );
        assert_eq!(rv, CKR_OK, "C_Login (SO) failed with rv {rv}");

        let init_pin = functions
            .C_InitPIN
            .expect("C_InitPIN function pointer is null");
        let mut user_pin = USER_PIN.as_bytes().to_vec();
        let rv = init_pin(
            session_handle,
            user_pin.as_mut_ptr(),
            CK_ULONG::try_from(user_pin.len()).expect("user PIN length out of range"),
        );
        assert_eq!(rv, CKR_OK, "C_InitPIN failed with rv {rv}");

        let logout = functions
            .C_Logout
            .expect("C_Logout function pointer is null");
        let rv = logout(session_handle);
        assert_eq!(rv, CKR_OK, "C_Logout failed with rv {rv}");

        let close_session = functions
            .C_CloseSession
            .expect("C_CloseSession function pointer is null");
        let rv = close_session(session_handle);
        assert_eq!(rv, CKR_OK, "C_CloseSession (bootstrap) failed with rv {rv}");

        // Intentionally do NOT call `C_Finalize` here: `library` is kept alive
        // (and the underlying module thus stays loaded/initialized) by the caller
        // for the remainder of the test, until `BaseHsm::instantiate` takes over.
    }
    library
}

fn instantiate(lib_path: &Path) -> BaseHsm<KryopticCapabilityProvider> {
    BaseHsm::<KryopticCapabilityProvider>::instantiate(
        lib_path.to_string_lossy().as_ref(),
        HashMap::from([(SLOT_ID, Some(USER_PIN.to_owned()))]),
    )
    .expect("failed to instantiate the kryoptic PKCS#11 library")
}

/// Path to the pre-built `kryoptic` cdylib, provided by
/// `.mise/lib/kryoptic.sh::kryoptic_build_cdylib` — this test does not build
/// `kryoptic` itself (see the module doc comment).
fn kryoptic_pkcs11_lib_path() -> PathBuf {
    PathBuf::from(std::env::var("KRYOPTIC_PKCS11_LIB").expect(
        "KRYOPTIC_PKCS11_LIB is not set. Run this suite via `mise run \
         test:hsm-kryoptic-conformance`, which builds the kryoptic cdylib and sets it.",
    ))
}

/// Real (populated) PKCS#11 v3.0 interface-list probe: unlike `SoftHSM2` (v2.40-only,
/// see `softhsm2::tests::test_hsm_softhsm2_pkcs11_v3_capability_probe_is_additive`,
/// which always observes `None`), `kryoptic` is a genuine v3.0 library and must
/// report a non-empty interface list via `C_GetInterfaceList` (issue #1153).
fn check_pkcs11_v3_interface_list_is_populated(hsm: &BaseHsm<KryopticCapabilityProvider>) {
    assert!(hsm.hsm_lib().supports_pkcs11_v3_interfaces());
    let interfaces = hsm
        .hsm_lib()
        .list_pkcs11_v3_interfaces()
        .expect("failed to list PKCS#11 v3 interfaces")
        .expect("kryoptic must report v3 interfaces");
    assert!(!interfaces.is_empty());
    assert!(
        interfaces
            .iter()
            .all(|interface| !interface.name.is_empty())
    );
}

/// `EdDSA` (Ed25519) key generation, sign, and verify via `CKM_EC_EDWARDS_KEY_PAIR_GEN`
/// / `CKM_EDDSA` (OASIS Cryptoki v3.0 §2.3.9) — the mechanism family added in Phase 1
/// of the `base_hsm` v3 refactor (`session/eddsa.rs`).
fn check_eddsa_sign_and_verify_round_trip(hsm: &BaseHsm<KryopticCapabilityProvider>) {
    let slot = hsm.get_slot(SLOT_ID).expect("failed to get slot");
    let session = slot.open_session(true).expect("failed to open session");
    let (sk, pk) = session
        .generate_eddsa_key_pair(b"eddsa-sk", b"eddsa-pk", false)
        .expect("kryoptic must support CKM_EC_EDWARDS_KEY_PAIR_GEN (v3.0 EdDSA)");
    let data = b"pkcs11 v3.1 eddsa conformance";
    let signature = session
        .sign(sk, HsmSigningAlgorithm::Eddsa, data)
        .expect("kryoptic must support CKM_EDDSA signing");
    let verified = session
        .verify(pk, HsmSigningAlgorithm::Eddsa, data, &signature)
        .expect("kryoptic must support CKM_EDDSA verification");
    assert!(verified, "EdDSA signature must verify");
}

/// HKDF key derivation via `CKM_HKDF_DERIVE` (OASIS Cryptoki v3.0 §2.5) — the
/// mechanism added in Phase 1 (`Session::derive_hkdf_key`).
fn check_hkdf_derive(hsm: &BaseHsm<KryopticCapabilityProvider>) {
    let slot = hsm.get_slot(SLOT_ID).expect("failed to get slot");
    let session = slot.open_session(true).expect("failed to open session");
    // `CKM_HKDF_DERIVE` requires `CKK_GENERIC_SECRET`/`CKK_HKDF` input key
    // material with `CKA_DERIVE` set (OASIS Cryptoki v3.0 §2.5); a `CKK_AES`
    // key is rejected by conformant libraries with `CKR_KEY_TYPE_INCONSISTENT`.
    let ikm = session
        .generate_generic_secret_key(b"hkdf-ikm", 32, false)
        .expect("failed to generate HKDF input key material");
    let derived = session
        .derive_hkdf_key(
            ikm,
            CKM_SHA256,
            Some(b"salt"),
            b"info",
            32,
            b"hkdf-derived",
            false,
        )
        .expect("kryoptic must support CKM_HKDF_DERIVE (v3.0)");
    assert_ne!(derived, 0);
}

/// Message-based AES-GCM encrypt/decrypt via `C_MessageEncryptInit`/`C_EncryptMessage`
/// and `C_MessageDecryptInit`/`C_DecryptMessage` (OASIS Cryptoki v3.0 §5.20/§5.21) —
/// the mechanism family added in Phase 1 (`session/message_aead.rs`).
fn check_message_based_aes_gcm_round_trip(hsm: &BaseHsm<KryopticCapabilityProvider>) {
    let slot = hsm.get_slot(SLOT_ID).expect("failed to get slot");
    let session = slot.open_session(true).expect("failed to open session");
    let key = session
        .generate_aes_key(b"aead-key", AesKeySize::Aes256, false)
        .expect("failed to generate AES key");
    assert!(
        hsm.hsm_lib().supports_message_encrypt(),
        "kryoptic must support C_MessageEncryptInit/C_EncryptMessage (v3.0)"
    );
    assert!(
        hsm.hsm_lib().supports_message_decrypt(),
        "kryoptic must support C_MessageDecryptInit/C_DecryptMessage (v3.0)"
    );
    let aad = b"pkcs11-v3-aad";
    let plaintext = b"pkcs11 v3.1 message-based aead conformance";
    let encrypted = session
        .encrypt_message_aes_gcm(key, aad, plaintext)
        .expect("message-based AES-GCM encryption failed");
    let iv = encrypted.iv.clone().unwrap_or_default();
    let tag = encrypted.tag.clone().unwrap_or_default();
    let decrypted = session
        .decrypt_message_aes_gcm(key, aad, &iv, &tag, &encrypted.ciphertext)
        .expect("message-based AES-GCM decryption failed");
    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

/// Runs the full PKCS#11 v3.0/v3.1 conformance suite against `kryoptic` in a single
/// test (rather than one `#[test]` per check) so that `KRYOPTIC_CONF` is set exactly
/// once via `std::env::set_var` and the `BaseHsm`/library is initialized exactly
/// once — mirroring the `softhsm2::tests::test_hsm_softhsm2_all` convention ("some
/// PKCS#11 native libraries are not safely re-initializable within the same
/// process").
#[test]
#[ignore = "Requires network access + cargo/curl/tar to build kryoptic out-of-tree"]
fn test_kryoptic_pkcs11_v3_conformance_suite() {
    configure_kryoptic_token();
    let lib_path = kryoptic_pkcs11_lib_path();
    // Kept alive for the whole test: see `bootstrap_kryoptic_token`'s doc comment.
    let _bootstrap_library = bootstrap_kryoptic_token(&lib_path);
    let hsm = instantiate(&lib_path);
    check_pkcs11_v3_interface_list_is_populated(&hsm);
    check_eddsa_sign_and_verify_round_trip(&hsm);
    check_hkdf_derive(&hsm);
    check_message_based_aes_gcm_round_trip(&hsm);
}
