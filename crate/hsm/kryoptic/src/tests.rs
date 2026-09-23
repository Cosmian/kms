use std::{
    collections::HashMap,
    ffi::c_void,
    fs,
    path::{Path, PathBuf},
    ptr,
};

use cosmian_kms_base_hsm::{
    AesKeySize, BaseHsm, HResult, HsmSigningAlgorithm, RsaOaepDigest, tests_shared as shared,
};
use libloading::Library;
use pkcs11_sys::{
    CK_C_INITIALIZE_ARGS, CK_FUNCTION_LIST_PTR, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG,
    CKF_OS_LOCKING_OK, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKM_SHA256, CKR_OK, CKU_SO,
};

use crate::{KRYOPTIC_PKCS11_LIB, KryopticCapabilityProvider};

const SLOT_ID: usize = 1;
const SO_PIN: &str = "87654321";
const USER_PIN: &str = "12345678";

fn configure_kryoptic_token() -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("cosmian-kms-kryoptic-token-{}", std::process::id()));
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

    #[allow(
        unsafe_code,
        reason = "single-threaded, one-time env setup before any HSM code runs"
    )]
    unsafe {
        std::env::set_var("KRYOPTIC_CONF", &conf_path);
    }
    conf_path
}

fn bootstrap_kryoptic_token(lib_path: &Path) -> Library {
    let library = unsafe { Library::new(lib_path) }.expect("failed to load kryoptic cdylib");
    unsafe {
        if let Ok(log_init) = library.get::<unsafe extern "C" fn()>(b"kryoptic_log_init") {
            log_init();
        }
    }
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
        let mut label = *b"Cosmian Kryoptic Token          ";
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
    }
    library
}

fn kryoptic_pkcs11_lib_path() -> PathBuf {
    let env_lib = std::env::var("KRYOPTIC_PKCS11_LIB");
    match env_lib {
        Ok(path) if !path.is_empty() => PathBuf::from(path),
        _ => {
            // Check default library path if it exists locally
            let default_path = PathBuf::from(KRYOPTIC_PKCS11_LIB);
            if default_path.exists() {
                default_path
            } else {
                panic!(
                    "KRYOPTIC_PKCS11_LIB is not set. Run this suite via `mise run \
                     test:hsm:kryoptic`, which builds the kryoptic cdylib and sets it."
                );
            }
        }
    }
}

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

fn check_hkdf_derive(hsm: &BaseHsm<KryopticCapabilityProvider>) {
    let slot = hsm.get_slot(SLOT_ID).expect("failed to get slot");
    let session = slot.open_session(true).expect("failed to open session");
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

#[test]
#[ignore = "Requires network access + cargo/curl/tar to build kryoptic out-of-tree"]
fn test_hsm_kryoptic_all() -> HResult<()> {
    if std::env::var("KRYOPTIC_CONF").is_err() {
        configure_kryoptic_token();
    }
    let lib_path = kryoptic_pkcs11_lib_path();
    // Kept alive for the whole test: see `bootstrap_kryoptic_token`'s doc comment.
    let _bootstrap_library = bootstrap_kryoptic_token(&lib_path);

    let test_cfg = shared::HsmTestConfig {
        lib_path: lib_path.to_string_lossy().into_owned(),
        slot_ids_and_passwords: HashMap::from([(SLOT_ID, Some(USER_PIN.to_owned()))]),
        slot_id_for_tests: SLOT_ID,
        rsa_oaep_digest: Some(RsaOaepDigest::SHA1),
        threads: 4,
        supports_rsa_wrap: true,
    };

    let hsm = shared::instantiate::<KryopticCapabilityProvider>(&test_cfg)?;
    drop(hsm.hsm_lib().get_info_struct()?);
    let slot = shared::get_slot::<KryopticCapabilityProvider>(&hsm, &test_cfg)?;
    shared::get_mechanisms_and_hashes(&slot)?;
    drop(hsm.get_algorithms(test_cfg.slot_id_for_tests)?);
    shared::destroy_all(&slot)?;
    shared::generate_aes_key(&slot)?;
    shared::generate_rsa_keypair(&slot)?;
    shared::rsa_key_wrap(&slot, RsaOaepDigest::SHA1)?;
    shared::rsa_pkcs_encrypt(&slot)?;
    shared::rsa_oaep_encrypt(&slot, RsaOaepDigest::SHA1)?;
    shared::aes_gcm_encrypt(&slot)?;
    shared::aes_cbc_encrypt(&slot)?;
    shared::aes_cbc_multi_round(&slot)?;
    shared::rsa_pkcs_v15_sign(&slot)?;
    shared::rsa_sha256_sign(&slot)?;
    shared::rsa_sign_all_algorithms(&slot)?;
    shared::multi_threaded_rsa(&slot, RsaOaepDigest::SHA1, test_cfg.threads)?;
    shared::get_key_metadata(&slot, true)?;
    shared::list_objects(&slot)?;
    shared::search_incompatible_key(&hsm, &test_cfg)?;
    shared::destroy_all(&slot)?;

    // PKCS#11 v3 specific checks
    check_pkcs11_v3_interface_list_is_populated(&hsm);
    check_eddsa_sign_and_verify_round_trip(&hsm);
    check_hkdf_derive(&hsm);
    check_message_based_aes_gcm_round_trip(&hsm);

    Ok(())
}
