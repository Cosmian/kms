use std::{
    mem::size_of,
    sync::atomic::{AtomicBool, Ordering},
};

use ckms::{
    config::{CKMS_CONF_ENV, ClientConfig},
    reexport::cosmian_kms_cli_actions::reexport::{
        cosmian_kmip::kmip_2_1::{
            extra::VENDOR_ID_COSMIAN,
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::{Object, PrivateKey},
            kmip_types::{CryptographicAlgorithm, KeyFormatType, RecommendedCurve},
            requests::{
                self, create_ec_key_pair_request, create_rsa_key_pair_request,
                create_symmetric_key_kmip_object, import_object_request,
            },
        },
        cosmian_kms_client::KmsClient,
    },
};
use cosmian_config_utils::ConfigUtils;
use cosmian_logger::{debug, log_init};
use cosmian_pkcs11_module::{
    pkcs11::{
        C_CloseSession, C_Decrypt, C_DecryptInit, C_Encrypt, C_EncryptInit, C_Finalize,
        C_FindObjects, C_FindObjectsFinal, C_FindObjectsInit, C_GetAttributeValue,
        C_GetMechanismInfo, C_Initialize, C_Login, C_LoginUser, C_OpenSession, C_SetAttributeValue,
        SLOT_ID,
    },
    test_decrypt, test_encrypt,
    traits::{Backend, SignatureAlgorithm, backend as registered_backend},
};
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_FUNCTION_LIST, CK_GCM_PARAMS, CK_INTERFACE, CK_INVALID_HANDLE, CK_MECHANISM,
    CK_MECHANISM_INFO, CK_OBJECT_CLASS, CK_PROFILE_ID, CK_ULONG, CK_USER_TYPE, CK_UTF8CHAR,
    CK_VERSION, CKA_CLASS, CKA_LABEL, CKA_PRIVATE, CKA_PROFILE_ID, CKA_UNIQUE_ID, CKF_DECRYPT,
    CKF_ENCRYPT, CKF_SERIAL_SESSION, CKM_AES_GCM, CKO_DATA, CKO_PROFILE, CKP_AUTHENTICATION_TOKEN,
    CKP_BASELINE_PROVIDER, CKP_EXTENDED_PROVIDER, CKP_PUBLIC_CERTIFICATES_TOKEN, CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY, CKR_BUFFER_TOO_SMALL, CKR_OK, CKR_OPERATION_NOT_INITIALIZED,
    CKR_USER_TYPE_INVALID, CKU_CONTEXT_SPECIFIC, CKU_SO, CKU_USER, CRYPTOKI_VERSION_MAJOR,
    CRYPTOKI_VERSION_MINOR,
};
use serial_test::serial;
use test_kms_server::start_default_test_kms_server;

use crate::{
    C_GetFunctionList, C_GetInterface, C_GetInterfaceList,
    backend::{COSMIAN_PKCS11_DISK_ENCRYPTION_TAG, COSMIAN_PKCS11_SSH_KEY_TAG, CliBackend},
    error::{Pkcs11Error, result::Pkcs11Result},
    kms_object::get_kms_objects_async,
};

fn save_pkcs11_client_config() -> String {
    // Start or get the shared test KMS server context
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let ctx = rt.block_on(async { start_default_test_kms_server().await });

    // Include PID to avoid cross-process file conflicts when cargo runs multiple
    // test binaries concurrently (cargo test --workspace --lib).
    let owner_file_path = std::env::temp_dir()
        .join(format!(
            "owner_{}_{}.toml",
            ctx.server_port,
            std::process::id()
        ))
        .to_string_lossy()
        .into_owned();
    if !std::path::Path::new(&owner_file_path).exists() {
        let conf = ClientConfig {
            kms_config: ctx.owner_client_config.clone(),
        };
        conf.to_toml(&owner_file_path)
            .expect("Failed to save owner test config");
    }
    owner_file_path
}

fn initialize_backend() -> Result<CliBackend, Pkcs11Error> {
    log_init(None);
    let rt = tokio::runtime::Runtime::new()?;
    let owner_client_conf = rt.block_on(async {
        let ctx = start_default_test_kms_server().await;

        let kms_rest_client = ctx.get_owner_client();
        create_keys(&kms_rest_client, COSMIAN_PKCS11_DISK_ENCRYPTION_TAG)
            .await
            .expect("failed to create keys");
        load_p12(COSMIAN_PKCS11_DISK_ENCRYPTION_TAG)
            .await
            .expect("failed to load p12");
        ctx.owner_client_config.clone()
    });

    Ok(CliBackend::instantiate(KmsClient::new_with_config(
        owner_client_conf,
    )?))
}

async fn create_keys(
    kms_rest_client: &KmsClient,
    disk_encryption_tag: &str,
) -> Result<(), Pkcs11Error> {
    // Use 16-byte AES key material to satisfy AES-CBC requirements
    let vol1 = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    debug!("vol1: {}", vol1);
    let import_object_request = import_object_request(
        VENDOR_ID_COSMIAN,
        Some("vol1".to_owned()),
        vol1,
        None,
        false,
        true,
        [disk_encryption_tag, "vol1"],
    )?;
    let _vol1_id = kms_rest_client
        .import(import_object_request)
        .await?
        .unique_identifier;

    let vol2 = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &[4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    let import_object_request_2 = requests::import_object_request(
        VENDOR_ID_COSMIAN,
        Some("vol2".to_owned()),
        vol2,
        None,
        false,
        true,
        [disk_encryption_tag, "vol2"],
    )?;
    let _vol2_id = kms_rest_client
        .import(import_object_request_2)
        .await?
        .unique_identifier;

    Ok(())
}

async fn load_p12(disk_encryption_tag: &str) -> Result<String, Pkcs11Error> {
    let ctx = start_default_test_kms_server().await;

    let p12_bytes = include_bytes!("../../../../../test_data/pkcs11/certificate.p12");

    let p12_sk = Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::PKCS12,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(zeroize::Zeroizing::new(p12_bytes.to_vec())),
                attributes: None,
            }),
            // According to the KMIP spec, the cryptographic algorithm is not required
            // as long as it can be recovered from the Key Format Type or the Key Value.
            // Also, it should not be specified if the cryptographic length is not specified.
            cryptographic_algorithm: None,
            // See comment above
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let import_object_request = import_object_request(
        VENDOR_ID_COSMIAN,
        Some("test.p12".to_owned()),
        p12_sk,
        None,
        false,
        true,
        [disk_encryption_tag, "luks_volume"],
    )?;
    let p12_id = ctx
        .get_owner_client()
        .import(import_object_request)
        .await?
        .unique_identifier;

    Ok(String::from(p12_id))
}

async fn test_kms_client() -> Result<(), Pkcs11Error> {
    let ctx = start_default_test_kms_server().await;

    let kms_rest_client = ctx.get_owner_client();
    create_keys(&kms_rest_client, COSMIAN_PKCS11_DISK_ENCRYPTION_TAG).await?;

    // Export using default per-object format, since the tag may also match non-key objects
    // (e.g. certificates) depending on other tests and server reuse.
    let objects = get_kms_objects_async(
        &kms_rest_client,
        VENDOR_ID_COSMIAN,
        &[COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_owned()],
        None,
    )
    .await?;

    // Expect two symmetric keys imported under the disk encryption tag
    assert_eq!(
        objects
            .into_iter()
            .filter(|o| matches!(o.object, Object::SymmetricKey(_)))
            .count(),
        2
    );

    Ok(())
}

#[test]
fn test_kms_client_and_backend() -> Result<(), Pkcs11Error> {
    log_init(None);

    // Must be called before the backend tests
    tokio::runtime::Runtime::new()?.block_on(async {
        test_kms_client().await.expect("failed to test kms client");
    });

    let backend = initialize_backend()?;

    // Disk-encryption symmetric keys should now appear as DataObjects (for VeraCrypt).
    let data_objects = backend.find_all_data_objects()?;
    assert!(
        data_objects.len() >= 2,
        "expected at least 2 data objects (vol1, vol2), got {}",
        data_objects.len()
    );
    let labels: Vec<String> = data_objects
        .iter()
        .map(|dao| dao.remote_id().to_owned())
        .collect();
    assert!(
        labels.contains(&"vol1".to_owned()),
        "expected 'vol1' in data object labels, got {labels:?}"
    );
    assert!(
        labels.contains(&"vol2".to_owned()),
        "expected 'vol2' in data object labels, got {labels:?}"
    );

    // RSA certificate — at least one from the P12 imported by initialize_backend();
    // other tests running against the shared server may add more.
    let certificates = backend.find_all_certificates()?;
    assert!(
        !certificates.is_empty(),
        "expected at least 1 certificate from the imported P12, got {}",
        certificates.len()
    );

    // Private key from the imported P12, plus any SSH keys added by concurrently
    // running tests that share the same test-server instance.
    let private_keys = backend.find_all_private_keys()?;
    assert!(
        !private_keys.is_empty(),
        "expected at least 1 private key from the imported P12, got {}",
        private_keys.len()
    );

    Ok(())
}

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Sentinel byte used by `test_aes_gcm_encrypt_rejects_undersized_output_buffer` to detect
/// out-of-bounds writes past a caller-declared buffer capacity.
const UNDERSIZED_BUFFER_GUARD: u8 = 0xAA;

#[test]
#[expect(unsafe_code)]
fn test_get_function_list_rejects_null_output() {
    // SAFETY: passing null intentionally verifies the required argument validation.
    assert_eq!(
        unsafe { C_GetFunctionList(std::ptr::null_mut()) },
        CKR_ARGUMENTS_BAD
    );
}

#[expect(unsafe_code)]
fn test_init() {
    // export RUST_LOG="cosmian_pkcs11=trace,ckms=trace,cosmian_config_utils=trace"
    log_init(None);

    if !INITIALIZED.load(Ordering::SeqCst) {
        let func_list = &mut CK_FUNCTION_LIST::default();
        // Update the function list with this PKCS#11 entry function
        func_list.C_GetFunctionList = Some(C_GetFunctionList);
        unsafe {
            C_GetFunctionList(&mut std::ptr::from_mut(func_list));
        }
    }
}

#[test]
#[serial]
#[expect(unsafe_code)]
fn test_generate_key_encrypt_decrypt() -> Pkcs11Result<()> {
    // Initialize the backend to create necessary keys
    let _backend = initialize_backend()?;

    // Ensure the PKCS#11 provider (which loads config via C_GetFunctionList) targets loopback
    let conf_path = save_pkcs11_client_config();
    // SAFETY: `#[serial]` ensures no other thread concurrently reads or modifies the process
    // environment, satisfying the thread-safety requirement for `set_var` (Rust 2024 edition).
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }

    test_init();
    assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        // SAFETY: `SLOT_ID` is the only valid slot; the two null/None args are optional and
        // intentionally unused; `handle` is a properly-aligned out-parameter on the stack.
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );

    // Locate the pre-imported "vol1" AES key via C_FindObjects.
    // Search by label only (no CKA_CLASS), which triggers the label-as-id path
    // in load_find_context: find_all_objects() populates OBJECTS_STORE, then
    // get_using_id("vol1") returns the handle for the key imported by initialize_backend().
    let mut label_bytes = b"vol1".to_vec();
    let label_len: CK_ULONG = label_bytes.len().try_into()?;
    #[allow(clippy::cast_ptr_alignment)]
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_LABEL,
        pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
        ulValueLen: label_len,
    }];
    let template_len: CK_ULONG = template.len().try_into()?;
    assert_eq!(
        // SAFETY: `handle` is a valid open session; `template` is a correctly-sized,
        // properly-aligned `CK_ATTRIBUTE` array with `template_len` elements, all alive
        // for the duration of the call.
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template_len) },
        CKR_OK
    );
    let mut obj_handles = [CK_INVALID_HANDLE; 4];
    let mut count: CK_ULONG = 0;
    let max_count: CK_ULONG = obj_handles.len().try_into()?;
    assert_eq!(
        // SAFETY: `handle` is a valid open session after a successful C_FindObjectsInit;
        // `obj_handles` is a buffer of `max_count` elements; `count` is a valid stack
        // out-parameter.
        unsafe { C_FindObjects(handle, obj_handles.as_mut_ptr(), max_count, &raw mut count) },
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(handle), CKR_OK);
    assert!(
        count > 0,
        "C_FindObjects should locate the pre-imported 'vol1' AES key"
    );
    let key_handle = obj_handles[0];

    // call to encrypt() test function
    let plaintext = vec![0_u8; 32];
    let encrypted_data = test_encrypt(handle, key_handle, plaintext.clone());
    // call to decrypt() test function
    let decrypted_data = test_decrypt(handle, key_handle, encrypted_data);
    assert_eq!(decrypted_data, plaintext);

    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    Ok(())
}

/// `VeraCrypt` discovers token keyfiles via `C_FindObjects` with `CKA_CLASS = CKO_DATA`.
/// This test verifies that disk-encryption symmetric keys are exposed as `CKO_DATA`
/// objects so `VeraCrypt` can list and select them.
#[test]
#[serial]
#[expect(unsafe_code)]
fn test_veracrypt_cko_data_find() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;

    let conf_path = save_pkcs11_client_config();
    // SAFETY: `#[serial]` ensures no other thread concurrently reads or modifies the process
    // environment, satisfying the thread-safety requirement for `set_var` (Rust 2024 edition).
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }

    test_init();
    assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        // SAFETY: `SLOT_ID` is the only valid slot; the two null/None args are optional and
        // intentionally unused; `handle` is a properly-aligned out-parameter on the stack.
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );

    // Search for CKO_DATA objects — this is how VeraCrypt discovers keyfiles.
    let mut class: CK_OBJECT_CLASS = CKO_DATA;
    #[allow(clippy::cast_ptr_alignment)]
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: std::ptr::from_mut(&mut class).cast::<std::ffi::c_void>(),
        ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>().try_into()?,
    }];
    let template_len: CK_ULONG = template.len().try_into()?;
    assert_eq!(
        // SAFETY: `handle` is a valid open session; `template` is a correctly-sized,
        // properly-aligned `CK_ATTRIBUTE` array with `template_len` elements, all alive
        // for the duration of the call.
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template_len) },
        CKR_OK
    );
    let mut obj_handles = [CK_INVALID_HANDLE; 16];
    let mut count: CK_ULONG = 0;
    let max_count: CK_ULONG = obj_handles.len().try_into()?;
    assert_eq!(
        // SAFETY: `handle` is a valid open session after a successful C_FindObjectsInit;
        // `obj_handles` is a buffer of `max_count` elements; `count` is a valid stack
        // out-parameter.
        unsafe { C_FindObjects(handle, obj_handles.as_mut_ptr(), max_count, &raw mut count) },
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(handle), CKR_OK);
    assert!(
        count >= 2,
        "VeraCrypt CKO_DATA search should find at least 2 disk-encryption keyfiles (vol1, \
         vol2), got {count}"
    );

    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    Ok(())
}

// ── SSH integration tests ────────────────────────────────────────────────────

async fn create_rsa_ssh_keypair(kms_rest_client: &KmsClient, bits: usize) -> (String, String) {
    let req = create_rsa_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        [COSMIAN_PKCS11_SSH_KEY_TAG],
        bits,
        false,
        None,
    )
    .expect("failed to build RSA key pair request");
    let resp = kms_rest_client
        .create_key_pair(req)
        .await
        .expect("failed to create RSA SSH key pair");
    (
        resp.private_key_unique_identifier.to_string(),
        resp.public_key_unique_identifier.to_string(),
    )
}

async fn create_ec_ssh_keypair(
    kms_rest_client: &KmsClient,
    curve: RecommendedCurve,
) -> (String, String) {
    let req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        [COSMIAN_PKCS11_SSH_KEY_TAG],
        curve,
        false,
        None,
    )
    .expect("failed to build EC key pair request");
    let resp = kms_rest_client
        .create_key_pair(req)
        .await
        .expect("failed to create EC SSH key pair");
    (
        resp.private_key_unique_identifier.to_string(),
        resp.public_key_unique_identifier.to_string(),
    )
}

/// Test that a remote RSA-PKCS1v15-SHA256 signature can be produced for an
/// `ssh-auth`-tagged RSA-2048 private key stored in the KMS.
#[test]
#[serial]
fn test_ssh_rsa_sign() -> Pkcs11Result<()> {
    log_init(None);
    let rt = tokio::runtime::Runtime::new()?;
    let (owner_client_conf, sk_id) = rt.block_on(async {
        let ctx = start_default_test_kms_server().await;
        let kms_rest_client = ctx.get_owner_client();
        let (sk_id, _pk_id) = create_rsa_ssh_keypair(&kms_rest_client, 2048).await;
        (ctx.owner_client_config.clone(), sk_id)
    });

    let backend = CliBackend::instantiate(KmsClient::new_with_config(owner_client_conf)?);
    let data = b"hello ssh world, this is a test message for RSA signing";
    let signature = backend.remote_sign(&sk_id, &SignatureAlgorithm::RsaPkcs1v15Sha256, data)?;
    assert!(
        !signature.is_empty(),
        "RSA-2048 signature must not be empty"
    );
    // RSA-2048 produces a 256-byte signature
    assert_eq!(signature.len(), 256, "RSA-2048 signature must be 256 bytes");
    Ok(())
}

/// Test that a remote ECDSA P-256 signature can be produced for an
/// `ssh-auth`-tagged EC P-256 private key stored in the KMS.
/// The data passed is a pre-computed 32-byte SHA-256 digest, matching
/// the `CKM_ECDSA` behaviour used by OpenSSH.
#[test]
#[serial]
fn test_ssh_ecdsa_p256_sign() -> Pkcs11Result<()> {
    log_init(None);
    let rt = tokio::runtime::Runtime::new()?;
    let (owner_client_conf, sk_id) = rt.block_on(async {
        let ctx = start_default_test_kms_server().await;
        let kms_rest_client = ctx.get_owner_client();
        let (sk_id, _pk_id) = create_ec_ssh_keypair(&kms_rest_client, RecommendedCurve::P256).await;
        (ctx.owner_client_config.clone(), sk_id)
    });

    let backend = CliBackend::instantiate(KmsClient::new_with_config(owner_client_conf)?);
    // Pre-computed 32-byte SHA-256 digest (CKM_ECDSA convention)
    let prehash = [0x42_u8; 32];
    let signature = backend.remote_sign(&sk_id, &SignatureAlgorithm::Ecdsa, &prehash)?;
    assert!(
        !signature.is_empty(),
        "ECDSA P-256 signature must not be empty"
    );
    Ok(())
}

/// Test that SSH-tagged keypairs are returned by the backend's key-discovery
/// methods. The test creates one RSA-2048 and one EC P-256 keypair under the
/// `ssh-auth` tag and verifies that the corresponding key IDs appear in the
/// results of `find_all_private_keys` and `find_all_public_keys`.
#[test]
#[serial]
fn test_ssh_key_discovery() -> Pkcs11Result<()> {
    log_init(None);
    let rt = tokio::runtime::Runtime::new()?;
    let (owner_client_conf, rsa_sk_id, rsa_pk_id, ec_sk_id, ec_pk_id) = rt.block_on(async {
        let ctx = start_default_test_kms_server().await;
        let kms_rest_client = ctx.get_owner_client();
        let (rsa_sk, rsa_pk) = create_rsa_ssh_keypair(&kms_rest_client, 2048).await;
        let (ec_sk, ec_pk) = create_ec_ssh_keypair(&kms_rest_client, RecommendedCurve::P256).await;
        (
            ctx.owner_client_config.clone(),
            rsa_sk,
            rsa_pk,
            ec_sk,
            ec_pk,
        )
    });

    let backend = CliBackend::instantiate(KmsClient::new_with_config(owner_client_conf)?);

    // Private key discovery
    let private_keys = backend.find_all_private_keys()?;
    let pk_ids: Vec<String> = private_keys
        .iter()
        .map(|k| k.remote_id().to_owned())
        .collect();
    assert!(
        pk_ids.contains(&rsa_sk_id),
        "RSA SSH private key {rsa_sk_id} not found in find_all_private_keys"
    );
    assert!(
        pk_ids.contains(&ec_sk_id),
        "EC SSH private key {ec_sk_id} not found in find_all_private_keys"
    );

    // Public key discovery
    let public_keys = backend.find_all_public_keys()?;
    let pub_ids: Vec<String> = public_keys
        .iter()
        .map(|k| k.remote_id().to_owned())
        .collect();
    assert!(
        pub_ids.contains(&rsa_pk_id),
        "RSA SSH public key {rsa_pk_id} not found in find_all_public_keys"
    );
    assert!(
        pub_ids.contains(&ec_pk_id),
        "EC SSH public key {ec_pk_id} not found in find_all_public_keys"
    );
    Ok(())
}

/// PKCS#11 v3.0 rollout (issue #1156): full `CKM_AES_GCM` encrypt/decrypt round trip against a
/// live KMS server, exercising the AAD threading and ciphertext||tag concatenation convention
/// implemented in `kms_object::kms_encrypt_async`/`kms_decrypt_async`.
#[test]
#[serial]
#[expect(unsafe_code, clippy::indexing_slicing)]
fn test_aes_gcm_encrypt_decrypt_roundtrip() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: `#[serial]` ensures no other thread concurrently reads or modifies the process
    // environment, satisfying the thread-safety requirement for `set_var` (Rust 2024 edition).
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }

    test_init();
    assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        // SAFETY: `SLOT_ID` is the only valid slot; the two null/None args are optional and
        // intentionally unused; `handle` is a properly-aligned out-parameter on the stack.
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );

    // Locate the pre-imported "vol1" AES key, exactly like `test_generate_key_encrypt_decrypt`.
    let mut label_bytes = b"vol1".to_vec();
    let label_len: CK_ULONG = label_bytes.len().try_into()?;
    #[allow(clippy::cast_ptr_alignment)]
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_LABEL,
        pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
        ulValueLen: label_len,
    }];
    let template_len: CK_ULONG = template.len().try_into()?;
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template_len) },
        CKR_OK
    );
    let mut obj_handles = [CK_INVALID_HANDLE; 4];
    let mut count: CK_ULONG = 0;
    let max_count: CK_ULONG = obj_handles.len().try_into()?;
    assert_eq!(
        unsafe { C_FindObjects(handle, obj_handles.as_mut_ptr(), max_count, &raw mut count) },
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(handle), CKR_OK);
    assert!(
        count > 0,
        "C_FindObjects should locate the pre-imported 'vol1' AES key"
    );
    let key_handle = obj_handles[0];

    let mut iv = [0x11_u8; 12];
    let mut aad = b"pkcs11-v3-rollout-aad".to_vec();
    let mut gcm_params = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len().try_into()?,
        ulIvBits: 0,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len().try_into()?,
        ulTagBits: 128,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: (&raw mut gcm_params).cast::<std::ffi::c_void>(),
        ulParameterLen: size_of::<CK_GCM_PARAMS>().try_into()?,
    };

    let mut plaintext = b"pkcs11-v3-rollout-aes-gcm-test-message".to_vec();
    assert_eq!(
        unsafe { C_EncryptInit(handle, &raw mut mechanism, key_handle) },
        CKR_OK
    );
    // ciphertext || 16-byte tag, per the PKCS#11 CKM_AES_GCM C_Encrypt convention.
    let mut ciphertext = vec![0_u8; plaintext.len() + 16];
    let mut ciphertext_len: CK_ULONG = ciphertext.len().try_into()?;
    assert_eq!(
        unsafe {
            C_Encrypt(
                handle,
                plaintext.as_mut_ptr(),
                plaintext.len().try_into()?,
                ciphertext.as_mut_ptr(),
                &raw mut ciphertext_len,
            )
        },
        CKR_OK
    );
    ciphertext.truncate(usize::try_from(ciphertext_len)?);
    assert_ne!(ciphertext[..ciphertext.len() - 16], plaintext[..]);

    assert_eq!(
        unsafe { C_DecryptInit(handle, &raw mut mechanism, key_handle) },
        CKR_OK
    );
    let mut decrypted = vec![0_u8; ciphertext.len()];
    let mut decrypted_len: CK_ULONG = decrypted.len().try_into()?;
    assert_eq!(
        unsafe {
            C_Decrypt(
                handle,
                ciphertext.as_mut_ptr(),
                ciphertext.len().try_into()?,
                decrypted.as_mut_ptr(),
                &raw mut decrypted_len,
            )
        },
        CKR_OK
    );
    decrypted.truncate(usize::try_from(decrypted_len)?);
    assert_eq!(decrypted, plaintext);

    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    Ok(())
}

/// Regression test for a security-review finding: `Session::encrypt` used to overwrite
/// `*pulEncryptedDataLen` with the ciphertext length *before* checking it against the caller's
/// original buffer capacity, so the too-small-buffer check always compared the freshly
/// overwritten value against itself and never actually caught anything — the caller would
/// then write `plaintext_len + 16` (AES-GCM tag) bytes into a `plaintext_len`-sized buffer,
/// silently corrupting adjacent heap memory instead of returning `CKR_BUFFER_TOO_SMALL`.
#[test]
#[serial]
#[expect(unsafe_code)]
fn test_aes_gcm_encrypt_rejects_undersized_output_buffer() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: `#[serial]` ensures no other thread concurrently reads or modifies the process
    // environment, satisfying the thread-safety requirement for `set_var` (Rust 2024 edition).
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }

    test_init();
    assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        // SAFETY: `SLOT_ID` is the only valid slot; the two null/None args are optional and
        // intentionally unused; `handle` is a properly-aligned out-parameter on the stack.
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );

    let mut label_bytes = b"vol1".to_vec();
    let label_len: CK_ULONG = label_bytes.len().try_into()?;
    #[allow(clippy::cast_ptr_alignment)]
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_LABEL,
        pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
        ulValueLen: label_len,
    }];
    let template_len: CK_ULONG = template.len().try_into()?;
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template_len) },
        CKR_OK
    );
    let mut obj_handles = [CK_INVALID_HANDLE; 4];
    let mut count: CK_ULONG = 0;
    let max_count: CK_ULONG = obj_handles.len().try_into()?;
    assert_eq!(
        unsafe { C_FindObjects(handle, obj_handles.as_mut_ptr(), max_count, &raw mut count) },
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(handle), CKR_OK);
    assert!(count > 0);
    let key_handle = obj_handles[0];

    let mut iv = [0x22_u8; 12];
    let mut aad: Vec<u8> = Vec::new();
    let mut gcm_params = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len().try_into()?,
        ulIvBits: 0,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: 0,
        ulTagBits: 128,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: (&raw mut gcm_params).cast::<std::ffi::c_void>(),
        ulParameterLen: size_of::<CK_GCM_PARAMS>().try_into()?,
    };

    let mut plaintext = b"undersized-output-buffer-regression".to_vec();
    assert_eq!(
        unsafe { C_EncryptInit(handle, &raw mut mechanism, key_handle) },
        CKR_OK
    );
    // Deliberately too small: exactly `plaintext.len()`, i.e. missing room for the 16-byte
    // AES-GCM tag that `C_Encrypt` appends. Guard bytes surround the buffer so an
    // out-of-bounds write (the pre-fix bug) would corrupt a detectable sentinel instead of
    // undefined process memory.
    let mut guarded_buffer = vec![UNDERSIZED_BUFFER_GUARD; plaintext.len() + 16];
    let undersized_len: CK_ULONG = plaintext.len().try_into()?;
    let mut ciphertext_len: CK_ULONG = undersized_len;
    let rv = unsafe {
        C_Encrypt(
            handle,
            plaintext.as_mut_ptr(),
            plaintext.len().try_into()?,
            guarded_buffer.as_mut_ptr(),
            &raw mut ciphertext_len,
        )
    };
    assert_eq!(
        rv, CKR_BUFFER_TOO_SMALL,
        "an output buffer too small to hold ciphertext+tag must be rejected, not silently \
         overflowed"
    );
    // The required length must still be reported so a retry with a correctly-sized buffer
    // can succeed, per the PKCS#11 spec's two-call convention.
    assert_eq!(usize::try_from(ciphertext_len)?, plaintext.len() + 16);
    // The guard bytes past `undersized_len` must be untouched — proves no out-of-bounds write
    // occurred.
    assert!(
        guarded_buffer
            .get(usize::try_from(undersized_len)?..)
            .expect("undersized_len is within guarded_buffer's bounds by construction")
            .iter()
            .all(|&b| b == UNDERSIZED_BUFFER_GUARD),
        "C_Encrypt must not write past the caller-declared buffer capacity on \
         CKR_BUFFER_TOO_SMALL"
    );

    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    Ok(())
}

/// Regression test for a security-review finding: `C_GetMechanismInfo` used to report
/// `CKM_AES_GCM` with the `CKF_SIGN` flag (the catch-all default for signature mechanisms)
/// instead of `CKF_ENCRYPT | CKF_DECRYPT`, which would cause PKCS#11 clients that check
/// mechanism capability flags before use to incorrectly reject AES-GCM encryption/decryption.
#[test]
#[serial]
#[expect(unsafe_code)]
fn test_get_mechanism_info_aes_gcm_reports_encrypt_decrypt() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: `#[serial]` ensures no other thread concurrently reads or modifies the process
    // environment, satisfying the thread-safety requirement for `set_var` (Rust 2024 edition).
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }
    test_init();
    assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);

    let mut info = CK_MECHANISM_INFO::default();
    assert_eq!(
        // SAFETY: `SLOT_ID` is the only valid slot; `info` is a properly-aligned out-parameter.
        unsafe { C_GetMechanismInfo(SLOT_ID, CKM_AES_GCM, &raw mut info) },
        CKR_OK
    );
    assert_eq!(
        info.flags,
        CKF_ENCRYPT | CKF_DECRYPT,
        "CKM_AES_GCM must report CKF_ENCRYPT | CKF_DECRYPT, not the CKF_SIGN default"
    );

    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    Ok(())
}

/// PKCS#11 v3.0 Interfaces API gap-fill (issue #1153 follow-up): `C_GetInterfaceList` must
/// implement the standard two-call convention and return the sole "PKCS 11" v3.0 interface;
/// `C_GetInterface` must resolve that same interface both when `pInterfaceName`/`pVersion` are
/// null (any interface/version accepted) and when they exactly match.
#[test]
#[serial]
#[expect(unsafe_code)]
fn test_get_interface_list_and_get_interface() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: `#[serial]` ensures no other thread concurrently reads or modifies the process
    // environment, satisfying the thread-safety requirement for `set_var` (Rust 2024 edition).
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }
    test_init();
    let backend_before_discovery = registered_backend()?;

    // First call: null buffer, learn the count.
    let mut count: CK_ULONG = 0;
    assert_eq!(
        // SAFETY: `pul_count` is a valid stack out-parameter; `p_interfaces_list` is
        // intentionally null (count-query call, per the two-call convention).
        unsafe { C_GetInterfaceList(std::ptr::null_mut(), &raw mut count) },
        CKR_OK
    );
    assert_eq!(count, 1, "this module exposes exactly one interface");

    // Second call: too-small buffer must report CKR_BUFFER_TOO_SMALL and the required count.
    let mut zero_count: CK_ULONG = 0;
    let mut interfaces = [CK_INTERFACE {
        pInterfaceName: std::ptr::null_mut(),
        pFunctionList: std::ptr::null_mut(),
        flags: 0,
    }; 1];
    assert_eq!(
        // SAFETY: `interfaces` is a valid 1-element buffer; `zero_count` (0) under-reports its
        // capacity on purpose to exercise the too-small path.
        unsafe { C_GetInterfaceList(interfaces.as_mut_ptr(), &raw mut zero_count) },
        CKR_BUFFER_TOO_SMALL
    );
    assert_eq!(zero_count, 1);

    // Third call: correctly sized buffer must succeed and return the "PKCS 11" interface.
    let mut full_count: CK_ULONG = 1;
    assert_eq!(
        // SAFETY: `interfaces` is a valid 1-element buffer, matching `full_count`.
        unsafe { C_GetInterfaceList(interfaces.as_mut_ptr(), &raw mut full_count) },
        CKR_OK
    );
    assert_eq!(full_count, 1);
    assert!(!interfaces[0].pInterfaceName.is_null());
    // SAFETY: `pInterfaceName` was just populated by a successful `C_GetInterfaceList` call
    // above, and is guaranteed NUL-terminated by `PKCS11_INTERFACE_NAME`.
    let name = unsafe { std::ffi::CStr::from_ptr(interfaces[0].pInterfaceName.cast()) };
    assert_eq!(name.to_bytes(), b"PKCS 11");

    // `C_GetInterface` with null name/version must resolve to the same sole interface.
    let mut interface_ptr: *mut CK_INTERFACE = std::ptr::null_mut();
    assert_eq!(
        // SAFETY: `pp_interface` is a valid stack out-parameter; name/version are
        // intentionally null (accept-any-interface call).
        unsafe {
            C_GetInterface(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut interface_ptr,
                0,
            )
        },
        CKR_OK
    );
    assert!(!interface_ptr.is_null());

    // `C_GetInterface` with a matching name and major version must also succeed.
    let mut name_bytes = b"PKCS 11\0".to_vec();
    let mut version = CK_VERSION {
        major: CRYPTOKI_VERSION_MAJOR,
        minor: CRYPTOKI_VERSION_MINOR,
    };
    assert_eq!(
        // SAFETY: `name_bytes` is NUL-terminated and well within `MAX_INTERFACE_NAME_LEN`;
        // `version` is a valid, properly-aligned `CK_VERSION` on the stack.
        unsafe {
            C_GetInterface(
                name_bytes.as_mut_ptr().cast::<CK_UTF8CHAR>(),
                &raw mut version,
                &raw mut interface_ptr,
                0,
            )
        },
        CKR_OK
    );
    let backend_after_discovery = registered_backend()?;
    assert!(
        std::sync::Arc::ptr_eq(&backend_before_discovery, &backend_after_discovery),
        "interface discovery must not replace an already authenticated backend"
    );
    Ok(())
}

/// `C_GetInterface` must reject an unknown interface name, an unsupported major version, and any
/// non-zero `flags` request (this module's sole interface makes no special guarantees).
#[test]
#[serial]
#[expect(unsafe_code)]
fn test_get_interface_rejects_mismatches() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: see other tests in this file for the `#[serial]` + `set_var` justification.
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }

    let mut interface_ptr: *mut CK_INTERFACE = std::ptr::null_mut();

    // Unknown interface name.
    let mut bad_name = b"NOT PKCS 11\0".to_vec();
    assert_eq!(
        // SAFETY: `bad_name` is NUL-terminated and within `MAX_INTERFACE_NAME_LEN`;
        // `interface_ptr` is a valid stack out-parameter.
        unsafe {
            C_GetInterface(
                bad_name.as_mut_ptr().cast::<CK_UTF8CHAR>(),
                std::ptr::null_mut(),
                &raw mut interface_ptr,
                0,
            )
        },
        CKR_ARGUMENTS_BAD
    );

    // Unsupported major version.
    let mut wrong_version = CK_VERSION { major: 1, minor: 0 };
    assert_eq!(
        // SAFETY: `wrong_version` is a valid, properly-aligned `CK_VERSION` on the stack;
        // `interface_ptr` is a valid stack out-parameter.
        unsafe {
            C_GetInterface(
                std::ptr::null_mut(),
                &raw mut wrong_version,
                &raw mut interface_ptr,
                0,
            )
        },
        CKR_ARGUMENTS_BAD
    );

    // A minor version *below* the implemented one (e.g. a v3.0 request against this v3.1
    // implementation) is backward-compatible and must be accepted, not rejected — a v3.1
    // interface is a superset of v3.0. Only a minor version *above* the implemented one is
    // truly unsupported.
    let mut compatible_minor = CK_VERSION {
        major: CRYPTOKI_VERSION_MAJOR,
        minor: 0,
    };
    assert_eq!(
        // SAFETY: `compatible_minor` and `interface_ptr` are valid stack values.
        unsafe {
            C_GetInterface(
                std::ptr::null_mut(),
                &raw mut compatible_minor,
                &raw mut interface_ptr,
                0,
            )
        },
        CKR_OK
    );
    assert!(!interface_ptr.is_null());

    let mut unsupported_minor = CK_VERSION {
        major: CRYPTOKI_VERSION_MAJOR,
        minor: CRYPTOKI_VERSION_MINOR.saturating_add(1),
    };
    assert_eq!(
        // SAFETY: `unsupported_minor` and `interface_ptr` are valid stack values.
        unsafe {
            C_GetInterface(
                std::ptr::null_mut(),
                &raw mut unsupported_minor,
                &raw mut interface_ptr,
                0,
            )
        },
        CKR_ARGUMENTS_BAD
    );

    // Non-zero flags: no interface satisfies any special guarantee.
    assert_eq!(
        // SAFETY: `interface_ptr` is a valid stack out-parameter; name/version are null.
        unsafe {
            C_GetInterface(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut interface_ptr,
                1,
            )
        },
        CKR_ARGUMENTS_BAD
    );
    Ok(())
}

/// Preserves the rollout branch's argument-validation coverage for interface discovery: a null
/// `pulCount` and a null `ppInterface` must be rejected, while an explicit v3.0 lookup by name
/// must succeed against the current v3.1 implementation.
#[test]
#[serial]
#[expect(unsafe_code)]
fn test_get_interface_validates_argument_pointers_and_accepts_v3_0() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: see other tests in this file for the `#[serial]` + `set_var` justification.
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }

    let mut interfaces = [CK_INTERFACE::default(); 1];
    assert_eq!(
        // SAFETY: a null `pul_count` is explicitly invalid, even when a buffer is supplied.
        unsafe { C_GetInterfaceList(interfaces.as_mut_ptr(), std::ptr::null_mut()) },
        CKR_ARGUMENTS_BAD
    );

    let mut interface_ptr: *mut CK_INTERFACE = std::ptr::null_mut();
    let mut name_bytes = b"PKCS 11\0".to_vec();
    let mut version = CK_VERSION { major: 3, minor: 0 };
    assert_eq!(
        // SAFETY: `name_bytes` is NUL-terminated, `version` is a valid stack object, and
        // `interface_ptr` is a valid out-parameter.
        unsafe {
            C_GetInterface(
                name_bytes.as_mut_ptr().cast::<CK_UTF8CHAR>(),
                &raw mut version,
                &raw mut interface_ptr,
                0,
            )
        },
        CKR_OK
    );
    assert!(!interface_ptr.is_null());
    // SAFETY: `interface_ptr` was returned by a successful `C_GetInterface` call above.
    assert!(!unsafe { (*interface_ptr).pFunctionList }.is_null());

    assert_eq!(
        // SAFETY: passing a null `pp_interface` is explicitly invalid.
        unsafe {
            C_GetInterface(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        },
        CKR_ARGUMENTS_BAD
    );
    Ok(())
}

/// PKCS#11 v3.1 `C_LoginUser` (issue #1153 follow-up): this module exposes a single implicit
/// backend identity per slot, so `C_LoginUser` must succeed regardless of the supplied
/// `pUsername`, exactly like `C_Login`, when the deployment does not use PIN-as-access-token
/// mode (the default in tests).
#[test]
#[serial]
#[expect(unsafe_code)]
fn test_c_login_user() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: see other tests in this file for the `#[serial]` + `set_var` justification.
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }

    test_init();
    assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        // SAFETY: `SLOT_ID` is the only valid slot; the two null/None args are optional and
        // intentionally unused; `handle` is a properly-aligned out-parameter on the stack.
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );

    assert_eq!(
        // SAFETY: all optional byte buffers are null with zero lengths; `handle` is valid.
        unsafe {
            C_LoginUser(
                handle,
                CKU_CONTEXT_SPECIFIC,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
            )
        },
        CKR_OPERATION_NOT_INITIALIZED
    );
    assert_eq!(
        // SAFETY: all optional byte buffers are null with zero lengths; `handle` is valid.
        unsafe {
            C_LoginUser(
                handle,
                CK_USER_TYPE::MAX,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
            )
        },
        CKR_USER_TYPE_INVALID
    );
    assert_eq!(
        // SAFETY: the PIN buffer is optional outside PIN-as-access-token mode.
        unsafe { C_Login(handle, CKU_CONTEXT_SPECIFIC, std::ptr::null_mut(), 0) },
        CKR_OPERATION_NOT_INITIALIZED
    );
    assert_eq!(
        // SAFETY: the PIN buffer is optional outside PIN-as-access-token mode.
        unsafe { C_Login(handle, CK_USER_TYPE::MAX, std::ptr::null_mut(), 0) },
        CKR_USER_TYPE_INVALID
    );
    assert_eq!(
        // SAFETY: the PIN buffer is optional outside PIN-as-access-token mode.
        // This module exposes a single implicit identity per slot (no separate Security
        // Officer role), so the standard `CKU_SO` user type is accepted like `CKU_USER`
        // rather than rejected -- real-world clients such as `pkcs11-tool --login-type so`
        // rely on this.
        unsafe { C_Login(handle, CKU_SO, std::ptr::null_mut(), 0) },
        CKR_OK
    );

    let mut username = b"alice".to_vec();
    let user_type: CK_USER_TYPE = CKU_USER;
    assert_eq!(
        // SAFETY: `handle` is a valid open session; `username` is a well-formed UTF-8 buffer
        // whose length is passed accurately; no PIN is required outside PIN-as-access-token mode.
        unsafe {
            C_LoginUser(
                handle,
                user_type,
                std::ptr::null_mut(),
                0,
                username.as_mut_ptr(),
                username.len().try_into()?,
            )
        },
        CKR_OK
    );

    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    Ok(())
}

/// PKCS#11 Profiles v3.1 gap-fill (issue #1153 follow-up): the module must self-declare its
/// OASIS conformance profiles via `CKO_PROFILE` objects, discoverable through `C_FindObjects`
/// with `CKA_CLASS = CKO_PROFILE` — including on a session that has not called `C_Login`
/// (`CKA_PRIVATE` must be `CK_FALSE`).
#[test]
#[serial]
#[expect(unsafe_code)]
fn test_profile_objects_self_declared() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: see other tests in this file for the `#[serial]` + `set_var` justification.
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }

    test_init();
    assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        // SAFETY: `SLOT_ID` is the only valid slot; the two null/None args are optional and
        // intentionally unused; `handle` is a properly-aligned out-parameter on the stack.
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );

    // Search for CKO_PROFILE objects (no login performed on this session).
    let mut class: CK_OBJECT_CLASS = CKO_PROFILE;
    #[allow(clippy::cast_ptr_alignment)]
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: (&raw mut class).cast::<std::ffi::c_void>(),
        ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>().try_into()?,
    }];
    let template_len: CK_ULONG = template.len().try_into()?;
    assert_eq!(
        // SAFETY: `handle` is a valid open session; `template` is a correctly-sized,
        // properly-aligned `CK_ATTRIBUTE` array with `template_len` elements, all alive
        // for the duration of the call.
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template_len) },
        CKR_OK
    );
    let mut obj_handles = [CK_INVALID_HANDLE; 8];
    let mut count: CK_ULONG = 0;
    let max_count: CK_ULONG = obj_handles.len().try_into()?;
    assert_eq!(
        // SAFETY: `handle` is a valid open session after a successful C_FindObjectsInit;
        // `obj_handles` is a buffer of `max_count` elements; `count` is a valid stack
        // out-parameter.
        unsafe { C_FindObjects(handle, obj_handles.as_mut_ptr(), max_count, &raw mut count) },
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(handle), CKR_OK);

    let count_usize = usize::try_from(count)?;
    assert!(
        count_usize >= 3,
        "expected at least Baseline/Authentication Token/Public Certificates Token profiles, \
         got {count_usize}"
    );

    // Verify each returned object really is a public (non-private), CKO_PROFILE object whose
    // CKA_PROFILE_ID is one of the profiles this module declares support for.
    let known_profiles: [CK_PROFILE_ID; 4] = [
        CKP_BASELINE_PROVIDER,
        CKP_EXTENDED_PROVIDER,
        CKP_AUTHENTICATION_TOKEN,
        CKP_PUBLIC_CERTIFICATES_TOKEN,
    ];
    let mut seen_profiles = Vec::new();
    let mut seen_unique_ids = std::collections::HashSet::new();
    for &obj_handle in obj_handles.iter().take(count_usize) {
        let mut sentinel = 0xA5_u8;
        let mut undersized = [CK_ATTRIBUTE {
            type_: CKA_UNIQUE_ID,
            pValue: (&raw mut sentinel).cast::<std::ffi::c_void>(),
            ulValueLen: 1,
        }];
        assert_eq!(
            // SAFETY: the one-byte output is valid; the call must report the required
            // size without writing beyond or modifying this undersized buffer.
            unsafe { C_GetAttributeValue(handle, obj_handle, undersized.as_mut_ptr(), 1) },
            CKR_BUFFER_TOO_SMALL
        );
        assert!(undersized[0].ulValueLen > 1);
        assert_eq!(sentinel, 0xA5);
        assert_eq!(
            // SAFETY: the template contains one valid attribute and `obj_handle` is live.
            unsafe { C_SetAttributeValue(handle, obj_handle, undersized.as_mut_ptr(), 1) },
            CKR_ATTRIBUTE_READ_ONLY
        );

        let mut class_value: CK_OBJECT_CLASS = 0;
        let mut private_value: pkcs11_sys::CK_BBOOL = 0;
        let mut profile_id_value: CK_PROFILE_ID = 0;
        let mut unique_id_value = [0_u8; 64];
        #[allow(clippy::cast_ptr_alignment)]
        let mut attr_template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: (&raw mut class_value).cast::<std::ffi::c_void>(),
                ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>().try_into()?,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE,
                pValue: (&raw mut private_value).cast::<std::ffi::c_void>(),
                ulValueLen: std::mem::size_of::<pkcs11_sys::CK_BBOOL>().try_into()?,
            },
            CK_ATTRIBUTE {
                type_: CKA_PROFILE_ID,
                pValue: (&raw mut profile_id_value).cast::<std::ffi::c_void>(),
                ulValueLen: std::mem::size_of::<CK_PROFILE_ID>().try_into()?,
            },
            CK_ATTRIBUTE {
                type_: CKA_UNIQUE_ID,
                pValue: unique_id_value.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: unique_id_value.len().try_into()?,
            },
        ];
        let attr_template_len: CK_ULONG = attr_template.len().try_into()?;
        assert_eq!(
            // SAFETY: `handle` is a valid open session; `obj_handle` was just returned by
            // `C_FindObjects` above; `attr_template` entries all point to valid, correctly-sized,
            // properly-aligned stack buffers.
            unsafe {
                C_GetAttributeValue(
                    handle,
                    obj_handle,
                    attr_template.as_mut_ptr(),
                    attr_template_len,
                )
            },
            CKR_OK
        );
        assert_eq!(class_value, CKO_PROFILE);
        assert_eq!(
            private_value, 0,
            "profile objects must be public (CKA_PRIVATE = CK_FALSE) to be discoverable \
             pre-login"
        );
        assert!(
            known_profiles.contains(&profile_id_value),
            "unexpected CKA_PROFILE_ID: {profile_id_value}"
        );
        let unique_id_len = usize::try_from(attr_template[3].ulValueLen)?;
        let unique_id_bytes = unique_id_value.get(..unique_id_len).ok_or_else(|| {
            Pkcs11Error::Conversion(format!(
                "CKA_UNIQUE_ID length {unique_id_len} exceeds the test buffer"
            ))
        })?;
        let unique_id = std::str::from_utf8(unique_id_bytes)
            .map_err(|e| Pkcs11Error::Default(e.to_string()))?;
        assert!(unique_id.starts_with("pkcs11-profile:"));
        assert!(seen_unique_ids.insert(unique_id.to_owned()));
        seen_profiles.push(profile_id_value);
    }
    assert!(seen_profiles.contains(&CKP_BASELINE_PROVIDER));
    assert!(seen_profiles.contains(&CKP_AUTHENTICATION_TOKEN));
    assert!(seen_profiles.contains(&CKP_PUBLIC_CERTIFICATES_TOKEN));

    assert_eq!(
        find_profile_count(handle, CKP_BASELINE_PROVIDER)?,
        1,
        "CKA_PROFILE_ID must select exactly one declared profile"
    );
    assert_eq!(
        find_profile_count(handle, CK_PROFILE_ID::MAX)?,
        0,
        "an unknown CKA_PROFILE_ID must select no profiles"
    );

    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    Ok(())
}

#[expect(unsafe_code)]
fn find_profile_count(
    session: pkcs11_sys::CK_SESSION_HANDLE,
    requested_profile: CK_PROFILE_ID,
) -> Pkcs11Result<CK_ULONG> {
    let mut profile = requested_profile;
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_PROFILE_ID,
        pValue: (&raw mut profile).cast::<std::ffi::c_void>(),
        ulValueLen: std::mem::size_of::<CK_PROFILE_ID>().try_into()?,
    }];
    let template_len = template.len().try_into()?;
    // SAFETY: `session` is open and the template references valid stack values.
    assert_eq!(
        unsafe { C_FindObjectsInit(session, template.as_mut_ptr(), template_len) },
        CKR_OK
    );
    let mut handles = [CK_INVALID_HANDLE; 4];
    let mut count = 0;
    let max_count = handles.len().try_into()?;
    // SAFETY: output buffers are valid for the supplied lengths.
    assert_eq!(
        unsafe { C_FindObjects(session, handles.as_mut_ptr(), max_count, &raw mut count) },
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(session), CKR_OK);
    Ok(count)
}
