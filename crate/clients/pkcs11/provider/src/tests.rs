use std::sync::atomic::{AtomicBool, Ordering};

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
use cosmian_kms_logger::{debug, log_init};
use cosmian_pkcs11_module::{
    pkcs11::{
        C_CloseSession, C_Finalize, C_FindObjects, C_FindObjectsFinal, C_FindObjectsInit,
        C_Initialize, C_OpenSession, SLOT_ID,
    },
    test_decrypt, test_encrypt,
    traits::{Backend, SignatureAlgorithm},
};
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_FUNCTION_LIST, CK_INVALID_HANDLE, CK_ULONG, CKA_LABEL, CKF_SERIAL_SESSION,
    CKR_OK,
};
use serial_test::serial;
use test_kms_server::start_default_test_kms_server;

use crate::{
    C_GetFunctionList,
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

    // TODO fix this test
    // // data objects
    // let data_objects = backend.find_all_data_objects()?;
    // assert_eq!(data_objects.len(), 2);
    // let mut labels = data_objects
    //     .iter()
    //     .map(|dao| dao.label())
    //     .collect::<Vec<String>>();
    // labels.sort();
    // assert_eq!(labels, vec!["vol1".to_owned(), "vol2".to_owned()]);

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
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }

    test_init();
    assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
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
