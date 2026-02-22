use std::sync::atomic::{AtomicBool, Ordering};

use ckms::{
    config::{CKMS_CONF_ENV, ClientConfig},
    reexport::cosmian_kms_cli::reexport::{
        cosmian_kmip::kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::{Object, PrivateKey},
            kmip_types::{CryptographicAlgorithm, KeyFormatType},
            requests::{self, create_symmetric_key_kmip_object, import_object_request},
        },
        cosmian_kms_client::KmsClient,
    },
};
use cosmian_config_utils::ConfigUtils;
use cosmian_logger::{debug, log_init};
use cosmian_pkcs11_module::{
    pkcs11::{
        C_CloseSession, C_Finalize, C_FindObjects, C_FindObjectsFinal, C_FindObjectsInit,
        C_Initialize, C_OpenSession, SLOT_ID,
    },
    test_decrypt, test_encrypt,
    traits::Backend,
};
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_FUNCTION_LIST, CK_INVALID_HANDLE, CK_OBJECT_CLASS, CK_ULONG, CKA_LABEL,
    CKF_SERIAL_SESSION, CKO_SECRET_KEY, CKR_OK,
};
use serial_test::serial;
use test_kms_server::start_default_test_kms_server;

use crate::{
    C_GetFunctionList,
    backend::{COSMIAN_PKCS11_DISK_ENCRYPTION_TAG, CliBackend},
    error::{Pkcs11Error, result::Pkcs11Result},
    kms_object::get_kms_objects_async,
};

fn save_pkcs11_client_config() -> String {
    // Start or get the shared test KMS server context
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let ctx = rt.block_on(async { start_default_test_kms_server().await });

    // Persist a client config that points explicitly to loopback to avoid 0.0.0.0 on Windows
    let owner_file_path = std::env::temp_dir()
        .join(format!("owner_{}.toml", ctx.server_port))
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
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    debug!("vol1: {}", vol1);
    let import_object_request = import_object_request(
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
        &[4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    let import_object_request_2 = requests::import_object_request(
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

    // RSA certificate
    let certificates = backend.find_all_certificates()?;
    assert_eq!(certificates.len(), 1);
    // assert_eq!(certificates[0].label(), "luks_volume");

    // RSA private key
    let private_keys = backend.find_all_private_keys()?;
    assert_eq!(private_keys.len(), 1);

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

    // Locate the previously imported symmetric key labeled "vol1"
    let mut label_bytes = b"vol1".to_vec();
    let label_len: CK_ULONG = label_bytes.len().try_into()?;
    let mut class_value: CK_OBJECT_CLASS = CKO_SECRET_KEY;
    let class_size: CK_ULONG = std::mem::size_of::<CK_OBJECT_CLASS>().try_into()?;
    let mut template = vec![
        CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
            ulValueLen: label_len,
        },
        CK_ATTRIBUTE {
            type_: pkcs11_sys::CKA_CLASS,
            pValue: std::ptr::from_mut(&mut class_value).cast::<std::ffi::c_void>(),
            ulValueLen: class_size,
        },
    ];

    let template_len: CK_ULONG = template.len().try_into()?;
    unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template_len) };
    let mut obj_handles = [pkcs11_sys::CK_OBJECT_HANDLE::default(); 4];
    let mut count: CK_ULONG = 0;
    let obj_handles_len: CK_ULONG = obj_handles.len().try_into()?;
    unsafe {
        C_FindObjects(
            handle,
            obj_handles.as_mut_ptr(),
            obj_handles_len,
            &raw mut count,
        )
    };
    C_FindObjectsFinal(handle);
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
