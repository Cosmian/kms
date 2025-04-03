use cosmian_kms_client::{
    KmsClient, import_object,
    reexport::cosmian_kmip::kmip_2_1::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::Object,
        kmip_types::{CryptographicAlgorithm, KeyFormatType},
        requests::create_symmetric_key_kmip_object,
    },
};
use cosmian_logger::log_init;
use cosmian_pkcs11_module::traits::Backend;
use test_kms_server::start_default_test_kms_server;
use tracing::debug;

use crate::{
    backend::{COSMIAN_PKCS11_DISK_ENCRYPTION_TAG, CliBackend},
    error::Pkcs11Error,
    kms_object::get_kms_objects_async,
};

fn initialize_backend() -> Result<CliBackend, Pkcs11Error> {
    log_init(None);
    let rt = tokio::runtime::Runtime::new()?;
    let owner_client_conf = rt.block_on(async {
        let ctx = start_default_test_kms_server().await;

        let kms_rest_client = KmsClient::new_with_config(ctx.owner_client_conf.kms_config.clone())
            .expect("failed to initialize kms client");
        create_keys(&kms_rest_client, COSMIAN_PKCS11_DISK_ENCRYPTION_TAG)
            .await
            .expect("failed to create keys");
        load_p12(COSMIAN_PKCS11_DISK_ENCRYPTION_TAG)
            .await
            .expect("failed to load p12");
        ctx.owner_client_conf.clone()
    });

    Ok(CliBackend::instantiate(KmsClient::new_with_config(
        owner_client_conf.kms_config,
    )?))
}

async fn create_keys(
    kms_rest_client: &KmsClient,
    disk_encryption_tag: &str,
) -> Result<(), Pkcs11Error> {
    let vol1 = create_symmetric_key_kmip_object(&[1, 2, 3, 4], CryptographicAlgorithm::AES, false)?;
    debug!("vol1: {}", vol1);
    let _vol1_id = import_object(
        kms_rest_client,
        Some("vol1".to_owned()),
        vol1,
        None,
        false,
        true,
        [disk_encryption_tag, "vol1"],
    )
    .await?;

    let vol2 = create_symmetric_key_kmip_object(&[4, 5, 6, 7], CryptographicAlgorithm::AES, false)?;
    let _vol2_id = import_object(
        kms_rest_client,
        Some("vol2".to_owned()),
        vol2,
        None,
        false,
        true,
        [disk_encryption_tag, "vol2"],
    )
    .await?;

    Ok(())
}

async fn load_p12(disk_encryption_tag: &str) -> Result<String, Pkcs11Error> {
    let ctx = start_default_test_kms_server().await;

    let kms_rest_client = KmsClient::new_with_config(ctx.owner_client_conf.kms_config.clone())?;
    let p12_bytes = include_bytes!("../../../../test_data/pkcs11/certificate.p12");

    let p12_sk = Object::PrivateKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::PKCS12,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(zeroize::Zeroizing::new(p12_bytes.to_vec())),
                attributes: None,
            },
            // According to the KMIP spec, the cryptographic algorithm is not required
            // as long as it can be recovered from the Key Format Type or the Key Value.
            // Also, it should not be specified if the cryptographic length is not specified.
            cryptographic_algorithm: None,
            // See comment above
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    };

    let p12_id = import_object(
        &kms_rest_client,
        Some("test.p12".to_owned()),
        p12_sk,
        None,
        false,
        true,
        [disk_encryption_tag, "luks_volume"],
    )
    .await?;
    Ok(p12_id)
}

async fn test_kms_client() -> Result<(), Pkcs11Error> {
    let ctx = start_default_test_kms_server().await;

    let kms_rest_client = KmsClient::new_with_config(ctx.owner_client_conf.kms_config.clone())?;
    create_keys(&kms_rest_client, COSMIAN_PKCS11_DISK_ENCRYPTION_TAG).await?;

    let keys = get_kms_objects_async(
        &kms_rest_client,
        &[COSMIAN_PKCS11_DISK_ENCRYPTION_TAG.to_owned()],
        KeyFormatType::Raw,
    )
    .await?;
    assert_eq!(keys.len(), 2);
    let mut labels = keys
        .iter()
        .flat_map(|k| k.other_tags.clone())
        .collect::<Vec<String>>();
    labels.sort();
    assert_eq!(labels, vec!["vol1".to_owned(), "vol2".to_owned()]);

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

    //TODO fix this test
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
