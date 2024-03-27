use cosmian_kmip::{
    crypto::symmetric::create_symmetric_key_kmip_object, kmip::kmip_types::CryptographicAlgorithm,
};
use cosmian_kms_client::{import_object, KmsClient};
use kms_test_server::{start_default_test_kms_server, ONCE};
use native_pkcs11_traits::Backend;

use crate::{backend::CkmsBackend, error::Pkcs11Error, pkcs_11_data_object::get_pkcs11_keys_async};

#[tokio::test]
async fn test_kms_client() -> Result<(), Pkcs11Error> {
    let ctx = ONCE
        .get_or_try_init(start_default_test_kms_server)
        .await
        .unwrap();

    let kms_client = ctx.owner_client_conf.initialize_kms_client()?;
    create_keys(&kms_client).await?;

    let keys = get_pkcs11_keys_async(&kms_client, &["disk-encryption".to_string()]).await?;
    assert_eq!(keys.len(), 2);
    let mut labels = keys
        .iter()
        .map(|k| k.label.clone())
        .collect::<Vec<String>>();
    labels.sort();
    assert_eq!(labels, vec!["vol1".to_string(), "vol2".to_string()]);
    Ok(())
}

#[test]
fn test_backend() -> Result<(), Pkcs11Error> {
    cosmian_logger::log_utils::log_init("fatal,cosmian_kms_client=debug");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let owner_client_conf = rt.block_on(async {
        let ctx = ONCE
            .get_or_try_init(start_default_test_kms_server)
            .await
            .unwrap();

        let kms_client = ctx.owner_client_conf.initialize_kms_client().unwrap();
        create_keys(&kms_client).await.unwrap();
        ctx.owner_client_conf.clone()
    });

    let backend = CkmsBackend::instantiate(owner_client_conf.initialize_kms_client()?)?;
    let data_objects = backend.find_all_data_objects()?;
    assert_eq!(data_objects.len(), 2);
    let mut labels = data_objects
        .iter()
        .map(|dao| dao.label().clone())
        .collect::<Vec<String>>();
    labels.sort();
    assert_eq!(labels, vec!["vol1".to_string(), "vol2".to_string()]);
    Ok(())
}

async fn create_keys(kms_client: &KmsClient) -> Result<(), Pkcs11Error> {
    let vol1 = create_symmetric_key_kmip_object(&[1, 2, 3, 4], CryptographicAlgorithm::AES);
    let _vol1_id = import_object(
        kms_client,
        Some("vol1".to_string()),
        vol1,
        None,
        false,
        true,
        ["disk-encryption", "vol1"],
    )
    .await?;
    let vol2 = create_symmetric_key_kmip_object(&[4, 5, 6, 7], CryptographicAlgorithm::AES);
    let _vol2_id = import_object(
        kms_client,
        Some("vol2".to_string()),
        vol2,
        None,
        false,
        true,
        ["disk-encryption", "vol2"],
    )
    .await?;
    Ok(())
}
