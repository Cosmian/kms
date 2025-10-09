use std::sync::Arc;

use crate::tests::hsm::{export_object, import_object, revoke_key};
use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    result::KResult,
    tests::{
        hsm::{create_kek, delete_key, hsm_clap_config},
        test_utils::get_tmp_sqlite_path,
    },
};
use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_0::kmip_types::SecretDataType;
use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attributes;
use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::kmip_data_structures::{
    KeyBlock, KeyMaterial, KeyValue,
};
use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::kmip_objects::{
    Object, ObjectType, SecretData,
};
use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::kmip_types::KeyFormatType;
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier;
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) async fn test_wrapped_secret_data() -> KResult<()> {
    let kek_uuid = Uuid::new_v4();
    let owner = Uuid::new_v4().to_string();

    let sqlite_path = get_tmp_sqlite_path();

    let mut clap_config = hsm_clap_config(&owner, Some(kek_uuid))?;
    clap_config.db.sqlite_path = sqlite_path.clone();
    let Some(kek_uid) = clap_config.key_encryption_key.clone() else {
        return Err(KmsError::Default("Missing KEK".to_owned()));
    };

    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    create_kek(&kek_uid, &owner, &kms).await?;

    // create a DEK
    let secret_id = format!("test-secret-wrapped-{}", Uuid::new_v4());
    let data = b"Some_secret_data".to_vec();
    let secret_data = create_secret_data(&secret_id, data.clone());
    let imported_uid = import_object(
        &kms,
        &owner,
        &secret_id,
        &secret_data,
        ObjectType::SecretData,
    )
    .await?;
    assert_eq!(
        imported_uid,
        UniqueIdentifier::TextString(secret_id.clone())
    );
    let exported = export_object(&kms, &owner, &secret_id).await?;
    assert_eq!(exported.object_type(), secret_data.object_type());

    // stop the kms
    drop(kms);
    // re-instantiate the kms
    let mut clap_config = hsm_clap_config(&owner, Some(kek_uuid))?;
    clap_config.db.sqlite_path = sqlite_path.clone();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    let exported = export_object(&kms, &owner, &secret_id).await?;
    assert_eq!(exported.object_type(), secret_data.object_type());
    assert!(exported.is_wrapped());

    // stop the kms
    drop(kms);
    // re-instantiate the kms
    let mut clap_config = hsm_clap_config(&owner, Some(kek_uuid))?;
    clap_config.db.sqlite_path = sqlite_path.clone();
    clap_config.default_unwrap_type = Some(["SecretData".to_owned()].to_vec());
    let Some(kek_uid) = clap_config.key_encryption_key.clone() else {
        return Err(KmsError::Default("Missing KEK".to_owned()));
    };
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    let exported = export_object(&kms, &owner, &secret_id).await?;
    assert_eq!(exported.object_type(), secret_data.object_type());
    assert!(!exported.is_wrapped());
    assert_eq!(
        exported
            .key_block()?
            .key_value
            .clone()
            .unwrap()
            .raw_bytes()?
            .to_vec(),
        data
    );

    // Revoke and destroy all
    revoke_key(secret_id.as_str(), &owner, &kms).await?;
    delete_key(secret_id.as_str(), &owner, &kms).await?;
    delete_key(&kek_uid, &owner, &kms).await?;

    Ok(())
}

fn create_secret_data(secret_id: &str, data: Vec<u8>) -> Object {
    // create the data encryption key

    Object::SecretData(SecretData {
        secret_data_type: SecretDataType::Password,
        key_block: KeyBlock {
            key_format_type: KeyFormatType::Opaque,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::from(data)),
                attributes: Some(Attributes {
                    object_type: Some(ObjectType::SecretData),
                    unique_identifier: Some(UniqueIdentifier::TextString(secret_id.to_owned())),
                    ..Default::default()
                }),
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    })
}
