#![allow(clippy::unwrap_in_result)]

use std::sync::Arc;

use cosmian_kms_client_utils::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{KeyWrapType, SecretDataType},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::SecretData,
        kmip_operations::Import,
        kmip_types::{
            CryptographicAlgorithm, EncodingOption, EncryptionKeyInformation, KeyFormatType,
        },
    },
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        extra::tagging::EMPTY_TAGS,
        kmip_data_structures::KeyWrappingSpecification,
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Destroy, Export, Get, Revoke},
        kmip_types::{UniqueIdentifier, WrappingMethod},
        requests::{secret_data_create_request, symmetric_key_create_request},
    },
};
use cosmian_logger::log_init;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    config::ServerParams, core::KMS, result::KResult, tests::test_utils::https_clap_config,
};

#[tokio::test]
async fn test_secret_data_create_basic() -> KResult<()> {
    // Instantiate KMS
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_secret_data_create_basic@example.com";

    // Create a basic secret data object using the existing request function
    let secret_id = format!("test-secret-{}", Uuid::new_v4());
    let create_request = secret_data_create_request(
        Some(UniqueIdentifier::TextString(secret_id.clone())),
        vec!["basic-test".to_owned()],
        false,
        None,
    )?;

    let create_response = kms.create(create_request, owner, None).await?;
    assert!(create_response.unique_identifier.as_str().is_some());

    // Test Get operation
    let get_request = Get {
        unique_identifier: Some(create_response.unique_identifier.clone()),
        key_format_type: None,
        key_compression_type: None,
        key_wrap_type: None,
        ..Default::default()
    };

    let get_response = kms.get(get_request, owner).await?;
    assert_eq!(
        get_response.unique_identifier,
        create_response.unique_identifier
    );
    assert!(matches!(get_response.object, Object::SecretData(_)));

    // Test Export operation
    let export_request = Export {
        unique_identifier: Some(create_response.unique_identifier.clone()),
        key_format_type: None,
        key_compression_type: None,
        key_wrap_type: None,
        key_wrapping_specification: None,
    };

    let export_response = kms.export(export_request, owner).await?;
    assert_eq!(
        export_response.unique_identifier,
        create_response.unique_identifier
    );
    assert!(matches!(export_response.object, Object::SecretData(_)));

    // Test Revoke operation (required before destroy)
    let revoke_request = Revoke {
        unique_identifier: Some(create_response.unique_identifier.clone()),
        revocation_reason: RevocationReason {
            revocation_reason_code: RevocationReasonCode::Unspecified,
            revocation_message: None,
        },
        compromise_occurrence_date: None,
        cascade: true,
    };

    let revoke_response = kms.revoke(revoke_request, owner).await?;
    assert_eq!(
        revoke_response.unique_identifier,
        create_response.unique_identifier
    );

    // Test Destroy operation
    let destroy_request = Destroy {
        unique_identifier: Some(create_response.unique_identifier.clone()),
        remove: true, // Force remove to clean up
        cascade: true,
    };

    let destroy_response = kms.destroy(destroy_request, owner).await?;
    assert_eq!(
        destroy_response.unique_identifier,
        create_response.unique_identifier
    );

    Ok(())
}

#[tokio::test]
async fn test_secret_data_with_wrapping() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    // Instantiate KMS
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_secret_data_wrapping@example.com";

    // Create a SecretData object with wrapping enabled
    let secret_id = UniqueIdentifier::TextString(format!("test-secret-wrapped-{}", Uuid::new_v4()));
    let create_request = secret_data_create_request(
        Some(secret_id.clone()),
        vec!["wrapping-test".to_owned()],
        false,
        None,
    )?;

    let create_response = kms.create(create_request, owner, None).await?;
    assert!(create_response.unique_identifier.as_str().is_some());

    // create the wrapping key
    let create_wrapping_key_request = symmetric_key_create_request(
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let create_wrapping_key_response = kms.create(create_wrapping_key_request, owner, None).await?;
    assert!(
        create_wrapping_key_response
            .unique_identifier
            .as_str()
            .is_some()
    );
    let wrapping_key_id = create_wrapping_key_response.unique_identifier;

    // Test Export operation with wrapping enabled
    let export_request = Export::new(
        secret_id.clone(),
        false,
        Some(KeyWrappingSpecification {
            wrapping_method: WrappingMethod::Encrypt,
            encryption_key_information: Some(EncryptionKeyInformation {
                unique_identifier: wrapping_key_id.clone(),
                cryptographic_parameters: None,
            }),
            attribute_name: None,
            encoding_option: Some(EncodingOption::NoEncoding),
            ..KeyWrappingSpecification::default()
        }),
        None,
    );

    let export_response = kms.export(export_request, owner).await?;
    assert_ne!(export_response.unique_identifier, wrapping_key_id);
    assert_eq!(export_response.unique_identifier, secret_id.clone());
    assert!(matches!(export_response.object, Object::SecretData(_)));
    assert!(export_response.object.is_wrapped());

    let revoke_request = Revoke {
        unique_identifier: Some(secret_id.clone()),
        revocation_reason: RevocationReason {
            revocation_reason_code: RevocationReasonCode::Unspecified,
            revocation_message: None,
        },
        compromise_occurrence_date: None,
        cascade: true,
    };

    kms.revoke(revoke_request, owner).await?;

    let destroy_request = Destroy {
        unique_identifier: Some(secret_id.clone()),
        remove: true,
        cascade: true,
    };

    kms.destroy(destroy_request, owner).await?;

    Ok(())
}

#[tokio::test]
async fn test_secret_data_import_export_with_kek() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    // Instantiate KMS
    let clap_config = https_clap_config();
    let sqlite_path = clap_config.db.sqlite_path.clone();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let key_material = Zeroizing::from(b"TestData".to_vec());
    let owner = "test_secret_data_wrapping@example.com";

    // create the wrapping key
    let create_wrapping_key_request = symmetric_key_create_request(
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let create_wrapping_key_response = kms.create(create_wrapping_key_request, owner, None).await?;
    assert!(
        create_wrapping_key_response
            .unique_identifier
            .as_str()
            .is_some()
    );
    let wrapping_key_id = create_wrapping_key_response.unique_identifier;
    drop(kms);
    let mut clap_config_kek = https_clap_config();
    clap_config_kek.db.sqlite_path = sqlite_path.clone();
    clap_config_kek.key_encryption_key = Some(wrapping_key_id.to_string());
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config_kek)?)).await?);

    let secret_id = UniqueIdentifier::TextString(format!("test-secret-wrapped-{}", Uuid::new_v4()));
    let secret_data = Object::SecretData(SecretData {
        secret_data_type: SecretDataType::Password,
        key_block: KeyBlock {
            key_format_type: KeyFormatType::Opaque,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(key_material.clone()),
                attributes: Some(Attributes {
                    object_type: Some(ObjectType::SecretData),
                    unique_identifier: Some(secret_id.clone()),
                    ..Default::default()
                }),
            }),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        },
    });

    let import_request = Import {
        unique_identifier: secret_id.clone(),
        object_type: ObjectType::SecretData,
        attributes: Attributes {
            object_type: Some(ObjectType::SecretData),
            ..Default::default()
        },
        replace_existing: None,
        key_wrap_type: None,
        object: secret_data,
    };

    let import_response = kms.import(import_request, owner, None).await?;
    assert_eq!(import_response.unique_identifier, secret_id);

    // Test Export operation with wrapping enabled
    let export_request = Export {
        unique_identifier: Some(secret_id.clone()),
        key_format_type: None,
        key_compression_type: None,
        key_wrap_type: None,
        key_wrapping_specification: None,
    };

    let export_response = kms.export(export_request, owner).await?;
    assert_eq!(
        export_response.unique_identifier,
        import_response.unique_identifier
    );
    assert!(matches!(export_response.object, Object::SecretData(_)));
    assert!(export_response.object.is_wrapped());

    // Test Export operation without wrapping
    let export_request_unwrap = Export {
        unique_identifier: Some(secret_id.clone()),
        key_format_type: None,
        key_compression_type: None,
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        key_wrapping_specification: None,
    };

    let export_response_unwrap = kms.export(export_request_unwrap, owner).await?;
    assert_eq!(
        export_response_unwrap.unique_identifier,
        import_response.unique_identifier
    );
    assert!(matches!(
        export_response_unwrap.object,
        Object::SecretData(_)
    ));
    assert!(!export_response_unwrap.object.is_wrapped());
    assert_eq!(
        export_response_unwrap
            .object
            .key_block()?
            .key_value
            .clone()
            .unwrap()
            .raw_bytes()?
            .to_vec(),
        key_material.to_vec()
    );

    drop(kms);
    let mut clap_config_unwrap = https_clap_config();
    clap_config_unwrap.db.sqlite_path = sqlite_path;
    clap_config_unwrap.key_encryption_key = Some(wrapping_key_id.to_string());
    clap_config_unwrap.default_unwrap_type = Some(["SecretData".to_owned()].to_vec());
    let kms =
        Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config_unwrap)?)).await?);

    // Test Export operation with default unwrapping
    let export_request_default_unwrap = Export {
        unique_identifier: Some(secret_id.clone()),
        key_format_type: None,
        key_compression_type: None,
        key_wrap_type: None,
        key_wrapping_specification: None,
    };

    let export_response_default_unwrap = kms.export(export_request_default_unwrap, owner).await?;
    assert!(matches!(
        export_response_default_unwrap.object,
        Object::SecretData(_)
    ));
    assert!(!export_response_default_unwrap.object.is_wrapped());
    assert_eq!(
        export_response_default_unwrap
            .object
            .key_block()?
            .key_value
            .clone()
            .unwrap()
            .raw_bytes()?
            .to_vec(),
        key_material.to_vec()
    );

    let revoke_request = Revoke {
        unique_identifier: Some(secret_id.clone()),
        revocation_reason: RevocationReason {
            revocation_reason_code: RevocationReasonCode::Unspecified,
            revocation_message: None,
        },
        compromise_occurrence_date: None,
        cascade: true,
    };

    kms.revoke(revoke_request, owner).await?;

    let destroy_request = Destroy {
        unique_identifier: Some(secret_id.clone()),
        remove: true,
        cascade: true,
    };

    kms.destroy(destroy_request, owner).await?;

    Ok(())
}
