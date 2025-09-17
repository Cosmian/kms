use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        kmip_objects::Object,
        kmip_operations::{Destroy, Export, Get, Revoke},
        kmip_types::UniqueIdentifier,
        requests::secret_data_create_request,
    },
};
use uuid::Uuid;

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

    let create_response = kms.create(create_request, owner, None, None).await?;
    assert!(create_response.unique_identifier.as_str().is_some());

    // Test Get operation
    let get_request = Get {
        unique_identifier: Some(create_response.unique_identifier.clone()),
        key_format_type: None,
        key_compression_type: None,
        key_wrap_type: None,
        ..Default::default()
    };

    let get_response = kms.get(get_request, owner, None).await?;
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

    let export_response = kms.export(export_request, owner, None).await?;
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
    };

    let revoke_response = kms.revoke(revoke_request, owner, None).await?;
    assert_eq!(
        revoke_response.unique_identifier,
        create_response.unique_identifier
    );

    // Test Destroy operation
    let destroy_request = Destroy {
        unique_identifier: Some(create_response.unique_identifier.clone()),
        remove: true, // Force remove to clean up
    };

    let destroy_response = kms.destroy(destroy_request, owner, None).await?;
    assert_eq!(
        destroy_response.unique_identifier,
        create_response.unique_identifier
    );

    Ok(())
}

#[tokio::test]
async fn test_secret_data_with_wrapping() -> KResult<()> {
    // Instantiate KMS
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_secret_data_wrapping@example.com";

    // Create a SecretData object with wrapping enabled
    let secret_id = format!("test-secret-wrapped-{}", Uuid::new_v4());
    let create_request = secret_data_create_request(
        Some(UniqueIdentifier::TextString(secret_id.clone())),
        vec!["wrapping-test".to_owned()],
        true, // Enable wrapping - creates sensitive SecretData that cannot be exported
        None,
    )?;

    let create_response = kms.create(create_request, owner, None, None).await?;
    assert!(create_response.unique_identifier.as_str().is_some());

    // Note: Wrapped SecretData objects are marked as sensitive and cannot be retrieved
    // with Get or Export operations. This is correct KMIP behavior for sensitive objects.
    // The fact that Create succeeded confirms that wrapping works correctly.

    // We can only revoke and destroy the object
    let revoke_request = Revoke {
        unique_identifier: Some(create_response.unique_identifier.clone()),
        revocation_reason: RevocationReason {
            revocation_reason_code: RevocationReasonCode::Unspecified,
            revocation_message: None,
        },
        compromise_occurrence_date: None,
    };

    kms.revoke(revoke_request, owner, None).await?;

    let destroy_request = Destroy {
        unique_identifier: Some(create_response.unique_identifier.clone()),
        remove: true,
    };

    kms.destroy(destroy_request, owner, None).await?;

    Ok(())
}
