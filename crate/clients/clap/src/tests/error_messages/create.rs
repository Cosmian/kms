// KMIP 2.1 Create Operation Compliance Tests
// Verifies that Create operation returns proper error reasons per Table 188: Create Errors

use cosmian_kmip::time_normalize;
use cosmian_kms_client::cosmian_kmip::{
    kmip_0::kmip_types::{CryptographicUsageMask, State},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, CreateResponse, Get},
        kmip_types::{CryptographicAlgorithm, ProtectionStorageMasks},
    },
};
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use crate::error::{KmsCliError, result::KmsCliResult};

/// Test 1: Successfully create a symmetric key (AES-256) in `PreActive` state
#[tokio::test]
async fn test_create_success_symmetric_key_preactive() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create a symmetric key without activation date → should be PreActive
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        ..Default::default()
    };

    let create = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    };

    let response: CreateResponse = client.create(create).await?;
    assert!(!response.unique_identifier.to_string().is_empty());
    assert_eq!(
        response.object_type,
        ObjectType::SymmetricKey,
        "Response object type should match request"
    );

    // Verify object is in PreActive state (no activation date provided)
    let get_response = client
        .get(Get {
            unique_identifier: Some(response.unique_identifier.clone()),
            ..Default::default()
        })
        .await?;

    let state = get_response
        .object
        .attributes()?
        .state
        .ok_or_else(|| KmsCliError::Default("Missing state".to_owned()))?;
    assert_eq!(
        state,
        State::PreActive,
        "Symmetric key without activation date should be PreActive"
    );

    Ok(())
}

/// Test 2: Successfully create a symmetric key in Active state (with activation date)
#[tokio::test]
async fn test_create_success_symmetric_key_active() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create a symmetric key with activation date in the past → should be Active
    let activation_date = time_normalize()? - time::Duration::hours(1);
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        // Zero milliseconds for KMIP serialization compatibility
        activation_date: Some(activation_date.replace_millisecond(0).unwrap()),
        ..Default::default()
    };

    let create = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    };

    let response: CreateResponse = client.create(create).await?;
    assert!(!response.unique_identifier.to_string().is_empty());

    // Verify object is in Active state
    let get_response = client
        .get(Get {
            unique_identifier: Some(response.unique_identifier.clone()),
            ..Default::default()
        })
        .await?;

    let state = get_response
        .object
        .attributes()?
        .state
        .ok_or_else(|| KmsCliError::Default("Missing state".to_owned()))?;
    assert_eq!(
        state,
        State::Active,
        "Symmetric key with past activation date should be Active"
    );

    Ok(())
}

/// Test 3: State determination - Create with future activation date → `PreActive`
#[tokio::test]
async fn test_create_state_determination_future_activation() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create a symmetric key with activation date in the future → should be PreActive
    let activation_date = time_normalize()? + time::Duration::days(1);
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        // Zero milliseconds for KMIP serialization compatibility
        activation_date: Some(activation_date.replace_millisecond(0).unwrap()),
        ..Default::default()
    };

    let create = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    };

    let response: CreateResponse = client.create(create).await?;
    assert!(!response.unique_identifier.to_string().is_empty());

    // Verify object is in PreActive state (future activation date)
    let get_response = client
        .get(Get {
            unique_identifier: Some(response.unique_identifier.clone()),
            ..Default::default()
        })
        .await?;

    let state = get_response
        .object
        .attributes()?
        .state
        .ok_or_else(|| KmsCliError::Default("Missing state".to_owned()))?;
    assert_eq!(
        state,
        State::PreActive,
        "Symmetric key with future activation date should be PreActive"
    );

    Ok(())
}

/// Test 4: Successfully create Secret Data object
#[tokio::test]
async fn test_create_success_secret_data() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let attributes = Attributes {
        object_type: Some(ObjectType::SecretData),
        ..Default::default()
    };

    let create = Create {
        object_type: ObjectType::SecretData,
        attributes,
        protection_storage_masks: None,
    };

    let response: CreateResponse = client.create(create).await?;
    assert!(!response.unique_identifier.to_string().is_empty());
    assert_eq!(
        response.object_type,
        ObjectType::SecretData,
        "Response object type should be SecretData"
    );

    Ok(())
}

/// Test 5: Invalid Object Type - Create operation with unsupported object type
/// Expected: Operation Failed with Invalid Object Type or Operation Not Supported
#[tokio::test]
async fn test_create_error_invalid_object_type() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Try to create a Certificate (not supported by Create operation)
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        ..Default::default()
    };

    let create = Create {
        object_type: ObjectType::Certificate, // Not supported by Create
        attributes,
        protection_storage_masks: None,
    };

    let result = client.create(create).await;
    assert!(
        result.is_err(),
        "Create should fail for unsupported object type"
    );

    let error = result.unwrap_err();
    // Use string matching as the specific object type should appear in the error
    let error_msg = error.to_string().to_lowercase();
    // Should mention "not supported" or "certificate" in error
    assert!(
        error_msg.contains("not")
            && (error_msg.contains("support") || error_msg.contains("certificate")),
        "Error should indicate unsupported object type, got: {error}"
    );

    Ok(())
}

/// Test 6: Feature Not Supported - Create with protection storage masks
/// Expected: Operation Failed with Feature Not Supported
#[tokio::test]
async fn test_create_error_feature_not_supported() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        ..Default::default()
    };

    let create = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: Some(ProtectionStorageMasks::empty()), /* Not supported - triggers error */
    };

    let result = client.create(create).await;
    assert!(
        result.is_err(),
        "Create should fail when protection_storage_masks is provided"
    );

    let error = result.unwrap_err();
    // Use string matching as the error message provides important context about the feature
    let error_msg = error.to_string().to_lowercase();
    assert!(
        error_msg.contains("not") && error_msg.contains("support"),
        "Error should indicate feature not supported, got: {error}"
    );

    Ok(())
}

/// Test 7: Invalid Attribute - Create with missing required attributes
/// Expected: Operation Failed with Invalid Attribute or similar
#[tokio::test]
async fn test_create_error_invalid_attribute() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Try to create a symmetric key with missing cryptographic_algorithm
    let attributes = Attributes {
        // Missing cryptographic_algorithm (required)
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        ..Default::default()
    };

    let create = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    };

    let result = client.create(create).await;
    assert!(
        result.is_err(),
        "Create should fail with missing required attributes"
    );

    // Error should indicate problem with attributes or algorithm
    let error = result.unwrap_err();
    // Use string matching as the specific missing field should be mentioned
    let error_msg = error.to_string().to_lowercase();
    assert!(
        error_msg.contains("algorithm")
            || error_msg.contains("attribute")
            || error_msg.contains("missing"),
        "Error should indicate invalid/missing attributes, got: {error}"
    );

    Ok(())
}
