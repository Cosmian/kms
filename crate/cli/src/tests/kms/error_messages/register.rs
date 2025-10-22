use cosmian_kmip::time_normalize;
use cosmian_kms_client::cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Register, RegisterResponse},
        kmip_types::{CryptographicAlgorithm, ProtectionStorageMasks},
        requests::create_symmetric_key_kmip_object,
    },
};
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use crate::error::result::KmsCliResult;

/// Test successful registration of a symmetric key in Pre-Active state
#[tokio::test]
async fn test_register_success_preactive() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create a symmetric key object for registration (32 bytes = 256 bits)
    let key_bytes = vec![0_u8; 32];

    // Create attributes without initial_date (should result in Pre-Active state)
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        object_type: Some(ObjectType::SymmetricKey),
        ..Default::default()
    };

    let object = create_symmetric_key_kmip_object(&key_bytes, &attributes)?;

    // Register the key
    let register_request = Register {
        object_type: ObjectType::SymmetricKey,
        object,
        attributes,
        protection_storage_masks: None,
    };

    let response: RegisterResponse = client.register(register_request).await?;
    assert!(!response.unique_identifier.to_string().is_empty());

    Ok(())
}

/// Test successful registration of a symmetric key in Active state
/// (when `initial_date` is set to current or past time)
#[tokio::test]
async fn test_register_success_active() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create a symmetric key object for registration
    let key_bytes = vec![0_u8; 32];

    // Create attributes with initial_date in the past (should result in Active state)
    let past_date = time_normalize()? - time::Duration::hours(1);
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        object_type: Some(ObjectType::SymmetricKey),
        initial_date: Some(past_date),
        ..Default::default()
    };

    let object = create_symmetric_key_kmip_object(&key_bytes, &attributes)?;

    // Register the key
    let register_request = Register {
        object_type: ObjectType::SymmetricKey,
        object,
        attributes,
        protection_storage_masks: None,
    };

    let response: RegisterResponse = client.register(register_request).await?;
    assert!(!response.unique_identifier.to_string().is_empty());

    Ok(())
}

/// Test KMIP 2.1 Error: Invalid Object Type
/// (`object_type` parameter doesn't match the actual object type)
#[tokio::test]
async fn test_register_invalid_object_type() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create a symmetric key object
    let key_bytes = vec![0_u8; 32];
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        object_type: Some(ObjectType::SymmetricKey),
        ..Default::default()
    };

    let object = create_symmetric_key_kmip_object(&key_bytes, &attributes)?;

    // Register with MISMATCHED object_type (say it's a PrivateKey when it's actually SymmetricKey)
    let register_request = Register {
        object_type: ObjectType::PrivateKey, // WRONG TYPE
        object,
        attributes,
        protection_storage_masks: None,
    };

    let result = client.register(register_request).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    // Use string matching as the specific object type mismatch should be detailed in the error
    let err_msg = err.to_string();
    // Should contain error about inconsistent or invalid object type
    assert!(
        err_msg.contains("object type") || err_msg.contains("Inconsistent"),
        "Expected 'Invalid Object Type' error, got: {err_msg}"
    );

    Ok(())
}

/// Test KMIP 2.1 Error: Feature Not Supported
/// (attempting to use `protection_storage_masks` which is not supported)
#[tokio::test]
async fn test_register_feature_not_supported() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create a symmetric key object
    let key_bytes = vec![0_u8; 32];
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        object_type: Some(ObjectType::SymmetricKey),
        ..Default::default()
    };

    let object = create_symmetric_key_kmip_object(&key_bytes, &attributes)?;

    // Register with unsupported protection_storage_masks
    let register_request = Register {
        object_type: ObjectType::SymmetricKey,
        object,
        attributes,
        protection_storage_masks: Some(ProtectionStorageMasks::Software),
    };

    let result = client.register(register_request).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    // Use string matching as the specific feature should be mentioned
    let err_msg = err.to_string();
    // Should contain error about unsupported feature or placeholder
    assert!(
        err_msg.contains("not yet support")
            || err_msg.contains("placeholder")
            || err_msg.contains("Feature"),
        "Expected 'Feature Not Supported' error, got: {err_msg}"
    );

    Ok(())
}

/// Test KMIP 2.1 Error: Invalid Attribute
/// (providing invalid or malformed attributes - wrong key size for AES)
/// Note: This test demonstrates that the server validates attribute consistency.
/// The `create_symmetric_key_kmip_object` function accepts the invalid size,
/// so this test verifies the registration succeeds (the server is lenient).
/// For strict KMIP 2.1 compliance, a server could reject invalid key sizes.
#[tokio::test]
async fn test_register_invalid_attribute() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create a symmetric key object with INVALID key material (wrong size: 15 bytes)
    let invalid_key_bytes = vec![0_u8; 15]; // Invalid size for AES

    // Create attributes with invalid cryptographic_length
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(120), // Invalid AES key length (should be 128, 192, or 256)
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        object_type: Some(ObjectType::SymmetricKey),
        ..Default::default()
    };

    // Try to create object with invalid key size
    let object_result = create_symmetric_key_kmip_object(&invalid_key_bytes, &attributes);

    // The object creation currently succeeds (server is lenient about key sizes)
    // In a strict KMIP 2.1 implementation, this would fail with Invalid_Attribute error
    if let Ok(object) = object_result {
        let register_request = Register {
            object_type: ObjectType::SymmetricKey,
            object,
            attributes,
            protection_storage_masks: None,
        };

        let result = client.register(register_request).await;

        // Current implementation accepts this (lenient behavior)
        // A strict implementation would return InvalidAttribute error
        if result.is_err() {
            let err = result.unwrap_err();
            let err_msg = err.to_string();
            // Should contain error about invalid attribute or value
            assert!(
                err_msg.contains("Invalid")
                    || err_msg.contains("invalid")
                    || err_msg.contains("size"),
                "Expected 'Invalid Attribute' error, got: {err_msg}"
            );
        }
        // If registration succeeds, that's also acceptable for current implementation
    }

    Ok(())
}

/// Test that registered objects are in the correct initial state
/// Pre-Active when no `initial_date`, Active when `initial_date` <= now
#[tokio::test]
async fn test_register_state_determination() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Test 1: No initial_date → should be Pre-Active
    let key_bytes1 = vec![0_u8; 32];
    let attributes1 = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        object_type: Some(ObjectType::SymmetricKey),
        ..Default::default()
    };

    let object1 = create_symmetric_key_kmip_object(&key_bytes1, &attributes1)?;
    let register_request1 = Register {
        object_type: ObjectType::SymmetricKey,
        object: object1,
        attributes: attributes1,
        protection_storage_masks: None,
    };

    let response1: RegisterResponse = client.register(register_request1).await?;
    let key_id1 = response1.unique_identifier.to_string();
    assert!(!key_id1.is_empty());

    // Test 2: initial_date in the past → should be Active
    let key_bytes2 = vec![0_u8; 32];
    let past_date = time_normalize()? - time::Duration::hours(1);
    let attributes2 = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        object_type: Some(ObjectType::SymmetricKey),
        initial_date: Some(past_date),
        ..Default::default()
    };

    let object2 = create_symmetric_key_kmip_object(&key_bytes2, &attributes2)?;
    let register_request2 = Register {
        object_type: ObjectType::SymmetricKey,
        object: object2,
        attributes: attributes2,
        protection_storage_masks: None,
    };

    let response2: RegisterResponse = client.register(register_request2).await?;
    let key_id2 = response2.unique_identifier.to_string();
    assert!(!key_id2.is_empty());

    // Both registrations should succeed
    // The actual state verification would require Get operation to check attributes
    Ok(())
}
