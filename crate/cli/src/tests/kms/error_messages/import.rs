// KMIP 2.1 Import Operation Compliance Tests
// Verifies that Import operation returns proper error reasons per Table 240: Import Errors

use cosmian_kms_client::cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyValue},
        kmip_objects::{Object, ObjectType, SplitKey},
        kmip_operations::{Get, Import, ImportResponse},
        kmip_types::{CryptographicAlgorithm, KeyFormatType, SplitKeyMethod, UniqueIdentifier},
        requests::create_symmetric_key_kmip_object,
    },
};
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;
use zeroize::Zeroizing;

use crate::error::result::KmsCliResult;

/// Test 1: Successfully import a symmetric key
#[tokio::test]
async fn test_import_success_symmetric_key() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create a symmetric key object for import (32 bytes = 256 bits)
    let key_bytes = vec![0xAA; 32];

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

    // Import the key
    let import_request = Import {
        unique_identifier: UniqueIdentifier::default(), // Server will generate
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes: attributes.clone(),
        object,
    };

    let response: ImportResponse = client.import(import_request).await?;
    assert!(!response.unique_identifier.to_string().is_empty());

    // Verify the imported object
    let get_response = client
        .get(Get {
            unique_identifier: Some(response.unique_identifier.clone()),
            ..Default::default()
        })
        .await?;

    assert_eq!(
        get_response.object_type,
        ObjectType::SymmetricKey,
        "Retrieved object should be SymmetricKey"
    );

    Ok(())
}

/// Test 2: Object Already Exists - Import with same UID without `replace_existing`
/// Expected: Operation Failed with Object Already Exists error
#[tokio::test]
async fn test_import_error_object_already_exists() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let key_bytes = vec![0xBB; 32];
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        object_type: Some(ObjectType::SymmetricKey),
        ..Default::default()
    };

    let object1 = create_symmetric_key_kmip_object(&key_bytes, &attributes)?;

    // First import with a specific UID
    let import_request1 = Import {
        unique_identifier: "test-duplicate-uid-12345".into(),
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes: attributes.clone(),
        object: object1,
    };

    let response1: ImportResponse = client.import(import_request1).await?;
    assert_eq!(
        response1.unique_identifier.to_string(),
        "test-duplicate-uid-12345"
    );

    // Try to import again with the same UID and replace_existing = false
    let object2 = create_symmetric_key_kmip_object(&key_bytes, &attributes)?;
    let import_request2 = Import {
        unique_identifier: "test-duplicate-uid-12345".into(),
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(false), // Should fail
        key_wrap_type: None,
        attributes: attributes.clone(),
        object: object2,
    };

    let result = client.import(import_request2).await;
    assert!(
        result.is_err(),
        "Import should fail when object already exists and replace_existing is false"
    );

    let error = result.unwrap_err();
    // Check for Object_Already_Exists error - the database returns UNIQUE constraint error
    let err_msg = error.to_string();
    assert!(
        err_msg.contains("Object_Already_Exists")
            || err_msg.contains("one or more objects already exist"),
        "Expected Object_Already_Exists or 'one or more objects already exist' error, got: {error}"
    );

    Ok(())
}

/// Test 3: Successfully replace existing object with `replace_existing` = true
#[tokio::test]
async fn test_import_success_replace_existing() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let key_bytes1 = vec![0xCC; 32];
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        object_type: Some(ObjectType::SymmetricKey),
        ..Default::default()
    };

    // First import
    let object1 = create_symmetric_key_kmip_object(&key_bytes1, &attributes)?;
    let import_request1 = Import {
        unique_identifier: "test-replace-uid-67890".into(),
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes: attributes.clone(),
        object: object1,
    };

    let _response1: ImportResponse = client.import(import_request1).await?;

    // Replace with different key material
    let key_bytes2 = vec![0xDD; 32];
    let object2 = create_symmetric_key_kmip_object(&key_bytes2, &attributes)?;
    let import_request2 = Import {
        unique_identifier: "test-replace-uid-67890".into(),
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(true), // Should succeed
        key_wrap_type: None,
        attributes: attributes.clone(),
        object: object2,
    };

    let response2: ImportResponse = client.import(import_request2).await?;
    assert_eq!(
        response2.unique_identifier.to_string(),
        "test-replace-uid-67890"
    );

    Ok(())
}

/// Test 4: Operation Not Supported - Import unsupported object type
/// Expected: Operation Failed with Operation Not Supported
#[tokio::test]
async fn test_import_error_unsupported_object_type() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create a SplitKey object (which is not supported by the import operation)
    let key_bytes = vec![0xEE; 32];

    let key_block = KeyBlock {
        key_format_type: KeyFormatType::Raw,
        key_compression_type: None,
        key_value: Some(KeyValue::ByteString(Zeroizing::new(key_bytes.clone()))),
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        key_wrapping_data: None,
    };

    let split_key = SplitKey {
        split_key_parts: 3,
        key_part_identifier: 1,
        split_key_threshold: 2,
        split_key_method: SplitKeyMethod::XOR,
        prime_field_size: None,
        key_block,
    };

    let object = Object::SplitKey(split_key);

    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        object_type: Some(ObjectType::SplitKey),
        ..Default::default()
    };

    let import_request = Import {
        unique_identifier: UniqueIdentifier::default(),
        object_type: ObjectType::SplitKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes,
        object,
    };

    let result = client.import(import_request).await;
    assert!(
        result.is_err(),
        "Import should fail for unsupported object type"
    );

    let error = result.unwrap_err();
    // Use string matching as the specific object type should be mentioned
    let error_msg = error.to_string().to_lowercase();
    assert!(
        error_msg.contains("not") && (error_msg.contains("support") || error_msg.contains("split")),
        "Error should indicate unsupported operation, got: {error}"
    );

    Ok(())
}

/// Test 5: Invalid Field - Import with reserved UID starting with '['
/// Expected: Operation Failed with Invalid Field
#[tokio::test]
async fn test_import_error_invalid_uid_reserved() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let key_bytes = vec![0xFF; 32];
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

    // Try to import with reserved UID starting with '['
    let import_request = Import {
        unique_identifier: "[tag1]".into(), // Reserved for tag queries
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes,
        object,
    };

    let result = client.import(import_request).await;
    assert!(
        result.is_err(),
        "Import should fail for reserved UID pattern"
    );

    let error = result.unwrap_err();
    // Use string matching as the specific invalid character should be mentioned
    let error_msg = error.to_string().to_lowercase();
    assert!(
        error_msg.contains("not supported") || error_msg.contains('['),
        "Error should indicate invalid UID pattern, got: {error}"
    );

    Ok(())
}

/// Test 6: Verify `InitialDate` is set on imported objects
#[tokio::test]
async fn test_import_sets_initial_date() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let key_bytes = vec![0x11; 32];
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        object_type: Some(ObjectType::SymmetricKey),
        // No initial_date specified
        ..Default::default()
    };

    let object = create_symmetric_key_kmip_object(&key_bytes, &attributes)?;

    let import_request = Import {
        unique_identifier: UniqueIdentifier::default(),
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes,
        object,
    };

    let response: ImportResponse = client.import(import_request).await?;

    // Get the object and verify initial_date is set
    let get_response = client
        .get(Get {
            unique_identifier: Some(response.unique_identifier.clone()),
            ..Get::default()
        })
        .await?;

    let attrs = get_response.object.attributes()?;
    assert!(
        attrs.initial_date.is_some(),
        "InitialDate should be set on imported object"
    );

    Ok(())
}

/// Test 7: Verify `KeyFormatType` is preserved from import
#[tokio::test]
async fn test_import_preserves_key_format_type() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let key_bytes = vec![0x22; 32];
    let mut attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        object_type: Some(ObjectType::SymmetricKey),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey), // Specific format
        ..Default::default()
    };

    let object = create_symmetric_key_kmip_object(&key_bytes, &attributes)?;
    // Clear the key_format_type from attributes to test preservation from object
    attributes.key_format_type = None;

    let import_request = Import {
        unique_identifier: UniqueIdentifier::default(),
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(false),
        key_wrap_type: None,
        attributes,
        object,
    };

    let response: ImportResponse = client.import(import_request).await?;

    // Get the object and verify key_format_type is preserved
    let get_response = client
        .get(Get {
            unique_identifier: Some(response.unique_identifier.clone()),
            ..Get::default()
        })
        .await?;

    let attrs = get_response.object.attributes()?;
    assert_eq!(
        attrs.key_format_type,
        Some(KeyFormatType::TransparentSymmetricKey),
        "KeyFormatType should be preserved from imported object"
    );

    Ok(())
}

/// Test 8: Permission Denied - Test will require proper auth setup
/// This test demonstrates the structure but may need auth configuration
#[tokio::test]
#[ignore = "Requires authentication setup"]
async fn test_import_error_permission_denied() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    // Would need a client without create permissions
    let _client = ctx.get_owner_client();

    // This test would verify that import fails without proper permissions
    // Implementation requires multi-user auth setup

    Ok(())
}

/// Test 9: Import Certificate (different object type)
/// Note: This test is simplified - full certificate import testing exists in certificates module
#[tokio::test]
#[ignore = "Requires proper certificate DER data - see certificates module for full tests"]
async fn test_import_success_certificate() -> KmsCliResult<()> {
    log_init(None);
    let _ctx = start_default_test_kms_server().await;

    // Full certificate import tests exist in crate/cli/src/tests/kms/certificates/export.rs
    // See test_import_export_p12_25519 and test_import_p12_rsa
    // This placeholder demonstrates the test structure for KMIP 2.1 compliance

    Ok(())
}
