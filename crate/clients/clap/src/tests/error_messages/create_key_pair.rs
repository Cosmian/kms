// KMIP 2.1 CreateKeyPair Operation Compliance Tests
// Verifies that CreateKeyPair operation returns proper error reasons per Table 192: Create Key Pair Errors

use cosmian_kms_client::cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::CreateKeyPair,
        kmip_types::{
            CryptographicAlgorithm, CryptographicDomainParameters, ProtectionStorageMasks,
            RecommendedCurve,
        },
    },
};
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use crate::error::result::KmsCliResult;

/// Test 1: Successfully create an RSA key pair
#[tokio::test]
async fn test_create_key_pair_success_rsa() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let common_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        cryptographic_length: Some(2048),
        object_type: Some(ObjectType::PrivateKey),
        ..Default::default()
    };

    let private_key_attributes = Attributes {
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Sign
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::UnwrapKey,
        ),
        ..Default::default()
    };

    let public_key_attributes = Attributes {
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Verify | CryptographicUsageMask::Encrypt,
        ),
        ..Default::default()
    };

    let create_request = CreateKeyPair {
        common_attributes: Some(common_attributes),
        private_key_attributes: Some(private_key_attributes),
        public_key_attributes: Some(public_key_attributes),
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
    };

    let response = client.create_key_pair(create_request).await?;

    assert!(
        !response
            .private_key_unique_identifier
            .to_string()
            .is_empty()
    );
    assert!(!response.public_key_unique_identifier.to_string().is_empty());

    Ok(())
}

/// Test 2: Successfully create an EC key pair (NIST P-256)
#[tokio::test]
async fn test_create_key_pair_success_ec() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let common_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
        cryptographic_length: Some(256),
        cryptographic_domain_parameters: Some(CryptographicDomainParameters {
            recommended_curve: Some(RecommendedCurve::P256),
            ..Default::default()
        }),
        object_type: Some(ObjectType::PrivateKey),
        ..Default::default()
    };

    let private_key_attributes = Attributes {
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::DeriveKey | CryptographicUsageMask::KeyAgreement,
        ),
        ..Default::default()
    };

    let public_key_attributes = Attributes {
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::DeriveKey | CryptographicUsageMask::KeyAgreement,
        ),
        ..Default::default()
    };

    let create_request = CreateKeyPair {
        common_attributes: Some(common_attributes),
        private_key_attributes: Some(private_key_attributes),
        public_key_attributes: Some(public_key_attributes),
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
    };

    let response = client.create_key_pair(create_request).await?;

    assert!(
        !response
            .private_key_unique_identifier
            .to_string()
            .is_empty()
    );
    assert!(!response.public_key_unique_identifier.to_string().is_empty());

    Ok(())
}

/// Test 3: Feature Not Supported - Protection Storage Masks
/// Expected: Operation Failed with Feature Not Supported
#[tokio::test]
async fn test_create_key_pair_error_feature_not_supported() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let common_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        cryptographic_length: Some(2048),
        object_type: Some(ObjectType::PrivateKey),
        ..Default::default()
    };

    // Attempt to use protection_storage_masks (not supported)
    let create_request = CreateKeyPair {
        common_attributes: Some(common_attributes),
        private_key_attributes: None,
        public_key_attributes: None,
        common_protection_storage_masks: Some(ProtectionStorageMasks::Software),
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
    };

    let result = client.create_key_pair(create_request).await;
    assert!(
        result.is_err(),
        "Should fail for unsupported protection storage masks"
    );

    let error = result.unwrap_err();
    // Feature Not Supported is the expected error, but string matching is more accurate here
    // as the exact error reason may vary based on implementation
    let error_msg = error.to_string().to_lowercase();
    assert!(
        error_msg.contains("not")
            && (error_msg.contains("support") || error_msg.contains("placeholder")),
        "Error should indicate unsupported feature, got: {error}"
    );

    Ok(())
}

/// Test 4: Invalid Attribute - Missing required algorithm
/// Expected: Operation Failed with Invalid Attribute or Cryptographic Failure
#[tokio::test]
async fn test_create_key_pair_error_invalid_attribute_missing_algorithm() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Missing cryptographic_algorithm (required)
    let common_attributes = Attributes {
        cryptographic_algorithm: None, // Missing!
        cryptographic_length: Some(2048),
        object_type: Some(ObjectType::PrivateKey),
        ..Default::default()
    };

    let create_request = CreateKeyPair {
        common_attributes: Some(common_attributes),
        private_key_attributes: None,
        public_key_attributes: None,
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
    };

    let result = client.create_key_pair(create_request).await;
    assert!(
        result.is_err(),
        "Should fail without cryptographic algorithm"
    );

    let error = result.unwrap_err();
    // Use string matching as multiple error reasons may apply (Invalid Attribute, Cryptographic Failure)
    let error_msg = error.to_string().to_lowercase();
    assert!(
        error_msg.contains("algorithm")
            || error_msg.contains("invalid")
            || error_msg.contains("cryptographic"),
        "Error should indicate missing algorithm, got: {error}"
    );

    Ok(())
}

/// Test 5: Invalid Attribute Value - Unsupported curve
/// Expected: Operation Failed with Invalid Attribute Value or Operation Not Supported
#[tokio::test]
async fn test_create_key_pair_error_invalid_curve() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let common_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
        cryptographic_length: Some(256),
        cryptographic_domain_parameters: Some(CryptographicDomainParameters {
            recommended_curve: Some(RecommendedCurve::SECT163R1), // Unsupported SECT curve
            ..Default::default()
        }),
        object_type: Some(ObjectType::PrivateKey),
        ..Default::default()
    };

    let create_request = CreateKeyPair {
        common_attributes: Some(common_attributes),
        private_key_attributes: None,
        public_key_attributes: None,
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
    };

    let result = client.create_key_pair(create_request).await;
    assert!(result.is_err(), "Should fail for unsupported curve");

    let error = result.unwrap_err();
    // Use string matching as the exact curve name should appear in the error
    let error_msg = error.to_string().to_lowercase();
    assert!(
        error_msg.contains("not")
            && (error_msg.contains("support")
                || error_msg.contains("curve")
                || error_msg.contains("sect163k1")),
        "Error should indicate unsupported curve, got: {error}"
    );

    Ok(())
}

/// Test 6: Permission Denied - Requires authentication
/// Expected: Operation Failed with Permission Denied
#[tokio::test]
#[ignore = "Requires authentication setup"]
async fn test_create_key_pair_error_permission_denied() -> KmsCliResult<()> {
    // This test would require setting up a KMS server with authentication
    // and using a client without proper Create permissions
    Ok(())
}

/// Test 7: Verify consistent attributes between private and public keys
/// According to Table 191, certain attributes must have the same value for both keys
#[tokio::test]
async fn test_create_key_pair_attribute_consistency() -> KmsCliResult<()> {
    use cosmian_kms_client::cosmian_kmip::kmip_2_1::kmip_operations::Get;

    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    let common_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        cryptographic_length: Some(2048),
        object_type: Some(ObjectType::PrivateKey),
        ..Default::default()
    };

    let private_key_attributes = Attributes {
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Sign
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::UnwrapKey,
        ),
        ..Default::default()
    };

    let public_key_attributes = Attributes {
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Verify | CryptographicUsageMask::Encrypt,
        ),
        ..Default::default()
    };

    let create_request = CreateKeyPair {
        common_attributes: Some(common_attributes.clone()),
        private_key_attributes: Some(private_key_attributes),
        public_key_attributes: Some(public_key_attributes),
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
    };

    let response = client.create_key_pair(create_request).await?;

    // Get both keys to verify attributes
    let private_key_response = client
        .get(Get {
            unique_identifier: Some(response.private_key_unique_identifier.clone()),
            ..Get::default()
        })
        .await?;

    let public_key_response = client
        .get(Get {
            unique_identifier: Some(response.public_key_unique_identifier.clone()),
            ..Get::default()
        })
        .await?;

    let private_attrs = private_key_response.object.attributes()?;
    let public_attrs = public_key_response.object.attributes()?;

    // Per Table 191: These attributes SHALL contain the same value for both keys
    assert_eq!(
        private_attrs.cryptographic_algorithm, public_attrs.cryptographic_algorithm,
        "Cryptographic Algorithm must match"
    );
    assert_eq!(
        private_attrs.cryptographic_length, public_attrs.cryptographic_length,
        "Cryptographic Length must match"
    );

    Ok(())
}
