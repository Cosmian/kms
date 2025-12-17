#![allow(clippy::unwrap_in_result)]
use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{CryptographicUsageMask, HashingAlgorithm},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{DerivationParameters, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, SymmetricKey},
        kmip_operations::{Create, DeriveKey, Get},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, DerivationMethod, KeyFormatType,
            UniqueIdentifier,
        },
        requests::create_derivation_object_request,
    },
};
use zeroize::Zeroizing;

use crate::{
    config::ServerParams, core::KMS, result::KResult, tests::test_utils::https_clap_config,
};

/// Helper function to create a symmetric key for testing `DeriveKey` operations
fn create_base_symmetric_key_request() -> Create {
    create_derivation_object_request(ObjectType::SymmetricKey)
        .expect("Failed to create base symmetric key request")
}

/// Helper function to create a secret data object for testing `DeriveKey` operations
fn create_base_secret_data_request() -> Create {
    create_derivation_object_request(ObjectType::SecretData)
        .expect("Failed to create base secret data request")
}

/// Test PBKDF2 key derivation with default parameters
#[tokio::test]
async fn test_derive_key_pbkdf2_default() -> KResult<()> {
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_user";

    // Create a base symmetric key
    let create_request = create_base_symmetric_key_request();
    let create_response = kms.create(create_request, owner, None).await?;
    let base_key_id = create_response.unique_identifier;

    // Create DeriveKey request with PBKDF2
    let derive_request = DeriveKey {
        object_unique_identifier: base_key_id.clone(),
        derivation_method: DerivationMethod::PBKDF2,
        derivation_parameters: DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"test derivation data".to_vec())),
            salt: Some(b"test salt".to_vec()),
            iteration_count: Some(100_000), // Lower than default for faster testing
        },
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(128), // Derive a 128-bit key
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    };

    // Perform the derivation
    let derive_response = kms.derive_key(derive_request, owner).await?;

    // Verify the response
    assert!(!derive_response.unique_identifier.to_string().is_empty());

    // Retrieve the derived key to verify it was created correctly
    let get_request = Get {
        unique_identifier: Some(derive_response.unique_identifier.clone()),
        key_format_type: None,
        key_wrap_type: None,
        key_compression_type: None,
        key_wrapping_specification: None,
    };
    let get_response = kms.get(get_request, owner).await?;

    // Verify the derived key properties
    match get_response.object {
        Object::SymmetricKey(SymmetricKey { key_block }) => {
            assert_eq!(key_block.key_format_type, KeyFormatType::Raw); // Will be converted to Raw on export
            assert_eq!(
                key_block.cryptographic_algorithm,
                Some(CryptographicAlgorithm::AES)
            );
            assert_eq!(key_block.cryptographic_length, Some(128));

            // Verify key material exists and has correct length
            match &key_block.key_value {
                Some(KeyValue::ByteString(key_bytes)) => {
                    assert_eq!(key_bytes.len(), 16); // 128 bits = 16 bytes
                }
                Some(KeyValue::Structure { key_material, .. }) => {
                    // Handle Structure format
                    match key_material {
                        KeyMaterial::TransparentSymmetricKey { key } => {
                            assert_eq!(key.len(), 16); // 128 bits = 16 bytes
                        }
                        KeyMaterial::ByteString(key_bytes) => {
                            assert_eq!(key_bytes.len(), 16); // 128 bits = 16 bytes
                        }
                        _ => panic!("Unexpected key material type"),
                    }
                }
                _ => panic!("Expected valid key value"),
            }
        }
        _ => panic!("Expected SymmetricKey object"),
    }

    Ok(())
}

/// Test PBKDF2 key derivation with different hash algorithms
#[tokio::test]
async fn test_derive_key_pbkdf2_different_hash_algorithms() -> KResult<()> {
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_user";

    // Create a base symmetric key
    let create_request = create_base_symmetric_key_request();
    let create_response = kms.create(create_request, owner, None).await?;
    let base_key_id = create_response.unique_identifier;

    let hash_algorithms = vec![
        HashingAlgorithm::SHA256,
        HashingAlgorithm::SHA384,
        HashingAlgorithm::SHA512,
    ];

    for hash_algorithm in hash_algorithms {
        let derive_request = DeriveKey {
            object_unique_identifier: base_key_id.clone(),
            derivation_method: DerivationMethod::PBKDF2,
            derivation_parameters: DerivationParameters {
                cryptographic_parameters: Some(CryptographicParameters {
                    hashing_algorithm: Some(hash_algorithm),
                    ..CryptographicParameters::default()
                }),
                initialization_vector: None,
                derivation_data: Some(Zeroizing::new(b"test derivation data".to_vec())),
                salt: Some(b"test salt".to_vec()),
                iteration_count: Some(10_000), // Lower for faster testing
            },
            object_type: ObjectType::SymmetricKey,
            attributes: Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(256),
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                ),
                key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
                object_type: Some(ObjectType::SymmetricKey),
                ..Attributes::default()
            },
        };

        let derive_response = kms.derive_key(derive_request, owner).await?;
        assert!(!derive_response.unique_identifier.to_string().is_empty());

        // Verify the derived key
        let get_request = Get {
            unique_identifier: Some(derive_response.unique_identifier),
            key_format_type: None,
            key_wrap_type: None,
            key_compression_type: None,
            key_wrapping_specification: None,
        };
        let get_response = kms.get(get_request, owner).await?;

        match get_response.object {
            Object::SymmetricKey(SymmetricKey { key_block }) => {
                let key_bytes = key_block.key_bytes()?;
                assert_eq!(key_bytes.len(), 32); // 256 bits = 32 bytes
            }
            _ => panic!("Expected SymmetricKey object"),
        }
    }

    Ok(())
}

/// Test HKDF key derivation
#[tokio::test]
async fn test_derive_key_hkdf() -> KResult<()> {
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_user";

    // Create a base symmetric key
    let create_request = create_base_symmetric_key_request();
    let create_response = kms.create(create_request, owner, None).await?;
    let base_key_id = create_response.unique_identifier;

    // Create DeriveKey request with HKDF
    let derive_request = DeriveKey {
        object_unique_identifier: base_key_id.clone(),
        derivation_method: DerivationMethod::HKDF,
        derivation_parameters: DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"test info for HKDF".to_vec())),
            salt: Some(b"HKDF salt".to_vec()),
            iteration_count: None, // Not used for HKDF
        },
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(192), // Derive a 192-bit key
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    };

    // Perform the derivation
    let derive_response = kms.derive_key(derive_request, owner).await?;

    // Verify the response
    assert!(!derive_response.unique_identifier.to_string().is_empty());

    // Retrieve the derived key to verify it was created correctly
    let get_request = Get {
        unique_identifier: Some(derive_response.unique_identifier),
        key_format_type: None,
        key_wrap_type: None,
        key_compression_type: None,
        key_wrapping_specification: None,
    };
    let get_response = kms.get(get_request, owner).await?;

    // Verify the derived key properties
    match get_response.object {
        Object::SymmetricKey(SymmetricKey { key_block }) => {
            let key_bytes = key_block.key_bytes()?;
            assert_eq!(key_bytes.len(), 24); // 192 bits = 24 bytes
        }
        _ => panic!("Expected SymmetricKey object"),
    }

    Ok(())
}

/// Test deriving from `SecretData` object
#[tokio::test]
async fn test_derive_key_from_secret_data() -> KResult<()> {
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_user";

    // Create a base secret data object
    let create_request = create_base_secret_data_request();
    let create_response = kms.create(create_request, owner, None).await?;
    let base_secret_id = create_response.unique_identifier;

    // Create DeriveKey request using the secret data as base
    let derive_request = DeriveKey {
        object_unique_identifier: base_secret_id,
        derivation_method: DerivationMethod::PBKDF2,
        derivation_parameters: DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"secret data derivation".to_vec())),
            salt: Some(b"secret salt".to_vec()),
            iteration_count: Some(50_000),
        },
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    };

    // Perform the derivation
    let derive_response = kms.derive_key(derive_request, owner).await?;
    assert!(!derive_response.unique_identifier.to_string().is_empty());
    Ok(())
}

/// Test error cases for `DeriveKey` operation
#[tokio::test]
async fn test_derive_key_error_cases() -> KResult<()> {
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_user";

    // Create a base symmetric key WITHOUT DeriveKey usage mask
    let create_request = Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                // Note: Missing DeriveKey usage mask
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
        protection_storage_masks: None,
    };
    let create_response = kms.create(create_request, owner, None).await?;
    let invalid_key_id = create_response.unique_identifier;

    // Test 1: Missing DeriveKey usage mask should fail
    let derive_request = DeriveKey {
        object_unique_identifier: invalid_key_id,
        derivation_method: DerivationMethod::PBKDF2,
        derivation_parameters: DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"test derivation data".to_vec())),
            salt: Some(b"test salt".to_vec()),
            iteration_count: Some(100_000),
        },
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(128),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    };

    let result = kms.derive_key(derive_request, owner).await;
    match result {
        Err(e) => assert!(e.to_string().contains("DeriveKey usage mask")),
        Ok(_) => panic!("expected error"),
    }

    Ok(())
}

/// Test PBKDF2 validation: missing salt should fail
#[tokio::test]
async fn test_derive_key_pbkdf2_missing_salt() -> KResult<()> {
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_user";

    // Create a base symmetric key
    let create_request = create_base_symmetric_key_request();
    let create_response = kms.create(create_request, owner, None).await?;
    let base_key_id = create_response.unique_identifier;

    // Create DeriveKey request with PBKDF2 but missing salt
    let derive_request = DeriveKey {
        object_unique_identifier: base_key_id,
        derivation_method: DerivationMethod::PBKDF2,
        derivation_parameters: DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"test derivation data".to_vec())),
            salt: None, // Missing salt - should cause error
            iteration_count: Some(100_000),
        },
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(128),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    };

    let result = kms.derive_key(derive_request, owner).await;
    match result {
        Err(e) => assert!(
            e.to_string()
                .contains("Salt is mandatory when derivation method is PBKDF2")
        ),
        Ok(_) => panic!("expected error"),
    }

    Ok(())
}

/// Test non-existent base key
#[tokio::test]
async fn test_derive_key_nonexistent_base_key() -> KResult<()> {
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_user";

    // Create DeriveKey request with non-existent base key
    let derive_request = DeriveKey {
        object_unique_identifier: UniqueIdentifier::TextString("nonexistent-key-id".to_owned()),
        derivation_method: DerivationMethod::PBKDF2,
        derivation_parameters: DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"test derivation data".to_vec())),
            salt: Some(b"test salt".to_vec()),
            iteration_count: Some(100_000),
        },
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(128),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    };

    let result = kms.derive_key(derive_request, owner).await;
    match result {
        Err(e) => assert!(e.to_string().contains("failed to retrieve base object")),
        Ok(_) => panic!("expected error"),
    }

    Ok(())
}

/// Test missing cryptographic length
#[tokio::test]
async fn test_derive_key_missing_cryptographic_length() -> KResult<()> {
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "test_user";

    // Create a base symmetric key
    let create_request = create_base_symmetric_key_request();
    let create_response = kms.create(create_request, owner, None).await?;
    let base_key_id = create_response.unique_identifier;

    // Create DeriveKey request without cryptographic length
    let derive_request = DeriveKey {
        object_unique_identifier: base_key_id,
        derivation_method: DerivationMethod::PBKDF2,
        derivation_parameters: DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"test derivation data".to_vec())),
            salt: Some(b"test salt".to_vec()),
            iteration_count: Some(100_000),
        },
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: None, // Missing - should cause error
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    };

    let result = kms.derive_key(derive_request, owner).await;
    match result {
        Err(e) => assert!(
            e.to_string()
                .contains("Cryptographic Length must be specified")
        ),
        Ok(_) => panic!("expected error"),
    }

    Ok(())
}
