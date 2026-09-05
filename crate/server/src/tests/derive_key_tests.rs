#![allow(clippy::unwrap_in_result)]
#[cfg(feature = "non-fips")]
use std::collections::HashSet;
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
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
    cosmian_kmip::kmip_2_1::{
        KmipOperation,
        kmip_data_structures::KeyBlock,
        kmip_objects::{PublicKey, SecretData},
        kmip_operations::{Activate, Decrypt, Destroy, Encrypt, Import, Revoke},
        kmip_types::{CryptographicDomainParameters, LinkType, RecommendedCurve},
        requests::create_ec_key_pair_request,
    },
    cosmian_kms_crypto::crypto::elliptic_curves::operation::{to_ec_private_key, to_ec_public_key},
};
use zeroize::Zeroizing;

use crate::{
    config::ServerParams, core::KMS, middlewares::UserId, result::KResult,
    tests::test_utils::https_clap_config,
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
    let owner = UserId::from("test_user");

    // Create a base symmetric key
    let create_request = create_base_symmetric_key_request();
    let create_response = kms.create(create_request, &owner).await?;
    let base_key_id = create_response.unique_identifier;

    // Create DeriveKey request with PBKDF2
    let derive_request = DeriveKey::new_single_base(
        ObjectType::SymmetricKey,
        base_key_id.clone(),
        DerivationMethod::PBKDF2,
        DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"test derivation data".to_vec())),
            salt: Some(b"test salt".to_vec()),
            iteration_count: Some(100_000), // Lower than default for faster testing
        },
        Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(128), // Derive a 128-bit key
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    );

    // Perform the derivation
    let derive_response = kms.derive_key(derive_request, &owner).await?;

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
    let get_response = kms.get(get_request, &owner).await?;

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
    let owner = UserId::from("test_user");

    // Create a base symmetric key
    let create_request = create_base_symmetric_key_request();
    let create_response = kms.create(create_request, &owner).await?;
    let base_key_id = create_response.unique_identifier;

    let hash_algorithms = vec![
        HashingAlgorithm::SHA256,
        HashingAlgorithm::SHA384,
        HashingAlgorithm::SHA512,
    ];

    for hash_algorithm in hash_algorithms {
        let derive_request = DeriveKey::new_single_base(
            ObjectType::SymmetricKey,
            base_key_id.clone(),
            DerivationMethod::PBKDF2,
            DerivationParameters {
                cryptographic_parameters: Some(CryptographicParameters {
                    hashing_algorithm: Some(hash_algorithm),
                    ..CryptographicParameters::default()
                }),
                initialization_vector: None,
                derivation_data: Some(Zeroizing::new(b"test derivation data".to_vec())),
                salt: Some(b"test salt".to_vec()),
                iteration_count: Some(10_000), // Lower for faster testing
            },
            Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(256),
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                ),
                key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
                object_type: Some(ObjectType::SymmetricKey),
                ..Attributes::default()
            },
        );

        let derive_response = kms.derive_key(derive_request, &owner).await?;
        assert!(!derive_response.unique_identifier.to_string().is_empty());

        // Verify the derived key
        let get_request = Get {
            unique_identifier: Some(derive_response.unique_identifier),
            key_format_type: None,
            key_wrap_type: None,
            key_compression_type: None,
            key_wrapping_specification: None,
        };
        let get_response = kms.get(get_request, &owner).await?;

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
    let owner = UserId::from("test_user");

    // Create a base symmetric key
    let create_request = create_base_symmetric_key_request();
    let create_response = kms.create(create_request, &owner).await?;
    let base_key_id = create_response.unique_identifier;

    // Create DeriveKey request with HKDF
    let derive_request = DeriveKey::new_single_base(
        ObjectType::SymmetricKey,
        base_key_id.clone(),
        DerivationMethod::HKDF,
        DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"test info for HKDF".to_vec())),
            salt: Some(b"HKDF salt".to_vec()),
            iteration_count: None, // Not used for HKDF
        },
        Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(192), // Derive a 192-bit key
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    );

    // Perform the derivation
    let derive_response = kms.derive_key(derive_request, &owner).await?;

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
    let get_response = kms.get(get_request, &owner).await?;

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
    let owner = UserId::from("test_user");

    // Create a base secret data object
    let create_request = create_base_secret_data_request();
    let create_response = kms.create(create_request, &owner).await?;
    let base_secret_id = create_response.unique_identifier;

    // Create DeriveKey request using the secret data as base
    let derive_request = DeriveKey::new_single_base(
        ObjectType::SymmetricKey,
        base_secret_id,
        DerivationMethod::PBKDF2,
        DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"secret data derivation".to_vec())),
            salt: Some(b"secret salt".to_vec()),
            iteration_count: Some(50_000),
        },
        Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    );

    // Perform the derivation
    let derive_response = kms.derive_key(derive_request, &owner).await?;
    assert!(!derive_response.unique_identifier.to_string().is_empty());
    Ok(())
}

/// Test error cases for `DeriveKey` operation
#[tokio::test]
async fn test_derive_key_error_cases() -> KResult<()> {
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = UserId::from("test_user");

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
    let create_response = kms.create(create_request, &owner).await?;
    let invalid_key_id = create_response.unique_identifier;

    // Test 1: Missing DeriveKey usage mask should fail
    let derive_request = DeriveKey::new_single_base(
        ObjectType::SymmetricKey,
        invalid_key_id,
        DerivationMethod::PBKDF2,
        DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"test derivation data".to_vec())),
            salt: Some(b"test salt".to_vec()),
            iteration_count: Some(100_000),
        },
        Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(128),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    );

    let result = kms.derive_key(derive_request, &owner).await;
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
    let owner = UserId::from("test_user");

    // Create a base symmetric key
    let create_request = create_base_symmetric_key_request();
    let create_response = kms.create(create_request, &owner).await?;
    let base_key_id = create_response.unique_identifier;

    // Create DeriveKey request with PBKDF2 but missing salt
    let derive_request = DeriveKey::new_single_base(
        ObjectType::SymmetricKey,
        base_key_id,
        DerivationMethod::PBKDF2,
        DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"test derivation data".to_vec())),
            salt: None, // Missing salt - should cause error
            iteration_count: Some(100_000),
        },
        Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(128),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    );

    let result = kms.derive_key(derive_request, &owner).await;
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
    let owner = UserId::from("test_user");

    // Create DeriveKey request with non-existent base key
    let derive_request = DeriveKey::new_single_base(
        ObjectType::SymmetricKey,
        UniqueIdentifier::TextString("nonexistent-key-id".to_owned()),
        DerivationMethod::PBKDF2,
        DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"test derivation data".to_vec())),
            salt: Some(b"test salt".to_vec()),
            iteration_count: Some(100_000),
        },
        Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(128),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    );

    let result = kms.derive_key(derive_request, &owner).await;
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
    let owner = UserId::from("test_user");

    // Create a base symmetric key
    let create_request = create_base_symmetric_key_request();
    let create_response = kms.create(create_request, &owner).await?;
    let base_key_id = create_response.unique_identifier;

    // Create DeriveKey request without cryptographic length
    let derive_request = DeriveKey::new_single_base(
        ObjectType::SymmetricKey,
        base_key_id,
        DerivationMethod::PBKDF2,
        DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            initialization_vector: None,
            derivation_data: Some(Zeroizing::new(b"test derivation data".to_vec())),
            salt: Some(b"test salt".to_vec()),
            iteration_count: Some(100_000),
        },
        Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: None, // Missing - should cause error
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    );

    let result = kms.derive_key(derive_request, &owner).await;
    match result {
        Err(e) => assert!(
            e.to_string()
                .contains("Cryptographic Length must be specified")
        ),
        Ok(_) => panic!("expected error"),
    }

    Ok(())
}

#[cfg(feature = "non-fips")]
async fn make_kms() -> KResult<Arc<KMS>> {
    let clap_config = https_clap_config();
    Ok(Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?,
    ))
}

#[cfg(feature = "non-fips")]
fn x25519_import_attributes(
    uid: &str,
    object_type: ObjectType,
    recommended_curve: Option<RecommendedCurve>,
    usage_mask: CryptographicUsageMask,
    key_format_type: KeyFormatType,
    sensitive: bool,
) -> Attributes {
    Attributes {
        object_type: Some(object_type),
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(usage_mask),
        key_format_type: Some(key_format_type),
        cryptographic_domain_parameters: Some(CryptographicDomainParameters {
            recommended_curve,
            ..CryptographicDomainParameters::default()
        }),
        sensitive: sensitive.then_some(true),
        ..Attributes::default()
    }
}

#[cfg(feature = "non-fips")]
async fn import_private_x25519_key(
    kms: &Arc<KMS>,
    owner: &UserId,
    uid: &str,
    public_key_uid: &str,
    private_key_bytes: &[u8],
    recommended_curve: Option<RecommendedCurve>,
    usage_mask: CryptographicUsageMask,
) -> KResult<String> {
    let curve = recommended_curve.unwrap_or(RecommendedCurve::CURVE25519);
    let object = to_ec_private_key(
        private_key_bytes,
        253,
        public_key_uid,
        curve,
        Some(CryptographicAlgorithm::ECDH),
        Some(usage_mask),
        true,
    )?;
    let attributes = x25519_import_attributes(
        uid,
        ObjectType::PrivateKey,
        recommended_curve,
        usage_mask,
        KeyFormatType::TransparentECPrivateKey,
        true,
    );
    let response = kms
        .import(
            Import {
                unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
                object_type: ObjectType::PrivateKey,
                replace_existing: Some(true),
                key_wrap_type: None,
                attributes,
                object,
            },
            owner,
        )
        .await?;
    Ok(response.unique_identifier.to_string())
}

#[cfg(feature = "non-fips")]
async fn import_public_x25519_key(
    kms: &Arc<KMS>,
    owner: &UserId,
    uid: &str,
    private_key_uid: &str,
    public_key_bytes: &[u8],
    recommended_curve: Option<RecommendedCurve>,
    usage_mask: CryptographicUsageMask,
) -> KResult<String> {
    let curve = recommended_curve.unwrap_or(RecommendedCurve::CURVE25519);
    let object = to_ec_public_key(
        public_key_bytes,
        253,
        private_key_uid,
        curve,
        Some(CryptographicAlgorithm::ECDH),
        Some(usage_mask),
    )?;
    let attributes = x25519_import_attributes(
        uid,
        ObjectType::PublicKey,
        recommended_curve,
        usage_mask,
        KeyFormatType::TransparentECPublicKey,
        false,
    );
    let response = kms
        .import(
            Import {
                unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
                object_type: ObjectType::PublicKey,
                replace_existing: Some(true),
                key_wrap_type: None,
                attributes,
                object,
            },
            owner,
        )
        .await?;
    Ok(response.unique_identifier.to_string())
}

#[cfg(feature = "non-fips")]
fn build_x25519_derive_request(private_uid: &str, peer_uid: &str, derived_uid: &str) -> DeriveKey {
    DeriveKey::new_asymmetric(
        UniqueIdentifier::TextString(private_uid.to_owned()),
        UniqueIdentifier::TextString(peer_uid.to_owned()),
        DerivationParameters::default(),
        Attributes {
            unique_identifier: Some(UniqueIdentifier::TextString(derived_uid.to_owned())),
            cryptographic_length: Some(256),
            object_type: Some(ObjectType::SecretData),
            ..Attributes::default()
        },
    )
}

#[cfg(feature = "non-fips")]
fn build_hkdf_chacha_request(base_uid: &str, derived_uid: &str) -> DeriveKey {
    DeriveKey::new_single_base(
        ObjectType::SymmetricKey,
        UniqueIdentifier::TextString(base_uid.to_owned()),
        DerivationMethod::HKDF,
        DerivationParameters {
            cryptographic_parameters: Some(CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..CryptographicParameters::default()
            }),
            derivation_data: Some(Zeroizing::new(b"share-seal/v1".to_vec())),
            salt: Some(b"share-seal-salt".to_vec()),
            iteration_count: None,
            initialization_vector: None,
        },
        Attributes {
            unique_identifier: Some(UniqueIdentifier::TextString(derived_uid.to_owned())),
            cryptographic_algorithm: Some(CryptographicAlgorithm::ChaCha20Poly1305),
            cryptographic_length: Some(256),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            object_type: Some(ObjectType::SymmetricKey),
            ..Attributes::default()
        },
    )
}

#[cfg(feature = "non-fips")]
async fn secret_bytes(kms: &Arc<KMS>, uid: &str) -> KResult<Zeroizing<Vec<u8>>> {
    let object = kms
        .database
        .retrieve_object(uid)
        .await?
        .expect("object must exist");
    match object.object() {
        Object::SecretData(SecretData { key_block, .. })
        | Object::SymmetricKey(SymmetricKey { key_block }) => {
            key_block.key_bytes().map_err(Into::into)
        }
        other => panic!("unexpected object type: {other:?}"),
    }
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_derive_key_x25519_rfc_7748_vector() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::from("x25519-owner");
    let alice_private =
        hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .expect("alice private");
    let bob_public =
        hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
            .expect("bob public");
    let expected_shared_secret =
        hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
            .expect("shared secret");

    import_private_x25519_key(
        &kms,
        &owner,
        "alice-private",
        "bob-public",
        &alice_private,
        Some(RecommendedCurve::CURVE25519),
        CryptographicUsageMask::DeriveKey | CryptographicUsageMask::KeyAgreement,
    )
    .await?;
    import_public_x25519_key(
        &kms,
        &owner,
        "bob-public",
        "alice-private",
        &bob_public,
        Some(RecommendedCurve::CURVE25519),
        CryptographicUsageMask::KeyAgreement,
    )
    .await?;

    let derived_uid = "derived-rfc7748-secret";
    let response = kms
        .derive_key(
            build_x25519_derive_request("alice-private", "bob-public", derived_uid),
            &owner,
        )
        .await?;
    assert_eq!(
        response.unique_identifier.to_string(),
        derived_uid.to_owned()
    );
    assert_eq!(
        secret_bytes(&kms, derived_uid).await?.as_slice(),
        expected_shared_secret
    );

    let private = kms
        .database
        .retrieve_object("alice-private")
        .await?
        .expect("private key must exist");
    let peer = kms
        .database
        .retrieve_object("bob-public")
        .await?
        .expect("public key must exist");
    let derived = kms
        .database
        .retrieve_object(derived_uid)
        .await?
        .expect("derived secret must exist");

    assert!(
        private
            .attributes()
            .get_links(LinkType::DerivedKeyLink)
            .iter()
            .any(|link| link.to_string() == derived_uid),
        "private key must point to the derived secret"
    );
    assert!(
        peer.attributes()
            .get_links(LinkType::DerivedKeyLink)
            .iter()
            .any(|link| link.to_string() == derived_uid),
        "peer public key must point to the derived secret"
    );
    let base_links = derived
        .attributes()
        .get_links(LinkType::DerivationBaseObjectLink);
    assert_eq!(base_links.len(), 2);
    assert_eq!(base_links[0].to_string(), "alice-private".to_owned());
    assert_eq!(base_links[1].to_string(), "bob-public".to_owned());

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_derive_key_x25519_can_feed_hkdf_and_chacha20_poly1305() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::from("x25519-generated-owner");

    let alice = kms
        .create_key_pair(
            create_ec_key_pair_request(
                "cosmian",
                Some(UniqueIdentifier::TextString(
                    "alice-generated-private".to_owned(),
                )),
                ["x25519-generated-a"],
                RecommendedCurve::CURVE25519,
                true,
                None,
            )?,
            &owner,
        )
        .await?;
    let bob = kms
        .create_key_pair(
            create_ec_key_pair_request(
                "cosmian",
                Some(UniqueIdentifier::TextString(
                    "bob-generated-private".to_owned(),
                )),
                ["x25519-generated-b"],
                RecommendedCurve::CURVE25519,
                true,
                None,
            )?,
            &owner,
        )
        .await?;

    kms.derive_key(
        build_x25519_derive_request(
            &alice.private_key_unique_identifier.to_string(),
            &bob.public_key_unique_identifier.to_string(),
            "shared-secret-ab",
        ),
        &owner,
    )
    .await?;
    kms.derive_key(
        build_x25519_derive_request(
            &bob.private_key_unique_identifier.to_string(),
            &alice.public_key_unique_identifier.to_string(),
            "shared-secret-ba",
        ),
        &owner,
    )
    .await?;

    let shared_ab = secret_bytes(&kms, "shared-secret-ab").await?;
    let shared_ba = secret_bytes(&kms, "shared-secret-ba").await?;
    assert_eq!(shared_ab.as_slice(), shared_ba.as_slice());

    let sealing_key_ab = kms
        .derive_key(
            build_hkdf_chacha_request("shared-secret-ab", "sealing-key-ab"),
            &owner,
        )
        .await?;
    let sealing_key_ba = kms
        .derive_key(
            build_hkdf_chacha_request("shared-secret-ba", "sealing-key-ba"),
            &owner,
        )
        .await?;
    kms.activate(
        Activate {
            unique_identifier: sealing_key_ab.unique_identifier.clone(),
        },
        &owner,
    )
    .await?;
    kms.activate(
        Activate {
            unique_identifier: sealing_key_ba.unique_identifier.clone(),
        },
        &owner,
    )
    .await?;

    let plaintext = Zeroizing::new(b"share payload".to_vec());
    let aad = b"protocol=v1;deposit=42;share=1;holder=alice;epk=bob-public".to_vec();
    let nonce = vec![0xA5; 12];

    let encrypt_response = kms
        .encrypt(
            Encrypt {
                unique_identifier: Some(sealing_key_ab.unique_identifier.clone()),
                cryptographic_parameters: Some(CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::ChaCha20Poly1305),
                    ..CryptographicParameters::default()
                }),
                data: Some(plaintext.clone()),
                i_v_counter_nonce: Some(nonce.clone()),
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
                authenticated_encryption_additional_data: Some(aad.clone()),
            },
            &owner,
        )
        .await?;

    let decrypt_response = kms
        .decrypt(
            Decrypt {
                unique_identifier: Some(sealing_key_ba.unique_identifier.clone()),
                cryptographic_parameters: Some(CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::ChaCha20Poly1305),
                    ..CryptographicParameters::default()
                }),
                data: encrypt_response.data.clone(),
                i_v_counter_nonce: Some(nonce.clone()),
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
                authenticated_encryption_additional_data: Some(aad),
                authenticated_encryption_tag: encrypt_response.authenticated_encryption_tag.clone(),
            },
            &owner,
        )
        .await?;
    assert_eq!(
        decrypt_response.data.expect("plaintext").as_slice(),
        plaintext.as_slice()
    );

    kms.revoke(
        Revoke {
            unique_identifier: Some(sealing_key_ab.unique_identifier.clone()),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::Unspecified,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: true,
        },
        &owner,
    )
    .await?;
    kms.destroy(
        Destroy {
            unique_identifier: Some(sealing_key_ab.unique_identifier.clone()),
            remove: true,
            cascade: true,
            expected_object_type: None,
        },
        &owner,
    )
    .await?;
    kms.revoke(
        Revoke {
            unique_identifier: Some(sealing_key_ba.unique_identifier.clone()),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::Unspecified,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: true,
        },
        &owner,
    )
    .await?;
    kms.destroy(
        Destroy {
            unique_identifier: Some(sealing_key_ba.unique_identifier.clone()),
            remove: true,
            cascade: true,
            expected_object_type: None,
        },
        &owner,
    )
    .await?;

    let reuse_result = kms
        .encrypt(
            Encrypt {
                unique_identifier: Some(sealing_key_ab.unique_identifier),
                cryptographic_parameters: Some(CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::ChaCha20Poly1305),
                    ..CryptographicParameters::default()
                }),
                data: Some(Zeroizing::new(b"again".to_vec())),
                i_v_counter_nonce: Some(nonce),
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
                authenticated_encryption_additional_data: None,
            },
            &owner,
        )
        .await;
    assert!(
        reuse_result.is_err(),
        "destroyed sealing key must no longer be usable"
    );

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_derive_key_x25519_authorization_is_generic() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::from("x25519-auth-owner");
    let bob = UserId::from("x25519-auth-bob");

    let alice_private =
        hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .expect("alice private");
    let bob_public =
        hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
            .expect("bob public");

    import_private_x25519_key(
        &kms,
        &owner,
        "auth-private",
        "auth-public",
        &alice_private,
        Some(RecommendedCurve::CURVE25519),
        CryptographicUsageMask::DeriveKey | CryptographicUsageMask::KeyAgreement,
    )
    .await?;
    import_public_x25519_key(
        &kms,
        &owner,
        "auth-public",
        "auth-private",
        &bob_public,
        Some(RecommendedCurve::CURVE25519),
        CryptographicUsageMask::KeyAgreement,
    )
    .await?;

    kms.database
        .grant_operations(
            "auth-private",
            &bob,
            HashSet::from([KmipOperation::DeriveKey]),
        )
        .await?;

    let error = kms
        .derive_key(
            build_x25519_derive_request("auth-private", "auth-public", "auth-derived"),
            &bob,
        )
        .await
        .expect_err("missing permission must fail");
    assert!(
        error
            .to_string()
            .contains("requires access to both referenced objects"),
        "unexpected error: {error}"
    );
    assert!(
        kms.database
            .retrieve_object("auth-derived")
            .await?
            .is_none()
    );

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_derive_key_x25519_validation_failures_create_no_object() -> KResult<()> {
    let kms = make_kms().await?;
    let owner = UserId::from("x25519-validation-owner");
    let alice_private =
        hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .expect("alice private");
    let bob_public =
        hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
            .expect("bob public");

    import_private_x25519_key(
        &kms,
        &owner,
        "validation-private",
        "validation-public",
        &alice_private,
        Some(RecommendedCurve::CURVE25519),
        CryptographicUsageMask::DeriveKey | CryptographicUsageMask::KeyAgreement,
    )
    .await?;
    import_public_x25519_key(
        &kms,
        &owner,
        "validation-public",
        "validation-private",
        &bob_public,
        Some(RecommendedCurve::CURVE25519),
        CryptographicUsageMask::KeyAgreement,
    )
    .await?;

    let wrong_count = DeriveKey {
        object_type: ObjectType::SecretData,
        object_unique_identifier: vec![UniqueIdentifier::TextString(
            "validation-private".to_owned(),
        )],
        derivation_method: DerivationMethod::Asymmetric_Key,
        derivation_parameters: DerivationParameters::default(),
        attributes: Attributes {
            unique_identifier: Some(UniqueIdentifier::TextString(
                "x25519-wrong-count".to_owned(),
            )),
            cryptographic_length: Some(256),
            ..Attributes::default()
        },
    };
    let error = kms
        .derive_key(wrong_count, &owner)
        .await
        .expect_err("wrong count");
    assert!(error.to_string().contains("exactly two identifiers"));
    assert!(
        kms.database
            .retrieve_object("x25519-wrong-count")
            .await?
            .is_none()
    );

    let wrong_order =
        build_x25519_derive_request("validation-public", "validation-private", "x25519-order");
    let error = kms
        .derive_key(wrong_order, &owner)
        .await
        .expect_err("wrong order");
    assert!(
        error
            .to_string()
            .contains("first identifier must reference a private key")
    );
    assert!(
        kms.database
            .retrieve_object("x25519-order")
            .await?
            .is_none()
    );

    let wrong_type_request = DeriveKey::new_single_base(
        ObjectType::SecretData,
        UniqueIdentifier::TextString("validation-private".to_owned()),
        DerivationMethod::Asymmetric_Key,
        DerivationParameters::default(),
        Attributes {
            unique_identifier: Some(UniqueIdentifier::TextString("x25519-single".to_owned())),
            cryptographic_length: Some(256),
            ..Attributes::default()
        },
    );
    let error = kms
        .derive_key(wrong_type_request, &owner)
        .await
        .expect_err("single identifier");
    assert!(error.to_string().contains("exactly two identifiers"));
    assert!(
        kms.database
            .retrieve_object("x25519-single")
            .await?
            .is_none()
    );

    // Regression test: a mismatched top-level `ObjectType` (e.g. `PrivateKey`) must be
    // rejected rather than silently persisting a `SecretData` object under a misleading
    // response type.
    let mismatched_object_type = DeriveKey {
        object_type: ObjectType::PrivateKey,
        object_unique_identifier: vec![
            UniqueIdentifier::TextString("validation-private".to_owned()),
            UniqueIdentifier::TextString("validation-public".to_owned()),
        ],
        derivation_method: DerivationMethod::Asymmetric_Key,
        derivation_parameters: DerivationParameters::default(),
        attributes: Attributes {
            unique_identifier: Some(UniqueIdentifier::TextString(
                "x25519-mismatched-type".to_owned(),
            )),
            cryptographic_length: Some(256),
            ..Attributes::default()
        },
    };
    let error = kms
        .derive_key(mismatched_object_type, &owner)
        .await
        .expect_err("mismatched object type");
    assert!(
        error
            .to_string()
            .contains("asymmetric derivation must create a SecretData object")
    );
    assert!(
        kms.database
            .retrieve_object("x25519-mismatched-type")
            .await?
            .is_none()
    );

    let symmetric_base = kms
        .create(create_base_symmetric_key_request(), &owner)
        .await?;
    let symmetric_base_uid = symmetric_base.unique_identifier.to_string();
    let error = kms
        .derive_key(
            build_x25519_derive_request(
                &symmetric_base_uid,
                "validation-public",
                "x25519-object-type",
            ),
            &owner,
        )
        .await
        .expect_err("wrong object type");
    assert!(
        error
            .to_string()
            .contains("first identifier must reference a private key")
    );
    assert!(
        kms.database
            .retrieve_object("x25519-object-type")
            .await?
            .is_none()
    );

    import_private_x25519_key(
        &kms,
        &owner,
        "ed25519-private",
        "ed25519-public",
        &alice_private,
        Some(RecommendedCurve::CURVE25519),
        CryptographicUsageMask::DeriveKey | CryptographicUsageMask::KeyAgreement,
    )
    .await?;
    import_public_x25519_key(
        &kms,
        &owner,
        "ed25519-public",
        "ed25519-private",
        &bob_public,
        Some(RecommendedCurve::CURVE25519),
        CryptographicUsageMask::KeyAgreement,
    )
    .await?;
    for uid in ["ed25519-private", "ed25519-public"] {
        let owm = kms
            .database
            .retrieve_object(uid)
            .await?
            .expect("ed25519 fixture must exist");
        let mut attributes = owm.attributes().clone();
        attributes.cryptographic_domain_parameters = Some(CryptographicDomainParameters {
            recommended_curve: Some(RecommendedCurve::CURVEED25519),
            ..CryptographicDomainParameters::default()
        });
        kms.database
            .update_object(uid, owm.object(), &attributes, None)
            .await?;
    }
    let error = kms
        .derive_key(
            build_x25519_derive_request("ed25519-private", "validation-public", "x25519-ed"),
            &owner,
        )
        .await
        .expect_err("ed25519 must fail");
    assert!(error.to_string().contains("X25519 curve"));
    assert!(kms.database.retrieve_object("x25519-ed").await?.is_none());

    let missing_curve_public = Object::PublicKey(PublicKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::TransparentECPublicKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentECPublicKey {
                    recommended_curve: RecommendedCurve::CURVE25519,
                    q_string: bob_public.clone(),
                },
                attributes: Some(x25519_import_attributes(
                    "missing-curve-public",
                    ObjectType::PublicKey,
                    None,
                    CryptographicUsageMask::KeyAgreement,
                    KeyFormatType::TransparentECPublicKey,
                    false,
                )),
            }),
            cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
            cryptographic_length: Some(256),
            key_wrapping_data: None,
        },
    });
    kms.import(
        Import {
            unique_identifier: UniqueIdentifier::TextString("missing-curve-public".to_owned()),
            object_type: ObjectType::PublicKey,
            replace_existing: Some(true),
            key_wrap_type: None,
            attributes: x25519_import_attributes(
                "missing-curve-public",
                ObjectType::PublicKey,
                None,
                CryptographicUsageMask::KeyAgreement,
                KeyFormatType::TransparentECPublicKey,
                false,
            ),
            object: missing_curve_public,
        },
        &owner,
    )
    .await?;
    let missing_curve_owm = kms
        .database
        .retrieve_object("missing-curve-public")
        .await?
        .expect("missing-curve public key must exist");
    let mut missing_curve_attributes = missing_curve_owm.attributes().clone();
    missing_curve_attributes.cryptographic_domain_parameters = None;
    kms.database
        .update_object(
            "missing-curve-public",
            missing_curve_owm.object(),
            &missing_curve_attributes,
            None,
        )
        .await?;
    let error = kms
        .derive_key(
            build_x25519_derive_request(
                "validation-private",
                "missing-curve-public",
                "x25519-missing-curve",
            ),
            &owner,
        )
        .await
        .expect_err("missing curve");
    assert!(
        error
            .to_string()
            .contains("declare the X25519 curve attribute")
            || error.to_string().contains("X25519 curve")
    );
    assert!(
        kms.database
            .retrieve_object("x25519-missing-curve")
            .await?
            .is_none()
    );

    let error = kms
        .derive_key(
            DeriveKey::new_asymmetric(
                UniqueIdentifier::TextString("validation-private".to_owned()),
                UniqueIdentifier::TextString("validation-public".to_owned()),
                DerivationParameters::default(),
                Attributes {
                    unique_identifier: Some(UniqueIdentifier::TextString(
                        "x25519-symmetric".to_owned(),
                    )),
                    object_type: Some(ObjectType::SymmetricKey),
                    cryptographic_length: Some(256),
                    ..Attributes::default()
                },
            ),
            &owner,
        )
        .await
        .expect_err("symmetric request type");
    assert!(
        error
            .to_string()
            .contains("must create a SecretData object")
    );
    assert!(
        kms.database
            .retrieve_object("x25519-symmetric")
            .await?
            .is_none()
    );

    Ok(())
}

#[cfg(not(feature = "non-fips"))]
#[tokio::test]
async fn test_derive_key_asymmetric_not_supported_in_fips() -> KResult<()> {
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = UserId::from("fips-owner");

    let error = kms
        .derive_key(
            DeriveKey::new_asymmetric(
                UniqueIdentifier::TextString("private-key".to_owned()),
                UniqueIdentifier::TextString("peer-public-key".to_owned()),
                DerivationParameters::default(),
                Attributes {
                    unique_identifier: Some(UniqueIdentifier::TextString(
                        "fips-x25519-secret".to_owned(),
                    )),
                    cryptographic_length: Some(256),
                    ..Attributes::default()
                },
            ),
            &owner,
        )
        .await
        .expect_err("fips must reject asymmetric derive");
    assert!(
        matches!(error, crate::error::KmsError::NotSupported(_)),
        "unexpected error: {error}"
    );

    Ok(())
}
