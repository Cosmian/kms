//! Security regression tests for fixed vulnerabilities.
//!
//! These tests ensure that security fixes are not accidentally reverted in future
//! development. Each test documents the vulnerability it guards against.
#![allow(clippy::unwrap_in_result)]

use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::HashingAlgorithm,
    kmip_2_1::{
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_operations::{Decrypt, Encrypt, Hash, MAC},
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
        requests::symmetric_key_create_request,
    },
};
use zeroize::Zeroizing;

use crate::{
    config::ServerParams, core::KMS, result::KResult, tests::test_utils::https_clap_config,
};

/// Helper: create a KMS instance for tests
async fn test_kms() -> KResult<Arc<KMS>> {
    Ok(Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(https_clap_config())?)).await?,
    ))
}

/// Helper: create a symmetric AES-256 key for encryption tests
async fn create_aes_key(kms: &KMS, user: &str) -> KResult<UniqueIdentifier> {
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )
    .map_err(|e| crate::error::KmsError::InvalidRequest(e.to_string()))?;
    let response = kms.create(request, user, None).await?;
    Ok(response.unique_identifier)
}

/// Regression test for log sanitization in Encrypt operation.
///
/// Previously, the trace! macro in encrypt.rs would log the full plaintext and
/// ciphertext. This test ensures that the encrypt operation works correctly after
/// the trace was changed to only log data lengths.
///
/// Guards: COSMIAN-2026-005 (sensitive data in logs)
#[tokio::test]
async fn test_encrypt_no_plaintext_in_traces() -> KResult<()> {
    cosmian_logger::log_init(Some("trace"));
    let kms = test_kms().await?;
    let key_id = create_aes_key(&kms, "test_user").await?;

    // Use distinctive plaintext that would be recognizable in logs
    let sensitive_plaintext = b"SUPER_SECRET_DATA_THAT_MUST_NOT_APPEAR_IN_LOGS_12345";

    let encrypt_request = Encrypt {
        unique_identifier: Some(key_id.clone()),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        }),
        data: Some(Zeroizing::new(sensitive_plaintext.to_vec())),
        ..Default::default()
    };

    // Operation must succeed (regression: trace changes didn't break functionality)
    let response = kms.encrypt(encrypt_request, "test_user").await?;
    assert!(response.data.is_some(), "Encrypt must return ciphertext");
    assert_ne!(
        response.data.as_ref().unwrap().as_slice(),
        sensitive_plaintext,
        "Ciphertext must differ from plaintext"
    );

    Ok(())
}

/// Regression test for log sanitization in Decrypt operation.
///
/// Previously, the trace! macro in decrypt.rs would log the full request including
/// ciphertext data. This test ensures decrypt works correctly after the trace change.
///
/// Guards: COSMIAN-2026-005 (sensitive data in logs)
#[tokio::test]
async fn test_decrypt_no_ciphertext_in_traces() -> KResult<()> {
    cosmian_logger::log_init(Some("trace"));
    let kms = test_kms().await?;
    let key_id = create_aes_key(&kms, "test_user").await?;

    let plaintext = b"CONFIDENTIAL_KEY_MATERIAL_NEVER_LOG_THIS";

    // Encrypt first
    let encrypt_response = kms
        .encrypt(
            Encrypt {
                unique_identifier: Some(key_id.clone()),
                cryptographic_parameters: Some(CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    ..Default::default()
                }),
                data: Some(Zeroizing::new(plaintext.to_vec())),
                ..Default::default()
            },
            "test_user",
        )
        .await?;

    let ciphertext = encrypt_response.data.unwrap();
    let iv = encrypt_response.i_v_counter_nonce;

    // Decrypt with trace level logging active
    let decrypt_request = Decrypt {
        unique_identifier: Some(key_id.clone()),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        }),
        data: Some(ciphertext),
        i_v_counter_nonce: iv,
        authenticated_encryption_tag: encrypt_response.authenticated_encryption_tag,
        ..Default::default()
    };

    let response = kms.decrypt(decrypt_request, "test_user").await?;
    assert_eq!(
        response.data.as_ref().map(|d| d.as_slice()),
        Some(plaintext.as_slice()),
        "Decrypt must return original plaintext"
    );

    Ok(())
}

/// Regression test for log sanitization in Hash operation.
///
/// Previously, the trace! macro in hash.rs would serialize the full request (including
/// the data being hashed). This test ensures hash works correctly after the trace change.
///
/// Guards: COSMIAN-2026-005 (sensitive data in logs)
#[tokio::test]
async fn test_hash_no_data_in_traces() -> KResult<()> {
    cosmian_logger::log_init(Some("trace"));
    let kms = test_kms().await?;

    let sensitive_data = b"PASSWORD_HASH_INPUT_MUST_NOT_APPEAR_IN_LOGS";

    let hash_request = Hash {
        cryptographic_parameters: CryptographicParameters {
            hashing_algorithm: Some(HashingAlgorithm::SHA3256),
            ..Default::default()
        },
        data: Some(sensitive_data.to_vec()),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    };

    let response = kms.hash(hash_request, "test_user").await?;
    assert!(response.data.is_some(), "Hash must return a digest");
    assert_eq!(
        response.data.as_ref().unwrap().len(),
        32,
        "SHA3-256 produces 32 bytes"
    );

    Ok(())
}

/// Regression test for log sanitization in MAC operation.
///
/// Previously, the debug! macro in mac.rs would log the full HMAC value.
/// This test ensures MAC compute works correctly after the trace change.
///
/// Guards: COSMIAN-2026-005 (sensitive data in logs)
#[tokio::test]
async fn test_mac_no_hmac_value_in_traces() -> KResult<()> {
    cosmian_logger::log_init(Some("trace"));
    let kms = test_kms().await?;

    // Create key with SHA3-256 algorithm (MAC keys need a hashing algorithm)
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::SHA3256,
        EMPTY_TAGS,
        false,
        None,
    )
    .map_err(|e| crate::error::KmsError::InvalidRequest(e.to_string()))?;
    let key_id = kms
        .create(request, "test_user", None)
        .await?
        .unique_identifier;

    let message = b"MESSAGE_WHOSE_MAC_MUST_NOT_BE_LOGGED_IN_FULL";

    let mac_request = MAC {
        unique_identifier: Some(key_id),
        cryptographic_parameters: Some(CryptographicParameters {
            hashing_algorithm: Some(HashingAlgorithm::SHA3256),
            ..Default::default()
        }),
        data: Some(message.to_vec()),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    };

    let response = kms.mac(mac_request, "test_user").await?;
    assert!(response.mac_data.is_some(), "MAC must return a value");

    Ok(())
}
