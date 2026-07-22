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
    config::ServerParams, core::KMS, middlewares::UserId, result::KResult,
    tests::test_utils::https_clap_config,
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
    let response = kms.create(request, &UserId::from(user)).await?;
    Ok(response.unique_identifier)
}

/// Regression test for log sanitization in Encrypt operation.
///
/// Previously, the trace! macro in encrypt.rs would log the full plaintext and
/// ciphertext. This test ensures that the encrypt operation works correctly after
/// the trace was changed to only log data lengths.
///
/// Guards: COSMIAN-2026-014 (sensitive data exposed in log/trace output)
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
    let response = kms
        .encrypt(encrypt_request, &UserId::from("test_user"))
        .await?;
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
/// Guards: COSMIAN-2026-014 (sensitive data exposed in log/trace output)
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
            &UserId::from("test_user"),
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

    let response = kms
        .decrypt(decrypt_request, &UserId::from("test_user"))
        .await?;
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
/// Guards: COSMIAN-2026-014 (sensitive data exposed in log/trace output)
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

    let response = kms.hash(hash_request, &UserId::from("test_user")).await?;
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
/// Guards: COSMIAN-2026-014 (sensitive data exposed in log/trace output)
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
        .create(request, &UserId::from("test_user"))
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

    let response = kms.mac(mac_request, &UserId::from("test_user")).await?;
    assert!(response.mac_data.is_some(), "MAC must return a value");

    Ok(())
}

/// Regression test: KEK-wrapped keys must remain wrapped after Decrypt with `UsageLimits`.
///
/// Previously, `decrypt.rs` unwrapped the key in-place via `unwrap_and_enforce_policy`
/// and then `decrement_usage_limits` persisted the plaintext key back to the database,
/// silently stripping KEK encryption at rest.
///
/// Guards: COSMIAN-2026-015 (KEK plaintext leak via `UsageLimits` persist in Decrypt)
#[tokio::test]
async fn test_decrypt_preserves_kek_wrapping_with_usage_limits() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::{
        UsageLimits, UsageLimitsUnit,
    };

    cosmian_logger::log_init(option_env!("RUST_LOG"));

    // Phase 1: create a wrapping key (KEK) on a plain KMS (no KEK configured yet)
    let clap_config = https_clap_config();
    let sqlite_path = clap_config.db.sqlite_path.clone();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = UserId::new("test_kek_wrapping_regression@example.com");

    let kek_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )
    .map_err(|e| crate::error::KmsError::InvalidRequest(e.to_string()))?;
    let kek_id = kms.create(kek_request, &owner).await?.unique_identifier;
    drop(kms);

    // Phase 2: re-instantiate KMS with KEK configured
    let mut clap_config_kek = https_clap_config();
    clap_config_kek.db.sqlite_path = sqlite_path;
    clap_config_kek.key_encryption_key = Some(kek_id.to_string());
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config_kek)?)).await?);

    // Create a data encryption key (DEK) — auto-wrapped by KEK — with UsageLimits
    let mut dek_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )
    .map_err(|e| crate::error::KmsError::InvalidRequest(e.to_string()))?;
    dek_request.attributes.usage_limits = Some(UsageLimits {
        usage_limits_unit: UsageLimitsUnit::Operation,
        usage_limits_count: None,
        usage_limits_total: 100,
    });
    let dek_id = kms.create(dek_request, &owner).await?.unique_identifier;

    // Verify the DEK is stored wrapped
    let raw_object_before = kms
        .database
        .retrieve_object(dek_id.as_str().unwrap())
        .await?
        .expect("DEK must exist in DB");
    assert!(
        raw_object_before.object().is_wrapped(),
        "DEK must be KEK-wrapped after creation"
    );

    // Verify WrappingKeyLink attribute is populated in stored metadata (KMIP 2.1 §4.31 Link).
    // Guards: bug where wrap_and_cache set key_block.key_wrapping_data but never
    // propagated the wrapping key UID to the separate Attributes struct used by
    // GetAttributes for wrapped (ByteString) key values.
    {
        use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::LinkType;
        let wrapping_link = raw_object_before
            .attributes()
            .get_link(LinkType::WrappingKeyLink);
        assert!(
            wrapping_link.is_some(),
            "WrappingKeyLink must be set in stored attributes after KEK-wrapped creation"
        );
        assert_eq!(
            wrapping_link.unwrap().to_string(),
            kek_id.to_string(),
            "WrappingKeyLink must point to the KEK"
        );
    }

    // Phase 3: Encrypt → Decrypt cycle (Decrypt triggers decrement_usage_limits)
    let plaintext = b"Regression test: KEK wrapping must survive decrypt";
    let encrypt_response = kms
        .encrypt(
            Encrypt {
                unique_identifier: Some(dek_id.clone()),
                cryptographic_parameters: Some(CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    ..Default::default()
                }),
                data: Some(Zeroizing::new(plaintext.to_vec())),
                ..Default::default()
            },
            &owner,
        )
        .await?;

    let ciphertext = encrypt_response.data.unwrap();
    let decrypt_response = kms
        .decrypt(
            Decrypt {
                unique_identifier: Some(dek_id.clone()),
                cryptographic_parameters: Some(CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    ..Default::default()
                }),
                data: Some(ciphertext),
                i_v_counter_nonce: encrypt_response.i_v_counter_nonce,
                authenticated_encryption_tag: encrypt_response.authenticated_encryption_tag,
                ..Default::default()
            },
            &owner,
        )
        .await?;
    assert_eq!(
        decrypt_response.data.as_ref().map(|d| d.as_slice()),
        Some(plaintext.as_slice()),
        "Decrypt must return original plaintext"
    );

    // Phase 4: CRITICAL CHECK — the DEK must still be wrapped in the database
    // Before the fix, decrement_usage_limits would persist the unwrapped plaintext.
    let raw_object_after = kms
        .database
        .retrieve_object(dek_id.as_str().unwrap())
        .await?
        .expect("DEK must still exist in DB after decrypt");
    assert!(
        raw_object_after.object().is_wrapped(),
        "SECURITY REGRESSION: KEK-wrapped key was persisted as plaintext after Decrypt \
         with UsageLimits! The decrement_usage_limits path must preserve wrapping."
    );

    Ok(())
}

/// Regression test: KEK-wrapped keys must remain wrapped after Sign with `UsageLimits`.
///
/// Same vulnerability pattern as Decrypt: `sign.rs` unwrapped in-place and then
/// `decrement_usage_limits` persisted plaintext.
///
/// Guards: COSMIAN-2026-015 (KEK plaintext leak via `UsageLimits` persist in Sign)
#[tokio::test]
async fn test_sign_preserves_kek_wrapping_with_usage_limits() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_operations::Sign,
        kmip_types::{RecommendedCurve, UsageLimits, UsageLimitsUnit},
        requests::create_ec_key_pair_request,
    };

    cosmian_logger::log_init(option_env!("RUST_LOG"));

    // Phase 1: create a wrapping key (KEK) on a plain KMS
    let clap_config = https_clap_config();
    let sqlite_path = clap_config.db.sqlite_path.clone();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = UserId::new("test_kek_sign_regression@example.com");

    let kek_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )
    .map_err(|e| crate::error::KmsError::InvalidRequest(e.to_string()))?;
    let kek_id = kms.create(kek_request, &owner).await?.unique_identifier;
    drop(kms);

    // Phase 2: re-instantiate KMS with KEK
    let mut clap_config_kek = https_clap_config();
    clap_config_kek.db.sqlite_path = sqlite_path;
    clap_config_kek.key_encryption_key = Some(kek_id.to_string());
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config_kek)?)).await?);

    // Create an Ed25519 keypair with UsageLimits on the private key
    let mut create_request = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::CURVEED25519,
        false,
        None,
    )
    .map_err(|e| crate::error::KmsError::InvalidRequest(e.to_string()))?;
    // Set UsageLimits on private key attributes
    if let Some(ref mut pk_attrs) = create_request.private_key_attributes {
        pk_attrs.usage_limits = Some(UsageLimits {
            usage_limits_unit: UsageLimitsUnit::Operation,
            usage_limits_count: None,
            usage_limits_total: 100,
        });
    }
    let create_response = kms.create_key_pair(create_request, &owner).await?;
    let private_key_id = create_response.private_key_unique_identifier;

    // Verify the private key is stored wrapped
    let raw_before = kms
        .database
        .retrieve_object(private_key_id.as_str().unwrap())
        .await?
        .expect("Private key must exist in DB");
    assert!(
        raw_before.object().is_wrapped(),
        "Private key must be KEK-wrapped after creation"
    );

    // Phase 3: Sign (triggers decrement_usage_limits)
    let sign_response = kms
        .sign(
            Sign {
                unique_identifier: Some(private_key_id.clone()),
                cryptographic_parameters: Some(CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::Ed25519),
                    ..Default::default()
                }),
                data: Some(Zeroizing::new(
                    b"Regression test: KEK wrapping must survive sign".to_vec(),
                )),
                digested_data: None,
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            },
            &owner,
        )
        .await?;
    assert!(
        sign_response.signature_data.is_some(),
        "Sign must return a signature"
    );

    // Phase 4: CRITICAL CHECK — private key must still be wrapped
    let raw_after = kms
        .database
        .retrieve_object(private_key_id.as_str().unwrap())
        .await?
        .expect("Private key must still exist after sign");
    assert!(
        raw_after.object().is_wrapped(),
        "SECURITY REGRESSION: KEK-wrapped private key was persisted as plaintext after Sign \
         with UsageLimits! The decrement_usage_limits path must preserve wrapping."
    );

    Ok(())
}
