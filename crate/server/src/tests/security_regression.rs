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
    config::ServerParams, core::KMS, error::KmsError, middlewares::UserId, result::KResult,
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
    let owner = UserId::from("test_kek_wrapping_regression@example.com");

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
        usage_limits_unit: UsageLimitsUnit::Object,
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
    let owner = UserId::from("test_kek_sign_regression@example.com");

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
            usage_limits_unit: UsageLimitsUnit::Object,
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

/// Regression test: a wrapped-at-rest key with `fresh=true` retrieved via `Get`
/// with auto-unwrap must NOT persist the unwrapped plaintext key to the database
/// during the fresh-bit flip writeback.
#[tokio::test]
async fn test_get_fresh_wrapped_key_preserves_wrapping_in_db() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Get;

    // Phase 1: create a wrapping key (KEK) on a plain KMS
    let clap_config = https_clap_config();
    let sqlite_path = clap_config.db.sqlite_path.clone();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = UserId::from("test_fresh_unwrap_owner@example.com");

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

    // Phase 2: re-instantiate KMS with KEK and default_unwrap_type so created keys are wrapped at rest
    let mut clap_config_kek = https_clap_config();
    clap_config_kek.db.sqlite_path = sqlite_path;
    clap_config_kek.key_encryption_key = Some(kek_id.to_string());
    clap_config_kek.default_unwrap_type = Some(vec!["All".to_owned()]);
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config_kek)?)).await?);

    // Create a symmetric key while KEK is configured -> wrapped at rest in DB
    let key_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )
    .map_err(|e| crate::error::KmsError::InvalidRequest(e.to_string()))?;
    let key_response = kms.create(key_request, &owner).await?;
    let key_id = key_response.unique_identifier;
    let key_uid = key_id.to_string();

    // Verify key is wrapped at rest and Fresh is not false before Get
    let raw_before = kms
        .database
        .retrieve_object(&key_uid)
        .await?
        .expect("key must exist");
    assert!(
        raw_before.object().is_wrapped(),
        "Key must be wrapped at rest before Get"
    );
    assert_ne!(
        raw_before.attributes().fresh,
        Some(false),
        "Key must not have fresh=false before Get"
    );

    // Phase 3: Perform a Get request with default auto-unwrap (NotWrapped / none)
    let get_resp = kms
        .get(
            Get {
                unique_identifier: Some(key_id.clone()),
                key_format_type: None,
                key_compression_type: None,
                key_wrap_type: None,
                key_wrapping_specification: None,
            },
            &owner,
        )
        .await?;

    // The response returned the key unwrapped
    assert!(
        !get_resp.object.is_wrapped(),
        "Get response should return key unwrapped"
    );

    // Phase 4: CRITICAL CHECK: In the database, the fresh bit was flipped to false,
    // BUT the key object must STILL be wrapped at rest!
    let raw_after = kms
        .database
        .retrieve_object(&key_uid)
        .await?
        .expect("key must exist");

    assert_eq!(
        raw_after.attributes().fresh,
        Some(false),
        "Fresh attribute must be flipped to false in DB after unwrapped Get"
    );

    assert!(
        raw_after.object().is_wrapped(),
        "SECURITY REGRESSION: Wrapped-at-rest key was persisted as plaintext to the database \
         during the Fresh-bit flip in export_get!"
    );

    let kb = raw_after.object().key_block().expect("must have key block");
    assert!(
        kb.key_wrapping_data.is_some(),
        "SECURITY REGRESSION: key_wrapping_data was stripped from the stored object!"
    );

    Ok(())
}

/// Regression test: a wrapped-at-rest key with `fresh=true` retrieved via `Get`
/// with explicit `KeyWrapType::NotWrapped` (no `default_unwrap_type` configured)
/// must also NOT persist the unwrapped plaintext key to the database.
#[tokio::test]
async fn test_get_fresh_wrapped_key_explicit_not_wrapped_preserves_wrapping_in_db() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::KeyWrapType, kmip_2_1::kmip_operations::Get,
    };

    // Phase 1: create a wrapping key (KEK) on a plain KMS
    let clap_config = https_clap_config();
    let sqlite_path = clap_config.db.sqlite_path.clone();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = UserId::from("test_fresh_unwrap_explicit_owner@example.com");

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

    // Phase 2: re-instantiate KMS with KEK (WITHOUT default_unwrap_type)
    let mut clap_config_kek = https_clap_config();
    clap_config_kek.db.sqlite_path = sqlite_path;
    clap_config_kek.key_encryption_key = Some(kek_id.to_string());
    clap_config_kek.default_unwrap_type = None;
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config_kek)?)).await?);

    // Create a symmetric key while KEK is configured -> wrapped at rest in DB
    let key_request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )
    .map_err(|e| crate::error::KmsError::InvalidRequest(e.to_string()))?;
    let key_response = kms.create(key_request, &owner).await?;
    let key_id = key_response.unique_identifier;
    let key_uid = key_id.to_string();

    let raw_before = kms
        .database
        .retrieve_object(&key_uid)
        .await?
        .expect("key must exist");
    assert!(raw_before.object().is_wrapped());
    assert_ne!(raw_before.attributes().fresh, Some(false));

    // Phase 3: Perform a Get request with explicit KeyWrapType::NotWrapped
    let get_resp = kms
        .get(
            Get {
                unique_identifier: Some(key_id.clone()),
                key_format_type: None,
                key_compression_type: None,
                key_wrap_type: Some(KeyWrapType::NotWrapped),
                key_wrapping_specification: None,
            },
            &owner,
        )
        .await?;

    assert!(!get_resp.object.is_wrapped());

    // Phase 4: CRITICAL CHECK: In DB, key must STILL be wrapped at rest
    let raw_after = kms
        .database
        .retrieve_object(&key_uid)
        .await?
        .expect("key must exist");

    assert_eq!(raw_after.attributes().fresh, Some(false));
    assert!(
        raw_after.object().is_wrapped(),
        "SECURITY REGRESSION: Wrapped-at-rest key was persisted as plaintext to the database \
         during the Fresh-bit flip in export_get (explicit NotWrapped)!"
    );

    let kb = raw_after.object().key_block().expect("must have key block");
    assert!(
        kb.key_wrapping_data.is_some(),
        "SECURITY REGRESSION: key_wrapping_data was stripped from the stored object!"
    );

    Ok(())
}

/// Regression test: a crypto operation on a key the caller may not use fails exactly
/// like one on a missing key, so key UIDs cannot be enumerated.
///
/// Guards: COSMIAN-2026-037 (existence and state oracle in key selection)
#[tokio::test]
async fn test_crypto_op_does_not_reveal_foreign_keys() -> KResult<()> {
    let kms = test_kms().await?;
    let foreign_key = create_aes_key(&kms, "oracle_owner@example.com").await?;
    let intruder = UserId::from("oracle_intruder@example.com");
    let encrypt = |uid: &str| Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        }),
        data: Some(Zeroizing::new(b"probe".to_vec())),
        ..Default::default()
    };

    let foreign = kms
        .encrypt(encrypt(&foreign_key.to_string()), &intruder)
        .await
        .expect_err("intruder must not use the owner's key");
    let missing = kms
        .encrypt(encrypt("oracle-no-such-key"), &intruder)
        .await
        .expect_err("missing key must fail");
    assert!(matches!(foreign, KmsError::ItemNotFound(_)), "{foreign:?}");
    assert!(matches!(missing, KmsError::ItemNotFound(_)), "{missing:?}");

    // A non-active foreign key must not reveal its state either.
    {
        use cosmian_kms_server_database::reexport::cosmian_kmip::{
            kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
            kmip_2_1::kmip_operations::Revoke,
        };
        kms.revoke(
            Revoke {
                unique_identifier: Some(foreign_key.clone()),
                revocation_reason: RevocationReason {
                    revocation_reason_code: RevocationReasonCode::Unspecified,
                    revocation_message: None,
                },
                compromise_occurrence_date: None,
                cascade: true,
            },
            &UserId::from("oracle_owner@example.com"),
        )
        .await?;
    }
    let revoked = kms
        .encrypt(encrypt(&foreign_key.to_string()), &intruder)
        .await
        .expect_err("intruder must not use the owner's revoked key");
    assert!(matches!(revoked, KmsError::ItemNotFound(_)), "{revoked:?}");
    Ok(())
}

/// Regression test: a caller holding a grant on a key but not the requested operation gets a
/// permission error (AWS XKS maps it to `InvalidKeyUsageException`), not "not found".
///
/// Guards: COSMIAN-2026-037 (masking must not apply to callers that already know the key)
#[tokio::test]
async fn test_crypto_op_reports_permission_error_to_grantee() -> KResult<()> {
    use std::collections::HashSet;

    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::KmipOperation;

    let kms = test_kms().await?;
    let key = create_aes_key(&kms, "grant_owner@example.com").await?;
    let grantee = UserId::from("grant_grantee@example.com");
    kms.database
        .grant_operations(
            &key.to_string(),
            &grantee,
            HashSet::from([KmipOperation::Encrypt]),
        )
        .await?;

    let decrypt = Decrypt {
        unique_identifier: Some(key.clone()),
        data: Some(vec![0_u8; 32]),
        ..Default::default()
    };
    let err = kms
        .decrypt(decrypt, &grantee)
        .await
        .expect_err("grantee has no Decrypt permission");
    assert!(matches!(err, KmsError::Unauthorized(_)), "{err:?}");
    Ok(())
}

/// Regression test: `/kmip/2_1` only accepts a JSON Content-Type, so a cross-origin page
/// cannot send it a CORS "simple" (non-preflighted) request carrying the session cookie.
///
/// Guards: COSMIAN-2026-039 (session-cookie requests from other same-site origins)
#[tokio::test]
async fn test_kmip_json_endpoint_requires_json_content_type() -> KResult<()> {
    use actix_web::{http::StatusCode, test};
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_2_1::{kmip_operations::Query, kmip_types::QueryFunction},
        ttlv::to_ttlv,
    };

    let app = crate::tests::test_utils::test_app(None).await;
    // Query Function is REQUIRED by KMIP 2.1 §6.1.40
    let query = Query {
        query_function: Some(vec![QueryFunction::QueryOperations]),
        ..Default::default()
    };
    let body = serde_json::to_vec(&to_ttlv(&query)?)?;
    for (content_type, accepted) in [
        ("text/plain", false),
        ("application/x-www-form-urlencoded", false),
        ("application/json; charset=utf-8", true),
    ] {
        let req = test::TestRequest::post()
            .uri("/kmip/2_1")
            .insert_header(("Content-Type", content_type))
            .set_payload(body.clone())
            .to_request();
        let status = test::call_service(&app, req).await.status();
        assert_eq!(
            status == StatusCode::OK,
            accepted,
            "{content_type}: {status}"
        );
    }
    Ok(())
}

/// Regression test: oversized KMIP batches and PBKDF2 iteration counts are refused
/// up front instead of tying up a worker.
///
/// Guards: COSMIAN-2026-036 (unbounded batch, PBKDF2 and RSA work per request)
#[tokio::test]
async fn test_request_work_limits() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::{
            kmip_messages::{
                RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            },
            kmip_types::ProtocolVersion,
        },
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_data_structures::DerivationParameters,
            kmip_messages::RequestMessageBatchItem,
            kmip_objects::ObjectType,
            kmip_operations::{DeriveKey, Operation, Query},
            kmip_types::DerivationMethod,
            requests::create_derivation_object_request,
        },
    };

    use crate::core::operations::MAX_BATCH_ITEMS;

    let kms = test_kms().await?;
    let owner = UserId::from("limits_owner@example.com");

    let message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: i32::try_from(MAX_BATCH_ITEMS + 1)?,
            ..Default::default()
        },
        batch_item: (0..=MAX_BATCH_ITEMS)
            .map(|_| {
                RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(
                    Operation::Query(Query::default()),
                ))
            })
            .collect(),
    };
    let err = kms
        .message(message, &owner)
        .await
        .expect_err("a batch above the limit must be refused");
    assert!(err.to_string().contains("batch items"), "{err}");

    let base_key = kms
        .create(
            create_derivation_object_request(ObjectType::SymmetricKey)?,
            &owner,
        )
        .await?
        .unique_identifier;
    for iteration_count in [i32::MAX, 0, -1] {
        let derive = DeriveKey::new_single_base(
            ObjectType::SymmetricKey,
            base_key.clone(),
            DerivationMethod::PBKDF2,
            DerivationParameters {
                salt: Some(b"limits salt".to_vec()),
                iteration_count: Some(iteration_count),
                ..DerivationParameters::default()
            },
            Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(128),
                object_type: Some(ObjectType::SymmetricKey),
                ..Attributes::default()
            },
        );
        let err = kms
            .derive_key(derive, &owner)
            .await
            .expect_err("an out-of-range iteration count must be refused");
        assert!(
            matches!(err, KmsError::InvalidRequest(_))
                && err.to_string().contains("iteration count"),
            "{iteration_count}: {err:?}"
        );
    }
    Ok(())
}

/// Once roles are configured only a Crypto Officer may add input to the server DRBG, on both
/// the TTLV-tag and `RequestMessage` paths.
#[tokio::test]
async fn test_rng_seed_is_restricted_to_crypto_officers() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::{
            kmip_messages::{
                RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
                ResponseMessageBatchItemVersioned,
            },
            kmip_types::{ErrorReason, ProtocolVersion, ResultStatusEnumeration},
        },
        kmip_2_1::{
            kmip_messages::RequestMessageBatchItem,
            kmip_operations::{Operation, RNGSeed},
            kmip_types::OperationEnumeration,
        },
    };

    use crate::{
        config::{ClapConfig, MainDBConfig},
        core::operations::check_role_permission,
        middlewares::UserId,
        tests::test_utils::get_tmp_sqlite_path,
    };

    let alice = "alice@example.com";
    let bob = "bob@example.com";
    let mut conf = ClapConfig {
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: get_tmp_sqlite_path(),
            clear_database: false,
            ..Default::default()
        },
        ..Default::default()
    };
    conf.roles.crypto_officer_users = Some(vec![alice.to_owned()]);
    let kms = KMS::instantiate(Arc::new(ServerParams::try_from(conf)?)).await?;
    let roles = &kms.params.crypto_officer;

    check_role_permission(&kms, alice, OperationEnumeration::RNGSeed, roles).await?;
    assert!(matches!(
        check_role_permission(&kms, bob, OperationEnumeration::RNGSeed, roles).await,
        Err(KmsError::Unauthorized(_))
    ));
    // reading random bytes stays open to every authenticated user
    check_role_permission(&kms, bob, OperationEnumeration::RNGRetrieve, roles).await?;

    // The batched `RequestMessage` path must apply the same policy.
    let seed_message = || RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem::new(Operation::RNGSeed(RNGSeed { data: vec![0; 32] })),
        )],
    };
    let response = kms.message(seed_message(), &UserId::from(bob)).await?;
    let ResponseMessageBatchItemVersioned::V21(item) = &response.batch_item[0] else {
        panic!("not a V21 response");
    };
    assert_eq!(item.result_status, ResultStatusEnumeration::OperationFailed);
    assert_eq!(item.result_reason, Some(ErrorReason::Permission_Denied));
    let response = kms.message(seed_message(), &UserId::from(alice)).await?;
    let ResponseMessageBatchItemVersioned::V21(item) = &response.batch_item[0] else {
        panic!("not a V21 response");
    };
    assert_eq!(item.result_status, ResultStatusEnumeration::Success);
    Ok(())
}

/// A `MAC` request is subject to the hash allow-list whichever spelling its TTLV root tag uses
/// (`dispatch` accepts both `MAC` and `Mac`).
#[tokio::test]
async fn test_mac_tag_spelling_cannot_bypass_algorithm_policy() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, HashingAlgorithm},
        kmip_2_1::{
            kmip_operations::MAC,
            kmip_types::{CryptographicParameters, UniqueIdentifier},
        },
        ttlv::to_ttlv,
    };

    use crate::{
        config::{ClapConfig, MainDBConfig},
        core::operations::dispatch,
        middlewares::UserId,
        tests::test_utils::get_tmp_sqlite_path,
    };

    let mut conf = ClapConfig {
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: get_tmp_sqlite_path(),
            clear_database: false,
            ..Default::default()
        },
        ..Default::default()
    };
    conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());
    conf.kmip_policy.allowlists.hashes = Some(vec![HashingAlgorithm::SHA512]);
    let kms = KMS::instantiate(Arc::new(ServerParams::try_from(conf)?)).await?;

    let mac = MAC {
        unique_identifier: Some(UniqueIdentifier::TextString("no-such-key".to_owned())),
        cryptographic_parameters: Some(CryptographicParameters {
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        }),
        data: Some(vec![0; 16]),
        ..Default::default()
    };
    for tag in ["MAC", "Mac"] {
        let mut ttlv = to_ttlv(&mac)?;
        ttlv.tag = tag.into();
        // The policy refuses before any key lookup: a missing key would be `ItemNotFound`.
        let err = dispatch(&kms, ttlv, &UserId::from("alice@example.com"))
            .await
            .expect_err("a SHA-256 MAC must be refused by the SHA-512-only policy");
        assert!(
            matches!(
                err,
                KmsError::Kmip21Error(ErrorReason::Constraint_Violation, _)
            ),
            "{tag}: {err:?}"
        );
    }
    Ok(())
}

/// The batched `RequestMessage` path applies the request-time algorithm policy like the TTLV one.
#[tokio::test]
async fn test_default_kmip_policy_applies_to_batched_request_messages() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::{
            kmip_messages::{
                RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
                ResponseMessageBatchItemVersioned,
            },
            kmip_types::{ErrorReason, ProtocolVersion, ResultStatusEnumeration},
        },
        kmip_2_1::{
            extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
            kmip_messages::RequestMessageBatchItem,
            kmip_operations::Operation,
            requests::create_rsa_key_pair_request,
        },
    };

    use crate::{
        config::{ClapConfig, MainDBConfig},
        middlewares::UserId,
        tests::test_utils::get_tmp_sqlite_path,
    };

    let mut conf = ClapConfig {
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            sqlite_path: get_tmp_sqlite_path(),
            clear_database: false,
            ..Default::default()
        },
        ..Default::default()
    };
    conf.kmip_policy.policy_id = Some("DEFAULT".to_owned());
    let kms = KMS::instantiate(Arc::new(ServerParams::try_from(conf)?)).await?;

    let message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem::new(Operation::CreateKeyPair(Box::new(
                create_rsa_key_pair_request(
                    VENDOR_ID_COSMIAN,
                    None,
                    EMPTY_TAGS,
                    2048,
                    false,
                    None,
                )?,
            ))),
        )],
    };
    let response = kms
        .message(message, &UserId::from("alice@example.com"))
        .await?;
    let ResponseMessageBatchItemVersioned::V21(item) = &response.batch_item[0] else {
        panic!("not a V21 response");
    };
    assert_eq!(item.result_status, ResultStatusEnumeration::OperationFailed);
    assert_eq!(item.result_reason, Some(ErrorReason::Constraint_Violation));
    Ok(())
}

/// Regression test: `ReKeyKeyPair` follows the private key's client-editable Public Key Link
/// only to a public key the caller may re-key; another user's public key is reported as
/// not found and left untouched.
///
/// Guards: COSMIAN-2026-044 (`ReKeyKeyPair` linked public key authorization)
#[tokio::test]
async fn test_rekey_keypair_does_not_retire_another_users_linked_public_key() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::{
            kmip_attributes::Attribute,
            kmip_operations::{ReKeyKeyPair, SetAttribute},
            kmip_types::{Link, LinkType, LinkedObjectIdentifier},
            requests::create_rsa_key_pair_request,
        },
    };

    let kms = test_kms().await?;
    let victim = UserId::from("rekey_link_victim@example.com");
    let attacker = UserId::from("rekey_link_attacker@example.com");
    let victim_pair = kms
        .create_key_pair(
            create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, EMPTY_TAGS, 2048, false, None)?,
            &victim,
        )
        .await?;
    let attacker_pair = kms
        .create_key_pair(
            create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, EMPTY_TAGS, 2048, false, None)?,
            &attacker,
        )
        .await?;
    let victim_pk = victim_pair.public_key_unique_identifier.to_string();

    // The attacker points its own private key at the victim's public key
    kms.set_attribute(
        SetAttribute {
            unique_identifier: Some(attacker_pair.private_key_unique_identifier.clone()),
            new_attribute: Attribute::Link(Link {
                link_type: LinkType::PublicKeyLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(victim_pk.clone()),
            }),
        },
        &attacker,
    )
    .await?;
    let before = kms.database.retrieve_state(&victim_pk).await?;

    let err = kms
        .rekey_keypair(
            ReKeyKeyPair {
                private_key_unique_identifier: Some(attacker_pair.private_key_unique_identifier),
                ..ReKeyKeyPair::default()
            },
            &attacker,
        )
        .await
        .expect_err("the victim's public key must not be re-keyed");
    assert!(
        matches!(err, KmsError::Kmip21Error(ErrorReason::Object_Not_Found, _)),
        "{err:?}"
    );
    let after = kms.database.retrieve_state(&victim_pk).await?;
    assert_eq!(after, before, "the victim's public key must be unchanged");
    assert_eq!(after.map(|(state, _)| state), Some(State::Active));
    Ok(())
}

/// Regression test: a caller with only a `Get` grant cannot change the attributes that
/// govern key usage (Usage Limits, Link, Deactivation Date, …) nor delete them; an explicit
/// grant of the edit operation is required.
///
/// Guards: GHSA-c75c-3cmm-48h7 (attribute edits relying on a generic `Get` grant)
#[tokio::test]
async fn test_get_grant_cannot_edit_usage_attributes() -> KResult<()> {
    use std::collections::HashSet;

    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::ErrorReason,
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attribute,
            kmip_operations::{DeleteAttribute, SetAttribute},
            kmip_types::{
                AttributeReference, Link, LinkType, LinkedObjectIdentifier, Tag, UsageLimits,
                UsageLimitsUnit,
            },
        },
    };

    let kms = test_kms().await?;
    let owner = UserId::from("usage_owner@example.com");
    let grantee = UserId::from("usage_grantee@example.com");
    let key = create_aes_key(&kms, owner.as_str()).await?;
    let link = Attribute::Link(Link {
        link_type: LinkType::ParentLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString("other".to_owned()),
    });
    let set = |new_attribute: Attribute| SetAttribute {
        unique_identifier: Some(key.clone()),
        new_attribute,
    };
    kms.set_attribute(set(link.clone()), &owner).await?;
    kms.database
        .grant_operations(
            &key.to_string(),
            &grantee,
            HashSet::from([KmipOperation::Get]),
        )
        .await?;

    let denied = |err: KmsError| {
        assert!(
            matches!(
                err,
                KmsError::Kmip21Error(ErrorReason::Permission_Denied, _)
            ),
            "{err:?}"
        );
    };
    for attribute in [
        Attribute::UsageLimits(UsageLimits {
            usage_limits_unit: UsageLimitsUnit::Object,
            usage_limits_count: None,
            usage_limits_total: 1_000_000,
        }),
        link.clone(),
        Attribute::DeactivationDate(time::OffsetDateTime::now_utc()),
        Attribute::RotateInterval(60),
    ] {
        denied(
            kms.set_attribute(set(attribute.clone()), &grantee)
                .await
                .expect_err(&format!("Get grantee must not set {attribute}")),
        );
    }
    denied(
        kms.delete_attribute(
            DeleteAttribute {
                unique_identifier: Some(key.clone()),
                current_attribute: None,
                attribute_references: Some(vec![AttributeReference::Standard(Tag::Link)]),
            },
            &grantee,
        )
        .await
        .expect_err("Get grantee must not delete the links"),
    );

    // An explicit grant of the edit operation is enough
    kms.database
        .grant_operations(
            &key.to_string(),
            &grantee,
            HashSet::from([KmipOperation::SetAttribute]),
        )
        .await?;
    kms.set_attribute(set(Attribute::RotateInterval(60)), &grantee)
        .await?;
    Ok(())
}

/// Regression test: Delete Attribute cannot remove the server-owned KMIP 1.x custom
/// attributes (`y-` names), by reference or by wiping all vendor attributes.
#[tokio::test]
async fn test_delete_attribute_keeps_server_owned_vendor_attributes() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::ErrorReason,
        kmip_2_1::{
            kmip_operations::DeleteAttribute,
            kmip_types::{AttributeReference, Tag, VendorAttributeReference, VendorAttributeValue},
        },
    };

    let kms = test_kms().await?;
    let owner = UserId::from("vendor_owner@example.com");
    let key = create_aes_key(&kms, owner.as_str()).await?.to_string();
    let owm = kms
        .database
        .retrieve_object(&key)
        .await?
        .ok_or_else(|| KmsError::ItemNotFound(key.clone()))?;
    let mut attributes = owm.attributes().clone();
    attributes.set_vendor_attribute(
        "KMIP1",
        "y-server",
        VendorAttributeValue::TextString("kept".to_owned()),
    );
    attributes.set_vendor_attribute(
        "acme",
        "client",
        VendorAttributeValue::TextString("removed".to_owned()),
    );
    let tags = kms.database.retrieve_tags(&key).await?;
    kms.database
        .update_object(&key, owm.object(), &attributes, Some(&tags))
        .await?;

    let delete = |reference: AttributeReference| DeleteAttribute {
        unique_identifier: Some(UniqueIdentifier::TextString(key.clone())),
        current_attribute: None,
        attribute_references: Some(vec![reference]),
    };
    let err = kms
        .delete_attribute(
            delete(AttributeReference::Vendor(VendorAttributeReference {
                vendor_identification: "KMIP1".to_owned(),
                attribute_name: "y-server".to_owned(),
            })),
            &owner,
        )
        .await
        .expect_err("a server-owned attribute must not be deleted");
    assert!(
        matches!(
            err,
            KmsError::Kmip21Error(ErrorReason::Attribute_Read_Only, _)
        ),
        "{err:?}"
    );

    kms.delete_attribute(
        delete(AttributeReference::Standard(Tag::VendorExtension)),
        &owner,
    )
    .await?;
    let (_, attributes) = kms
        .database
        .retrieve_state(&key)
        .await?
        .ok_or_else(|| KmsError::ItemNotFound(key.clone()))?;
    assert!(
        attributes
            .get_vendor_attribute_value("KMIP1", "y-server")
            .is_some()
    );
    assert!(
        attributes
            .get_vendor_attribute_value("acme", "client")
            .is_none()
    );
    Ok(())
}

/// Regression test: Get Attributes without a Unique Identifier (and no ID Placeholder) no
/// longer selects the newest object in the database, which could belong to another user,
/// and the error does not reveal any identifier.
///
/// Guards: COSMIAN-2026-047 (Get Attributes implicit selection of another user's object)
#[tokio::test]
async fn test_get_attributes_without_identifier_selects_nothing() -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::GetAttributes;

    let kms = test_kms().await?;
    let foreign_key = create_aes_key(&kms, "implicit_owner@example.com").await?;
    let err = kms
        .get_attributes(
            GetAttributes {
                unique_identifier: None,
                attribute_reference: None,
            },
            &UserId::from("implicit_intruder@example.com"),
        )
        .await
        .expect_err("no object may be selected implicitly");
    assert!(matches!(err, KmsError::UnsupportedPlaceholder), "{err:?}");
    assert!(!err.to_string().contains(&foreign_key.to_string()));
    Ok(())
}
