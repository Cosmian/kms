#![allow(clippy::unwrap_used, clippy::expect_used, clippy::as_conversions)]
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_client_utils::reexport::cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        extra::tagging::EMPTY_TAGS,
        kmip_attributes::Attributes,
        kmip_types::CryptographicAlgorithm,
        requests::{
            create_rsa_key_pair_request, create_symmetric_key_kmip_object, import_object_request,
            symmetric_key_create_request,
        },
    },
};
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_logger::{log_init, warn};

use crate::{
    config::ServerParams,
    core::KMS,
    result::KResult,
    routes::azure_ekm::{
        handlers::{unwrap_key_handler, wrap_key_handler},
        models::{RequestContext, UnwrapKeyRequest, WrapAlgorithm, WrapKeyRequest},
    },
    tests::test_utils::https_clap_config,
};

#[tokio::test]
async fn test_wrap_unwrap_error_cases() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    // INFO: I will take care of this one by adding the new code
    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "ekm_owner";

    // Test 1: Invalid Base64 URL encoding
    let req = symmetric_key_create_request(
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )
    .unwrap();
    let create_response = kms.create(req, owner, None).await.unwrap();
    let aes_kek_id = create_response.unique_identifier.to_string();

    // Test invalid base64url - contains invalid characters
    let invalid_wrap_request = WrapKeyRequest {
        request_context: RequestContext {
            request_id: Some("test-invalid-base64".to_owned()),
            correlation_id: "test-invalid-corr".to_owned(),
            pool_name: "test-pool".to_owned(),
        },
        alg: WrapAlgorithm::A256KW,
        value: "This!is@not#valid$base64url%".to_owned(), // Invalid characters
    };

    let wrap_result = wrap_key_handler(&kms, &aes_kek_id, owner, invalid_wrap_request).await;
    assert!(
        wrap_result.is_err(),
        "Wrap operation should fail with invalid base64url input"
    );

    // Test 2: Algorithm mismatch - Use AES key with RSA algorithm
    // we already created an AES KEK above
    let plaintext = hex::decode("00112233445566778899AABBCCDDEEFF").expect("valid hex");
    let algorithm_mismatch_request = WrapKeyRequest {
        request_context: RequestContext {
            request_id: Some("test-algorithm-mismatch".to_owned()),
            correlation_id: "test-mismatch-corr".to_owned(),
            pool_name: "test-pool".to_owned(),
        },
        alg: WrapAlgorithm::RsaOaep256, // AES algorithm
        value: URL_SAFE_NO_PAD.encode(&plaintext),
    };

    let mismatch_result =
        wrap_key_handler(&kms, &aes_kek_id, owner, algorithm_mismatch_request).await;

    assert!(
        mismatch_result.is_err(),
        "Wrap operation should fail when asking for a key that uses the wrong algorithm"
    );
    if let Err(e) = mismatch_result {
        // Check that error message indicates algorithm mismatch
        let error_msg = format!("{e:?}");
        assert!(
            error_msg.contains("algorithm")
                || error_msg.contains("Algorithm")
                || error_msg.contains("mismatch")
                || error_msg.contains("incompatible"),
            "Error should mention algorithm mismatch: {error_msg}"
        );
    }

    // Test 3: Non-existent key ID
    let nonexistent_key_id = "I-DO-NOT-EXIST-12345";
    let nonexistent_key_request = WrapKeyRequest {
        request_context: RequestContext {
            request_id: Some("test-nonexistent-key".to_owned()),
            correlation_id: "test-nonexistent-corr".to_owned(),
            pool_name: "test-pool".to_owned(),
        },
        alg: WrapAlgorithm::A256KW,
        value: URL_SAFE_NO_PAD.encode(&plaintext),
    };

    let nonexistent_result =
        wrap_key_handler(&kms, nonexistent_key_id, owner, nonexistent_key_request).await;

    assert!(
        nonexistent_result.is_err(),
        "Wrap operation should fail with non-existent key ID"
    );

    // Test 4: Empty values
    let empty_value_request = WrapKeyRequest {
        request_context: RequestContext {
            request_id: Some("test-empty-value".to_owned()),
            correlation_id: "test-empty-corr".to_owned(),
            pool_name: "test-pool".to_owned(),
        },
        alg: WrapAlgorithm::A256KW,
        value: String::new(), // Empty string
    };

    let empty_result = wrap_key_handler(&kms, &aes_kek_id, owner, empty_value_request).await;
    assert!(
        empty_result.is_err(),
        "Wrap operation should fail with empty value"
    );

    // Test 5: Invalid AES key size (spec only mentions 256 bits for A256KW/P)
    for al in [WrapAlgorithm::A256KW, WrapAlgorithm::A256KWP] {
        let invalid_key_sizes = [128, 192]; // bits
        for &size in &invalid_key_sizes {
            let req = symmetric_key_create_request(
                None,
                size,
                CryptographicAlgorithm::AES,
                EMPTY_TAGS,
                false,
                None,
            )
            .unwrap();
            let create_response = kms.create(req, owner, None).await.unwrap();
            let aes_kek_id = create_response.unique_identifier.to_string();

            let invalid_size_request = WrapKeyRequest {
                request_context: RequestContext {
                    request_id: Some(format!("test-invalid-key-size-{size:?}")),
                    correlation_id: format!("test-invalid-size-corr-{size:?}"),
                    pool_name: "test-pool".to_owned(),
                },
                alg: al.clone(),
                value: URL_SAFE_NO_PAD.encode(&plaintext),
            };

            let invalid_size_result =
                wrap_key_handler(&kms, &aes_kek_id, owner, invalid_size_request).await;

            assert!(
                invalid_size_result.is_err(),
                "Wrap operation should fail with invalid key size: {size} bits"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_wrap_unwrap_roundtrip_aes256_kw() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "ekm_owner";

    // RFC 3394 Section 4.6: Wrap 256 bits of Key Data with a 256-bit KEK
    let rfc_kek_bytes =
        hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
            .expect("valid hex");

    let rfc_plaintext_unwrapped_input =
        hex::decode("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
            .expect("valid hex");

    let rfc_expected_wrapped = hex::decode(
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
    )
    .expect("valid hex");

    let kek_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
        ),
        ..Default::default()
    };

    let kek_object = create_symmetric_key_kmip_object(&rfc_kek_bytes, &kek_attributes)?;

    // Use the helper function to create import request
    let import_request = import_object_request(
        Some("rfc3394-test-kek".to_owned()),
        kek_object,
        Some(kek_attributes),
        false,
        true,
        EMPTY_TAGS,
    )?;

    let import_response = kms.import(import_request, owner, None).await?;
    let kek_id = import_response.unique_identifier.to_string();

    let wrap_request = WrapKeyRequest {
        request_context: RequestContext {
            request_id: Some("test-aes-wrap".to_owned()),
            correlation_id: "test-aes-corr".to_owned(),
            pool_name: "test-pool".to_owned(),
        },
        alg: WrapAlgorithm::A256KW,
        value: URL_SAFE_NO_PAD.encode(&rfc_plaintext_unwrapped_input),
    };

    let wrap_response = wrap_key_handler(&kms, &kek_id, owner, wrap_request)
        .await
        .unwrap();
    let decoded_wrapped_key = URL_SAFE_NO_PAD.decode(&wrap_response.value)?;

    assert_eq!(
        decoded_wrapped_key, rfc_expected_wrapped,
        "Wrapped output must match RFC 3394 Section 4.6 test vector"
    );

    // Test unwrap operation (round-trip verification)
    let unwrap_request = UnwrapKeyRequest {
        request_context: RequestContext {
            request_id: Some("rfc3394-unwrap-test".to_owned()),
            correlation_id: "rfc3394-unwrap".to_owned(),
            pool_name: "test-pool".to_owned(),
        },
        alg: WrapAlgorithm::A256KW,
        value: wrap_response.value, // Use our wrapped result
    };

    let unwrap_response = unwrap_key_handler(&kms, &kek_id, owner, unwrap_request)
        .await
        .unwrap();
    let unwrapped = URL_SAFE_NO_PAD.decode(&unwrap_response.value)?;

    assert_eq!(
        unwrapped, rfc_plaintext_unwrapped_input,
        "Unwrapped key must match original RFC plaintext"
    );

    Ok(())
}

#[tokio::test]
async fn test_wrap_unwrap_roundtrip_aes256_kwp() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "ekm_owner";

    // For info, the rfc document has no test vector with a 256-bit KEK, so we generate our own
    for _ in 0..5 {
        let mut rng = CsRng::from_entropy();
        let mut rfc_kek_bytes = vec![0_u8; 32];
        rng.fill_bytes(&mut rfc_kek_bytes);

        // aes256_kwp can handle any plaintext size (unlike KW which requires multiples of 8 bytes)
        // we'll re-run multiple times to make sure sizes are handled correctly
        let plaintext_len = 8 + (rng.next_u32() as usize % 256);
        let mut rfc_plaintext_unwrapped_input = vec![0_u8; plaintext_len];
        rng.fill_bytes(&mut rfc_plaintext_unwrapped_input);

        let kek_attributes = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | { CryptographicUsageMask::Decrypt },
            ),
            ..Default::default()
        };

        let kek_object = create_symmetric_key_kmip_object(&rfc_kek_bytes, &kek_attributes)?;

        // Use the helper function to create import request
        let import_request = import_object_request(
            Some("test-kek".to_owned()),
            kek_object,
            Some(kek_attributes),
            false,
            true,
            EMPTY_TAGS,
        )
        .unwrap();

        let import_response = kms.import(import_request, owner, None).await?;
        let kek_id = import_response.unique_identifier.to_string();

        let wrap_request = WrapKeyRequest {
            request_context: RequestContext {
                request_id: Some("test-rsa-wrap".to_owned()),
                correlation_id: "test-rsa-corr".to_owned(),
                pool_name: "test-pool".to_owned(),
            },
            alg: WrapAlgorithm::A256KWP,
            value: URL_SAFE_NO_PAD.encode(&rfc_plaintext_unwrapped_input),
        };

        let wrap_response = wrap_key_handler(&kms, &kek_id, owner, wrap_request)
            .await
            .unwrap();

        // Test unwrap operation (round-trip verification)
        let unwrap_request = UnwrapKeyRequest {
            request_context: RequestContext {
                request_id: Some("unwrap-test".to_owned()),
                correlation_id: "unwrap".to_owned(),
                pool_name: "test-pool".to_owned(),
            },
            alg: WrapAlgorithm::A256KWP,
            value: wrap_response.value, // Use our wrapped result
        };

        let unwrap_response = unwrap_key_handler(&kms, &kek_id, owner, unwrap_request)
            .await
            .unwrap();
        let unwrapped = URL_SAFE_NO_PAD.decode(&unwrap_response.value)?;

        assert_eq!(
            unwrapped, rfc_plaintext_unwrapped_input,
            "Unwrapped key must match original RFC plaintext"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_wrap_unwrap_roundtrip_rsa_oaep_256() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let clap_config = https_clap_config();
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let owner = "ekm_owner";

    let create_keys = kms
        .create_key_pair(
            create_rsa_key_pair_request(None, Vec::<String>::new(), 2048, false, None)?,
            owner,
            None,
        )
        .await?;
    let key_id_private = create_keys.private_key_unique_identifier.to_string();
    warn!(
        "Created RSA key pair with Private Key ID: {}",
        key_id_private
    );

    let mut rng = CsRng::from_entropy();
    let plaintext_len = 1 + (rng.next_u32() as usize % 190); // OAEP with SHA-256 and 2048-bit key max
    let mut valid_random_plaintext = vec![0_u8; plaintext_len];
    rng.fill_bytes(&mut valid_random_plaintext);

    // Wrap with public key
    let wrap_request = WrapKeyRequest {
        request_context: RequestContext {
            request_id: Some("test-rsa-wrap".to_owned()),
            correlation_id: "test-rsa-corr".to_owned(),
            pool_name: "test-pool".to_owned(),
        },
        alg: WrapAlgorithm::RsaOaep256,
        value: URL_SAFE_NO_PAD.encode(&valid_random_plaintext),
    };

    let wrap_response = wrap_key_handler(&kms, &key_id_private, owner, wrap_request)
        .await
        .unwrap();

    assert!(
        URL_SAFE_NO_PAD.decode(&wrap_response.value).is_ok(),
        "Result should be base 64 encoded data"
    );

    // Test unwrap operation (round-trip verification)
    let unwrap_request = UnwrapKeyRequest {
        request_context: RequestContext {
            request_id: Some("rfc3394-unwrap-test".to_owned()),
            correlation_id: "rfc3394-unwrap".to_owned(),
            pool_name: "test-pool".to_owned(),
        },
        alg: WrapAlgorithm::RsaOaep256,
        value: wrap_response.value, // Use our wrapped result
    };

    let unwrap_response = unwrap_key_handler(&kms, &key_id_private, owner, unwrap_request)
        .await
        .unwrap();
    let unwrapped = URL_SAFE_NO_PAD.decode(&unwrap_response.value)?;

    assert_eq!(
        unwrapped, valid_random_plaintext,
        "Unwrapped test must match original plaintext"
    );

    Ok(())
}
