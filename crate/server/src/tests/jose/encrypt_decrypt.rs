//! AES-GCM encrypt/decrypt round-trip tests and AAD binding verification.

use actix_web::{http::StatusCode, test};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
    kmip_operations::CreateResponse,
    kmip_types::CryptographicAlgorithm,
    requests::symmetric_key_create_request,
};
use cosmian_logger::log_init;
use serde_json::{Value, json};

use crate::{result::KResult, tests::test_utils};

#[tokio::test]
async fn test_aes128gcm_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;
    super::common::aes_gcm_round_trip(&app, 128, "A128GCM").await
}

#[tokio::test]
async fn test_aes256gcm_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;
    super::common::aes_gcm_round_trip(&app, 256, "A256GCM").await
}

/// Encrypting with AAD and then decrypting with tampered AAD must fail.
#[tokio::test]
async fn test_aad_binding() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let create_req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let cr: CreateResponse = test_utils::post_2_1(&app, create_req).await?;
    let kid = cr.unique_identifier.to_string();

    let data_b64 = URL_SAFE_NO_PAD.encode(b"secret payload");
    let aad_b64 = URL_SAFE_NO_PAD.encode(b"associated-data");
    let wrong_aad_b64 = URL_SAFE_NO_PAD.encode(b"tampered-aad");

    let enc_resp: serde_json::Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "dir", "enc": "A256GCM", "data": data_b64, "aad": aad_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    // Correct AAD → success
    test_utils::post_json_with_uri::<_, _, serde_json::Value, _>(
        &app,
        json!({
            "protected":  enc_resp["protected"],
            "iv":         enc_resp["iv"],
            "ciphertext": enc_resp["ciphertext"],
            "tag":        enc_resp["tag"],
            "aad":        aad_b64
        }),
        "/v1/crypto/decrypt",
    )
    .await
    .expect("decrypt with correct AAD should succeed");

    // Wrong AAD → non-200
    let req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&json!({
            "protected":  enc_resp["protected"],
            "iv":         enc_resp["iv"],
            "ciphertext": enc_resp["ciphertext"],
            "tag":        enc_resp["tag"],
            "aad":        wrong_aad_b64
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "decrypt with wrong AAD should fail"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// RSA-OAEP single-roundtrip tests (RFC 7516 §A.1 pattern)
// ---------------------------------------------------------------------------

/// Basic RSA-OAEP (SHA-1) + A256GCM round-trip: encrypt via public key UID, decrypt.
#[tokio::test]
async fn test_rsa_oaep_a256gcm_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (_kid_priv, kid_pub) = super::common::create_rsa_key_pair_rest(&app).await?;

    let plaintext = b"RSA-OAEP/A256GCM test payload";
    let data_b64 = URL_SAFE_NO_PAD.encode(plaintext);

    let enc_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid_pub, "alg": "RSA-OAEP", "enc": "A256GCM", "data": data_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    // Wrapped CEK must be present (non-empty) for key-wrapping algorithms
    assert!(
        !enc_resp["encrypted_key"].as_str().unwrap_or("").is_empty(),
        "RSA-OAEP encrypted_key must be non-empty"
    );

    let dec_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({
            "protected":    enc_resp["protected"],
            "encrypted_key": enc_resp["encrypted_key"],
            "iv":           enc_resp["iv"],
            "ciphertext":   enc_resp["ciphertext"],
            "tag":          enc_resp["tag"]
        }),
        "/v1/crypto/decrypt",
    )
    .await?;

    let recovered = URL_SAFE_NO_PAD
        .decode(dec_resp["data"].as_str().expect("data field missing"))
        .expect("base64url decode failed");
    assert_eq!(recovered, plaintext);

    Ok(())
}

/// RSA-OAEP-256 (SHA-256) + A128GCM round-trip.
#[tokio::test]
async fn test_rsa_oaep_256_a128gcm_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (_kid_priv, kid_pub) = super::common::create_rsa_key_pair_rest(&app).await?;

    let plaintext = b"RSA-OAEP-256/A128GCM test payload";
    let data_b64 = URL_SAFE_NO_PAD.encode(plaintext);

    let enc_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid_pub, "alg": "RSA-OAEP-256", "enc": "A128GCM", "data": data_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    assert!(
        !enc_resp["encrypted_key"].as_str().unwrap_or("").is_empty(),
        "RSA-OAEP-256 encrypted_key must be non-empty"
    );

    let dec_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({
            "protected":    enc_resp["protected"],
            "encrypted_key": enc_resp["encrypted_key"],
            "iv":           enc_resp["iv"],
            "ciphertext":   enc_resp["ciphertext"],
            "tag":          enc_resp["tag"]
        }),
        "/v1/crypto/decrypt",
    )
    .await?;

    let recovered = URL_SAFE_NO_PAD
        .decode(dec_resp["data"].as_str().expect("data field missing"))
        .expect("base64url decode failed");
    assert_eq!(recovered, plaintext);

    Ok(())
}

/// Supplying the private key UID to encrypt must work (handler extracts/follows public key).
#[tokio::test]
async fn test_rsa_oaep_encrypt_with_private_kid() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (kid_priv, _kid_pub) = super::common::create_rsa_key_pair_rest(&app).await?;

    let plaintext = b"encrypt via private key UID";
    let data_b64 = URL_SAFE_NO_PAD.encode(plaintext);

    let enc_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid_priv, "alg": "RSA-OAEP", "enc": "A256GCM", "data": data_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    assert!(
        !enc_resp["encrypted_key"].as_str().unwrap_or("").is_empty(),
        "encrypted_key must be non-empty"
    );

    let dec_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({
            "protected":    enc_resp["protected"],
            "encrypted_key": enc_resp["encrypted_key"],
            "iv":           enc_resp["iv"],
            "ciphertext":   enc_resp["ciphertext"],
            "tag":          enc_resp["tag"]
        }),
        "/v1/crypto/decrypt",
    )
    .await?;

    let recovered = URL_SAFE_NO_PAD
        .decode(dec_resp["data"].as_str().expect("data field missing"))
        .expect("base64url decode failed");
    assert_eq!(recovered, plaintext);

    Ok(())
}

/// AAD is bound to the ciphertext: correct AAD decrypts; tampered AAD must fail.
#[tokio::test]
async fn test_rsa_oaep_aad_binding() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (_kid_priv, kid_pub) = super::common::create_rsa_key_pair_rest(&app).await?;

    let data_b64 = URL_SAFE_NO_PAD.encode(b"secret payload");
    let aad_b64 = URL_SAFE_NO_PAD.encode(b"context-data");
    let wrong_aad_b64 = URL_SAFE_NO_PAD.encode(b"tampered-context");

    let enc_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid_pub, "alg": "RSA-OAEP", "enc": "A256GCM",
               "data": data_b64, "aad": aad_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    // Correct AAD → success
    test_utils::post_json_with_uri::<_, _, Value, _>(
        &app,
        json!({
            "protected":    enc_resp["protected"],
            "encrypted_key": enc_resp["encrypted_key"],
            "iv":           enc_resp["iv"],
            "ciphertext":   enc_resp["ciphertext"],
            "tag":          enc_resp["tag"],
            "aad":          aad_b64
        }),
        "/v1/crypto/decrypt",
    )
    .await
    .expect("decrypt with correct AAD should succeed");

    // Tampered AAD → must fail (AES-GCM authentication tag covers the AAD)
    let req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&json!({
            "protected":    enc_resp["protected"],
            "encrypted_key": enc_resp["encrypted_key"],
            "iv":           enc_resp["iv"],
            "ciphertext":   enc_resp["ciphertext"],
            "tag":          enc_resp["tag"],
            "aad":          wrong_aad_b64
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "decrypt with tampered AAD must fail"
    );

    Ok(())
}

/// RSA-OAEP + A192GCM — verifies the 24-byte CEK path.
#[tokio::test]
async fn test_rsa_oaep_a192gcm_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (_kid_priv, kid_pub) = super::common::create_rsa_key_pair_rest(&app).await?;

    let plaintext = b"RSA-OAEP/A192GCM 24-byte CEK test";
    let data_b64 = URL_SAFE_NO_PAD.encode(plaintext);

    let enc_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid_pub, "alg": "RSA-OAEP", "enc": "A192GCM", "data": data_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    assert!(
        !enc_resp["encrypted_key"].as_str().unwrap_or("").is_empty(),
        "RSA-OAEP/A192GCM encrypted_key must be non-empty"
    );

    let dec_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({
            "protected":    enc_resp["protected"],
            "encrypted_key": enc_resp["encrypted_key"],
            "iv":           enc_resp["iv"],
            "ciphertext":   enc_resp["ciphertext"],
            "tag":          enc_resp["tag"]
        }),
        "/v1/crypto/decrypt",
    )
    .await?;

    let recovered = URL_SAFE_NO_PAD
        .decode(dec_resp["data"].as_str().expect("data field missing"))
        .expect("base64url decode failed");
    assert_eq!(recovered, plaintext);

    Ok(())
}
