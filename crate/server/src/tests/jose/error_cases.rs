//! Error-path tests: unknown algorithms, bad key IDs, wrong key types.

use actix_web::{http::StatusCode, test};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
    kmip_operations::CreateResponse,
    kmip_types::CryptographicAlgorithm,
    requests::symmetric_key_create_request,
};
use cosmian_logger::log_init;
use serde_json::json;

use crate::{result::KResult, tests::test_utils};

#[tokio::test]
async fn test_unknown_encrypt_alg_returns_422() -> KResult<()> {
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

    let req = test::TestRequest::post()
        .uri("/v1/crypto/encrypt")
        .set_json(&json!({"kid": kid, "alg": "A128KW", "enc": "A256GCM", "data": "dGVzdA"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    // With typed JoseAlgorithm enum, unknown alg values are rejected at
    // serde deserialization time (400 Bad Request) rather than at handler
    // level (422). This is expected — the enum enforces valid values.
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unsupported alg should return 400 (serde rejects unknown enum variant)"
    );
    Ok(())
}

#[tokio::test]
async fn test_unknown_sign_alg_returns_422() -> KResult<()> {
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

    let req = test::TestRequest::post()
        .uri("/v1/crypto/sign")
        .set_json(&json!({"kid": kid, "alg": "XYZ-UNKNOWN", "data": "dGVzdA"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    // With typed JoseAlgorithm enum, unknown alg values are rejected at
    // serde deserialization time (400 Bad Request) rather than at handler
    // level (422). This is expected — the enum enforces valid values.
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unsupported alg should return 400 (serde rejects unknown enum variant)"
    );
    Ok(())
}

#[tokio::test]
async fn test_nonexistent_key_id() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let req = test::TestRequest::post()
        .uri("/v1/crypto/encrypt")
        .set_json(&json!({
            "kid": "00000000-0000-0000-0000-000000000000",
            "alg": "dir",
            "enc": "A256GCM",
            "data": "dGVzdA"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_client_error(),
        "nonexistent key should return 4xx, got {}",
        resp.status()
    );
    Ok(())
}

#[tokio::test]
async fn test_wrong_key_type_for_sign() -> KResult<()> {
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

    let req = test::TestRequest::post()
        .uri("/v1/crypto/sign")
        .set_json(&json!({"kid": kid, "alg": "RS256", "data": "dGVzdA"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        !resp.status().is_success(),
        "AES key used for RS256 sign should fail, got {}",
        resp.status()
    );
    Ok(())
}

/// RFC 7515 §4.1.1 / RFC 8725 §2.1: `alg: "none"` must be explicitly rejected.
#[tokio::test]
async fn test_alg_none_returns_422() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    // Build a protected header with alg=none and a valid kid
    let protected_json = r#"{"alg":"none","kid":"any-key"}"#;
    let protected_b64 = URL_SAFE_NO_PAD.encode(protected_json.as_bytes());
    let data_b64 = URL_SAFE_NO_PAD.encode(b"payload");
    let sig_b64 = URL_SAFE_NO_PAD.encode(b"");

    let req = test::TestRequest::post()
        .uri("/v1/crypto/verify")
        .set_json(&json!({
            "protected": protected_b64,
            "data": data_b64,
            "signature": sig_b64
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "alg 'none' must be rejected with 422"
    );
    Ok(())
}

/// GCM IV must be exactly 12 bytes (96 bits).
#[tokio::test]
async fn test_decrypt_invalid_iv_length_returns_400() -> KResult<()> {
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

    // Encrypt normally to get a valid ciphertext+tag, then tamper the IV length
    let data_b64 = URL_SAFE_NO_PAD.encode(b"test");
    let enc_resp: serde_json::Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "dir", "enc": "A256GCM", "data": data_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    // Use a 16-byte IV (invalid — must be 12)
    let bad_iv = URL_SAFE_NO_PAD.encode([0_u8; 16]);

    let req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&json!({
            "protected":  enc_resp["protected"],
            "iv":         bad_iv,
            "ciphertext": enc_resp["ciphertext"],
            "tag":        enc_resp["tag"]
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "non-12-byte IV must be rejected with 400"
    );
    Ok(())
}

/// GCM authentication tag must be exactly 16 bytes (128 bits).
#[tokio::test]
async fn test_decrypt_short_tag_returns_400() -> KResult<()> {
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

    let data_b64 = URL_SAFE_NO_PAD.encode(b"test");
    let enc_resp: serde_json::Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "dir", "enc": "A256GCM", "data": data_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    // Use a truncated 8-byte tag (invalid — must be 16)
    let short_tag = URL_SAFE_NO_PAD.encode([0_u8; 8]);

    let req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&json!({
            "protected":  enc_resp["protected"],
            "iv":         enc_resp["iv"],
            "ciphertext": enc_resp["ciphertext"],
            "tag":        short_tag
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "truncated GCM tag must be rejected with 400"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// RSA-OAEP error-path tests
// ---------------------------------------------------------------------------

/// RSA-OAEP protected header with no `encrypted_key` (or empty) must be rejected 400.
#[tokio::test]
async fn test_rsa_oaep_decrypt_missing_encrypted_key() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (kid_priv, _kid_pub) = super::common::create_rsa_key_pair_rest(&app).await?;

    // Craft a valid RSA-OAEP protected header pointing at the private key
    let protected_json = format!(r#"{{"alg":"RSA-OAEP","enc":"A256GCM","kid":"{kid_priv}"}}"#);
    let protected_b64 = URL_SAFE_NO_PAD.encode(protected_json.as_bytes());

    let req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&json!({
            "protected":    protected_b64,
            "encrypted_key": "",          // empty — must be rejected
            "iv":           URL_SAFE_NO_PAD.encode([0_u8; 12]),
            "ciphertext":   URL_SAFE_NO_PAD.encode(b"fake"),
            "tag":          URL_SAFE_NO_PAD.encode([0_u8; 16])
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "RSA-OAEP decrypt with empty encrypted_key must return 400"
    );
    Ok(())
}

/// Flipping one bit of the wrapped CEK triggers implicit rejection (RFC 7516 §11.5):
/// the server substitutes a random CEK and AES-GCM authentication then fails → 422.
#[tokio::test]
async fn test_rsa_oaep_decrypt_tampered_encrypted_key() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (_kid_priv, kid_pub) = super::common::create_rsa_key_pair_rest(&app).await?;

    let data_b64 = URL_SAFE_NO_PAD.encode(b"tamper target");
    let enc_resp: serde_json::Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid_pub, "alg": "RSA-OAEP", "enc": "A256GCM", "data": data_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    // Flip the first byte of the wrapped CEK to corrupt it
    let mut ek_bytes = URL_SAFE_NO_PAD
        .decode(enc_resp["encrypted_key"].as_str().expect("encrypted_key"))
        .expect("base64url decode");
    ek_bytes[0] ^= 0xFF;
    let tampered_ek = URL_SAFE_NO_PAD.encode(&ek_bytes);

    let req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&json!({
            "protected":    enc_resp["protected"],
            "encrypted_key": tampered_ek,
            "iv":           enc_resp["iv"],
            "ciphertext":   enc_resp["ciphertext"],
            "tag":          enc_resp["tag"]
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    // Implicit rejection: wrong CEK → AES-GCM tag mismatch → DecryptionFailed (422)
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "tampered wrapped key must trigger implicit rejection and return 422"
    );
    Ok(())
}

/// Supplying a symmetric AES key UID in an RSA-OAEP protected header must be rejected.
#[tokio::test]
async fn test_rsa_oaep_decrypt_symmetric_key_as_kid() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    // Create a symmetric AES key
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
    let aes_kid = cr.unique_identifier.to_string();

    // Build an RSA-OAEP protected header with the AES key UID as `kid`
    let protected_json = format!(r#"{{"alg":"RSA-OAEP","enc":"A256GCM","kid":"{aes_kid}"}}"#);
    let protected_b64 = URL_SAFE_NO_PAD.encode(protected_json.as_bytes());

    let req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&json!({
            "protected":    protected_b64,
            "encrypted_key": URL_SAFE_NO_PAD.encode([0_u8; 256]), // 256 bytes (fake RSA-wrapped CEK)
            "iv":           URL_SAFE_NO_PAD.encode([0_u8; 12]),
            "ciphertext":   URL_SAFE_NO_PAD.encode(b"fake"),
            "tag":          URL_SAFE_NO_PAD.encode([0_u8; 16])
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    // AES key is not an RSA key → CryptoFailure (422)
    assert_ne!(
        resp.status().as_u16() / 100,
        2,
        "RSA-OAEP decrypt with an AES kid must fail with a non-2xx status"
    );
    Ok(())
}
