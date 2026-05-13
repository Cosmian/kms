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
    let app = test_utils::test_app(None, None).await;

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
        .set_json(&json!({"kid": kid, "alg": "RSA-OAEP-256", "enc": "A256GCM", "data": "dGVzdA"}))
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
    let app = test_utils::test_app(None, None).await;

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
    let app = test_utils::test_app(None, None).await;

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
    let app = test_utils::test_app(None, None).await;

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
    let app = test_utils::test_app(None, None).await;

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
    let app = test_utils::test_app(None, None).await;

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
    let app = test_utils::test_app(None, None).await;

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
