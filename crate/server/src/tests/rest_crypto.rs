#![allow(clippy::doc_markdown, clippy::needless_borrows_for_generic_args)]
//! Integration tests for the REST Native Crypto API (`/v1/crypto/*`).
//!
//! Uses the same in-process `actix_web::test` infrastructure as the CSE and
//! health-endpoint tests — no TCP server, no external HTTP client.
//!
//! Coverage:
//!   encrypt_decrypt  — AES-GCM round-trips (128 / 256-bit), AAD binding
//!   sign_verify      — RS256 and ES256 round-trips; tamper rejection
//!   mac              — HS256 compute + correct/wrong MAC verify
//!   error_cases      — unknown alg (422), bad key id (4xx), wrong key type

use actix_web::{http::StatusCode, test};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
    kmip_operations::{CreateKeyPairResponse, CreateResponse},
    kmip_types::{CryptographicAlgorithm, RecommendedCurve},
    requests::{
        create_ec_key_pair_request, create_rsa_key_pair_request, symmetric_key_create_request,
    },
};
use cosmian_logger::log_init;
use serde_json::{Value, json};

use crate::{result::KResult, tests::test_utils};

// encrypt / decrypt round trips

#[tokio::test]
async fn test_aes128gcm_round_trip() -> KResult<()> {
    log_init(None);
    aes_gcm_round_trip(128, "A128GCM").await
}

#[tokio::test]
async fn test_aes256gcm_round_trip() -> KResult<()> {
    log_init(None);
    aes_gcm_round_trip(256, "A256GCM").await
}

async fn aes_gcm_round_trip(bits: usize, enc_alg: &str) -> KResult<()> {
    let app = test_utils::test_app(None, None).await;

    // Create AES key via KMIP
    let create_req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        bits,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let create_resp: CreateResponse = test_utils::post_2_1(&app, create_req).await?;
    let kid = create_resp.unique_identifier.to_string();

    let plaintext_b64 = URL_SAFE_NO_PAD.encode(b"Hello, REST crypto API!");

    // Encrypt
    let enc_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "dir", "enc": enc_alg, "data": plaintext_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    assert!(enc_resp.get("ciphertext").is_some(), "missing ciphertext");
    assert!(enc_resp.get("iv").is_some(), "missing iv");
    assert!(enc_resp.get("tag").is_some(), "missing tag");

    // Decrypt
    let dec_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({
            "protected":  enc_resp["protected"],
            "iv":         enc_resp["iv"],
            "ciphertext": enc_resp["ciphertext"],
            "tag":        enc_resp["tag"]
        }),
        "/v1/crypto/decrypt",
    )
    .await?;

    let recovered = URL_SAFE_NO_PAD
        .decode(dec_resp["data"].as_str().expect("missing data"))
        .expect("base64 decode");
    assert_eq!(recovered, b"Hello, REST crypto API!");
    Ok(())
}

#[tokio::test]
async fn test_aad_binding() -> KResult<()> {
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

    let data_b64 = URL_SAFE_NO_PAD.encode(b"secret payload");
    let aad_b64 = URL_SAFE_NO_PAD.encode(b"associated-data");
    let wrong_aad_b64 = URL_SAFE_NO_PAD.encode(b"tampered-aad");

    // Encrypt with AAD
    let enc_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "dir", "enc": "A256GCM", "data": data_b64, "aad": aad_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    // Correct AAD → success
    test_utils::post_json_with_uri::<_, _, Value, _>(
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

// sign / verify round trips

#[tokio::test]
async fn test_rs256_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None, None).await;

    let kp_req =
        create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, EMPTY_TAGS, 2048, false, None)?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let private_kid = kp_resp.private_key_unique_identifier.to_string();
    let public_kid = kp_resp.public_key_unique_identifier.to_string();

    sign_verify_round_trip(&app, "RS256", &private_kid, &public_kid).await
}

#[tokio::test]
async fn test_es256_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None, None).await;

    let kp_req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P256,
        false,
        None,
    )?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let private_kid = kp_resp.private_key_unique_identifier.to_string();
    let public_kid = kp_resp.public_key_unique_identifier.to_string();

    sign_verify_round_trip(&app, "ES256", &private_kid, &public_kid).await
}

async fn sign_verify_round_trip<S, B>(
    app: &S,
    alg: &str,
    private_kid: &str,
    public_kid: &str,
) -> KResult<()>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let data_b64 = URL_SAFE_NO_PAD.encode(b"data to sign");

    let sign_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": private_kid, "alg": alg, "data": data_b64}),
        "/v1/crypto/sign",
    )
    .await?;

    let protected = sign_resp["protected"].as_str().expect("missing protected");
    let signature = sign_resp["signature"].as_str().expect("missing signature");

    // Verify (valid)
    let verify_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"protected": protected, "data": data_b64, "signature": signature}),
        "/v1/crypto/verify",
    )
    .await?;

    assert_eq!(
        verify_resp["valid"].as_bool(),
        Some(true),
        "verify should return valid=true; response: {verify_resp}"
    );
    assert_eq!(
        verify_resp["kid"].as_str().expect("missing kid"),
        public_kid,
        "verify kid should be the public key"
    );

    // Verify with tampered data → non-200 or valid=false
    let tampered_b64 = URL_SAFE_NO_PAD.encode(b"tampered data");
    let req = test::TestRequest::post()
        .uri("/v1/crypto/verify")
        .set_json(&json!({"protected": protected, "data": tampered_b64, "signature": signature}))
        .to_request();
    let resp = test::call_service(app, req).await;
    if resp.status() == StatusCode::OK {
        let body = test::read_body(resp).await;
        let json: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(
            json["valid"].as_bool(),
            Some(false),
            "tampered data should yield valid=false"
        );
    }
    // non-200 is also acceptable

    Ok(())
}

// MAC compute / verify

#[tokio::test]
async fn test_hs256_compute_verify() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None, None).await;

    // Use an AES key; its raw bytes serve as HMAC key material
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

    let data_b64 = URL_SAFE_NO_PAD.encode(b"message to authenticate");

    // Compute MAC
    let compute_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "HS256", "data": data_b64}),
        "/v1/crypto/mac",
    )
    .await?;

    let mac_b64 = compute_resp["mac"].as_str().expect("missing mac");

    // Verify MAC (correct) → valid=true
    let verify_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "HS256", "data": data_b64, "mac": mac_b64}),
        "/v1/crypto/mac",
    )
    .await?;
    assert_eq!(
        verify_resp["valid"].as_bool(),
        Some(true),
        "correct MAC should yield valid=true; response: {verify_resp}"
    );

    // Verify MAC (wrong) → non-200 or valid=false
    let wrong_mac_b64 = URL_SAFE_NO_PAD.encode(&[0_u8; 32]);
    let req = test::TestRequest::post()
        .uri("/v1/crypto/mac")
        .set_json(&json!({"kid": kid, "alg": "HS256", "data": data_b64, "mac": wrong_mac_b64}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    if resp.status() == StatusCode::OK {
        let body = test::read_body(resp).await;
        let json: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(
            json["valid"].as_bool(),
            Some(false),
            "wrong MAC should yield valid=false"
        );
    }

    Ok(())
}

// error cases

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
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported alg should return 422"
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
    assert_eq!(
        resp.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported alg should return 422"
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
