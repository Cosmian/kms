//! Tests for `POST /v1/crypto/keys/unwrap` — CEK import by RSA-OAEP unwrapping.

use actix_web::{http::StatusCode, test as actix_test};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
    kmip_operations::CreateKeyPairResponse,
    requests::create_rsa_key_pair_request,
};
use cosmian_logger::log_init;
use serde_json::{Value, json};

use crate::{result::KResult, tests::test_utils};

/// Create an RSA key pair via KMIP and return `(private_kid, public_kid)`.
async fn create_rsa_key_pair<S, B>(app: &S) -> KResult<(String, String)>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let create_req =
        create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, EMPTY_TAGS, 2048, false, None)?;
    let resp: CreateKeyPairResponse = test_utils::post_2_1(app, create_req).await?;
    Ok((
        resp.private_key_unique_identifier.to_string(),
        resp.public_key_unique_identifier.to_string(),
    ))
}

/// Encrypt a plaintext with the `/v1/crypto/encrypt` endpoint using RSA-OAEP,
/// returning the `encrypted_key` (wrapped CEK).
/// This is a helper that drives the existing encrypt endpoint to produce a wrapped CEK
/// that we can feed to `/v1/crypto/keys/unwrap`.
async fn wrap_cek_via_encrypt<S, B>(
    app: &S,
    kid: &str,
    alg: &str,
    enc: &str,
) -> KResult<(String, String)>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    // Encrypt trivial data — we only care about the encrypted_key (wrapped CEK)
    let data_b64 = URL_SAFE_NO_PAD.encode(b"x");
    let enc_resp: Value = test_utils::post_json_with_uri(
        app,
        json!({"kid": kid, "alg": alg, "enc": enc, "data": data_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    let encrypted_key = enc_resp["encrypted_key"]
        .as_str()
        .expect("encrypt response must have encrypted_key for RSA-OAEP")
        .to_owned();
    // The protected header from encrypt contains kid pointing to the private key
    let protected = enc_resp["protected"]
        .as_str()
        .expect("encrypt response must have protected")
        .to_owned();
    Ok((protected, encrypted_key))
}

/// Build a base64url-encoded `protected` header for the unwrap endpoint.
fn build_protected_header(alg: &str, enc: &str, kid: &str) -> String {
    let header_json = json!({"alg": alg, "enc": enc, "kid": kid});
    URL_SAFE_NO_PAD.encode(header_json.to_string().as_bytes())
}

/// Round-trip: unwrap a CEK with RSA-OAEP, then use it to encrypt/decrypt.
#[tokio::test]
async fn test_unwrap_key_then_decrypt() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    // 1. Create RSA key pair via KMIP
    let (_kid_priv, kid_pub) = create_rsa_key_pair(&app).await?;

    // 2. Use the encrypt endpoint with RSA-OAEP to produce a wrapped CEK
    //    The encrypt endpoint wraps a fresh CEK with the public key and returns
    //    a protected header containing the private key UID
    let (protected, encrypted_key) =
        wrap_cek_via_encrypt(&app, &kid_pub, "RSA-OAEP", "A256GCM").await?;

    // 3. Call POST /v1/crypto/keys/unwrap using the protected header from encrypt
    let unwrap_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({
            "protected": protected,
            "encrypted_key": encrypted_key
        }),
        "/v1/crypto/keys/unwrap",
    )
    .await?;

    let ksym_kid = unwrap_resp["kid"]
        .as_str()
        .expect("missing kid in unwrap response");
    assert_eq!(unwrap_resp["kty"].as_str(), Some("oct"));
    assert_eq!(unwrap_resp["alg"].as_str(), Some("A256GCM"));
    assert!(unwrap_resp["key_ops"].as_array().is_some());

    // 4. Encrypt some data with the imported key using direct encryption
    let plaintext = b"Hello, JWE unwrap endpoint!";
    let data_b64 = URL_SAFE_NO_PAD.encode(plaintext);

    let enc_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": ksym_kid, "alg": "dir", "enc": "A256GCM", "data": data_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    // 5. Decrypt with the same key
    let dec_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({
            "protected": enc_resp["protected"],
            "iv": enc_resp["iv"],
            "ciphertext": enc_resp["ciphertext"],
            "tag": enc_resp["tag"]
        }),
        "/v1/crypto/decrypt",
    )
    .await?;

    let recovered = URL_SAFE_NO_PAD
        .decode(dec_resp["data"].as_str().expect("missing data"))
        .expect("base64 decode");
    assert_eq!(recovered, plaintext);

    Ok(())
}

/// Test with RSA-OAEP-256 (SHA-256 for both OAEP hash and MGF1).
#[tokio::test]
async fn test_unwrap_key_rsa_oaep_256() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (_kid_priv, kid_pub) = create_rsa_key_pair(&app).await?;

    // Use the encrypt endpoint with RSA-OAEP-256 to produce a wrapped CEK
    let (protected, encrypted_key) =
        wrap_cek_via_encrypt(&app, &kid_pub, "RSA-OAEP-256", "A128GCM").await?;

    let unwrap_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({
            "protected": protected,
            "encrypted_key": encrypted_key
        }),
        "/v1/crypto/keys/unwrap",
    )
    .await?;

    assert_eq!(unwrap_resp["alg"].as_str(), Some("A128GCM"));
    assert_eq!(unwrap_resp["kty"].as_str(), Some("oct"));

    // Verify the key works for A128GCM encrypt/decrypt
    let ksym_kid = unwrap_resp["kid"].as_str().expect("kid");
    let data_b64 = URL_SAFE_NO_PAD.encode(b"test 128");
    let enc_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": ksym_kid, "alg": "dir", "enc": "A128GCM", "data": data_b64}),
        "/v1/crypto/encrypt",
    )
    .await?;

    let dec_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({
            "protected": enc_resp["protected"],
            "iv": enc_resp["iv"],
            "ciphertext": enc_resp["ciphertext"],
            "tag": enc_resp["tag"]
        }),
        "/v1/crypto/decrypt",
    )
    .await?;

    let recovered = URL_SAFE_NO_PAD
        .decode(dec_resp["data"].as_str().expect("base64 data"))
        .expect("base64 decode");
    assert_eq!(recovered, b"test 128");

    Ok(())
}

/// Error case: unsupported algorithm (e.g. dir) should return 422.
#[tokio::test]
async fn test_unwrap_key_unsupported_alg() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let protected = build_protected_header("dir", "A256GCM", "some-kid");
    let req = actix_test::TestRequest::post()
        .uri("/v1/crypto/keys/unwrap")
        .set_json(&json!({
            "protected": protected,
            "encrypted_key": URL_SAFE_NO_PAD.encode(b"fake-wrapped-key")
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    Ok(())
}

/// Error case: missing `enc` in protected header should return 400.
#[tokio::test]
async fn test_unwrap_key_missing_enc() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let header = json!({"alg": "RSA-OAEP-256", "kid": "some-kid"});
    let protected = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let req = actix_test::TestRequest::post()
        .uri("/v1/crypto/keys/unwrap")
        .set_json(&json!({
            "protected": protected,
            "encrypted_key": URL_SAFE_NO_PAD.encode(b"fake")
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// Error case: empty encrypted_key should return 400.
#[tokio::test]
async fn test_unwrap_key_empty_encrypted_key() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (kid_priv, _kid_pub) = create_rsa_key_pair(&app).await?;
    let protected = build_protected_header("RSA-OAEP-256", "A256GCM", &kid_priv);

    let req = actix_test::TestRequest::post()
        .uri("/v1/crypto/keys/unwrap")
        .set_json(&json!({
            "protected": protected,
            "encrypted_key": ""
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// Error case: CEK size mismatch (wrap 16 bytes but claim A256GCM expects 32).
/// We encrypt with A128GCM (16-byte CEK) but tell the unwrap endpoint it's A256GCM (32-byte CEK).
#[tokio::test]
async fn test_unwrap_key_size_mismatch() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let (kid_priv, kid_pub) = create_rsa_key_pair(&app).await?;

    // Wrap a 16-byte CEK (A128GCM) via the encrypt endpoint
    let (_protected, encrypted_key) =
        wrap_cek_via_encrypt(&app, &kid_pub, "RSA-OAEP", "A128GCM").await?;

    // Tell unwrap endpoint that the CEK is for A256GCM (expects 32 bytes) but it's only 16
    let protected = build_protected_header("RSA-OAEP", "A256GCM", &kid_priv);
    let req = actix_test::TestRequest::post()
        .uri("/v1/crypto/keys/unwrap")
        .set_json(&json!({
            "protected": protected,
            "encrypted_key": encrypted_key
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    Ok(())
}
