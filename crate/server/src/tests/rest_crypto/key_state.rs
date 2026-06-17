//! Tests that cryptographic operations respect KMIP 2.1 §3.31 state rules:
//!
//! - **Protection operations** (Encrypt, Sign, MAC) require `Active` state.
//! - **Processing operations** (Decrypt, Verify, MACVerify) accept
//!   `Active`, `Deactivated`, and `Compromised` states.

use actix_web::{http::StatusCode, test};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_operations::{CreateResponse, Revoke, RevokeResponse},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
        requests::symmetric_key_create_request,
    },
};
use cosmian_logger::log_init;
use serde_json::json;

use crate::{result::KResult, tests::test_utils};

/// Create an AES-256 key and return its UID.
async fn create_aes_key<S, B>(app: &S) -> KResult<String>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let create_req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let cr: CreateResponse = test_utils::post_2_1(app, create_req).await?;
    Ok(cr.unique_identifier.to_string())
}

/// Encrypt plaintext with the given key, returning the JSON encrypt response.
async fn encrypt<S, B>(app: &S, kid: &str, plaintext: &[u8]) -> KResult<serde_json::Value>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let data_b64 = URL_SAFE_NO_PAD.encode(plaintext);
    test_utils::post_json_with_uri(
        app,
        json!({"kid": kid, "alg": "dir", "enc": "A256GCM", "data": data_b64}),
        "/v1/crypto/encrypt",
    )
    .await
}

/// Attempt to decrypt the given ciphertext response; returns Ok(value) on success.
async fn try_decrypt<S, B>(
    app: &S,
    enc_resp: &serde_json::Value,
) -> Result<serde_json::Value, StatusCode>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let req = test::TestRequest::post()
        .uri("/v1/crypto/decrypt")
        .set_json(&json!({
            "protected":  enc_resp["protected"],
            "iv":         enc_resp["iv"],
            "ciphertext": enc_resp["ciphertext"],
            "tag":        enc_resp["tag"],
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    if resp.status() == StatusCode::OK {
        let body = test::read_body(resp).await;
        Ok(serde_json::from_slice(&body).unwrap_or_default())
    } else {
        Err(resp.status())
    }
}

/// Attempt to encrypt; returns Ok on 200, Err(status) otherwise.
async fn try_encrypt<S, B>(
    app: &S,
    kid: &str,
    plaintext: &[u8],
) -> Result<serde_json::Value, StatusCode>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let data_b64 = URL_SAFE_NO_PAD.encode(plaintext);
    let req = test::TestRequest::post()
        .uri("/v1/crypto/encrypt")
        .set_json(&json!({"kid": kid, "alg": "dir", "enc": "A256GCM", "data": data_b64}))
        .to_request();
    let resp = test::call_service(app, req).await;
    if resp.status() == StatusCode::OK {
        let body = test::read_body(resp).await;
        Ok(serde_json::from_slice(&body).unwrap_or_default())
    } else {
        Err(resp.status())
    }
}

/// Deactivate a key via KMIP `Revoke` with `CessationOfOperation` reason.
async fn deactivate_key<S, B>(app: &S, kid: &str) -> KResult<()>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let revoke = Revoke {
        unique_identifier: Some(UniqueIdentifier::TextString(kid.to_owned())),
        revocation_reason: RevocationReason {
            revocation_reason_code: RevocationReasonCode::CessationOfOperation,
            revocation_message: Some("test deactivation".to_owned()),
        },
        compromise_occurrence_date: None,
        cascade: false,
    };
    let _resp: RevokeResponse = test_utils::post_2_1(app, revoke).await?;
    Ok(())
}

/// Compromise a key via KMIP `Revoke` with `KeyCompromise` reason.
async fn compromise_key<S, B>(app: &S, kid: &str) -> KResult<()>
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let revoke = Revoke {
        unique_identifier: Some(UniqueIdentifier::TextString(kid.to_owned())),
        revocation_reason: RevocationReason {
            revocation_reason_code: RevocationReasonCode::KeyCompromise,
            revocation_message: Some("test compromise".to_owned()),
        },
        compromise_occurrence_date: None,
        cascade: false,
    };
    let _resp: RevokeResponse = test_utils::post_2_1(app, revoke).await?;
    Ok(())
}

/// KMIP 2.1 §3.31: Decrypt MUST work on a Deactivated key.
#[tokio::test]
async fn test_decrypt_deactivated_key_succeeds() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;
    let enc_resp = encrypt(&app, &kid, b"secret data").await?;

    // Deactivate the key
    deactivate_key(&app, &kid).await?;

    // Decrypt must still work per KMIP 2.1 §3.31
    let dec_result = try_decrypt(&app, &enc_resp).await;
    assert!(
        dec_result.is_ok(),
        "Decrypt with deactivated key should succeed per KMIP 2.1 §3.31, got: {dec_result:?}"
    );

    Ok(())
}

/// KMIP 2.1 §3.31: Decrypt SHOULD work on a Compromised key.
#[tokio::test]
async fn test_decrypt_compromised_key_succeeds() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;
    let enc_resp = encrypt(&app, &kid, b"secret data").await?;

    // Compromise the key
    compromise_key(&app, &kid).await?;

    // Decrypt must still work per KMIP 2.1 §3.31
    let dec_result = try_decrypt(&app, &enc_resp).await;
    assert!(
        dec_result.is_ok(),
        "Decrypt with compromised key should succeed per KMIP 2.1 §3.31, got: {dec_result:?}"
    );

    Ok(())
}

/// KMIP 2.1 §3.31: Encrypt MUST NOT work on a Deactivated key.
#[tokio::test]
async fn test_encrypt_deactivated_key_rejected() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;

    // Deactivate the key
    deactivate_key(&app, &kid).await?;

    // Encrypt must be rejected (protection operation on non-Active key)
    let enc_result = try_encrypt(&app, &kid, b"will not encrypt").await;
    assert!(
        enc_result.is_err(),
        "Encrypt with deactivated key should fail per KMIP 2.1 §3.31"
    );

    Ok(())
}

/// KMIP 2.1 §3.31: Encrypt MUST NOT work on a Compromised key.
#[tokio::test]
async fn test_encrypt_compromised_key_rejected() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;

    let kid = create_aes_key(&app).await?;

    // Compromise the key
    compromise_key(&app, &kid).await?;

    // Encrypt must be rejected (protection operation on non-Active key)
    let enc_result = try_encrypt(&app, &kid, b"will not encrypt").await;
    assert!(
        enc_result.is_err(),
        "Encrypt with compromised key should fail per KMIP 2.1 §3.31"
    );

    Ok(())
}
