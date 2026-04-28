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
use serde_json::json;

use crate::{result::KResult, tests::test_utils};

#[tokio::test]
async fn test_aes128gcm_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None, None).await;
    super::common::aes_gcm_round_trip(&app, 128, "A128GCM").await
}

#[tokio::test]
async fn test_aes256gcm_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None, None).await;
    super::common::aes_gcm_round_trip(&app, 256, "A256GCM").await
}

/// Encrypting with AAD and then decrypting with tampered AAD must fail.
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
