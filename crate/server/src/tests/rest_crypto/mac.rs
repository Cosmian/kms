//! HS256 MAC compute and verify tests.

use actix_web::test;
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

/// Compute an HS256 MAC and verify it; also assert that a wrong MAC is rejected.
#[tokio::test]
async fn test_hs256_compute_verify() -> KResult<()> {
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

    let data_b64 = URL_SAFE_NO_PAD.encode(b"message to authenticate");

    // Compute MAC
    let compute_resp: Value = test_utils::post_json_with_uri(
        &app,
        json!({"kid": kid, "alg": "HS256", "data": data_b64}),
        "/v1/crypto/mac",
    )
    .await?;
    let mac_b64 = compute_resp["mac"].as_str().expect("missing mac");

    // Correct MAC → valid=true
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

    // Wrong MAC → non-200 or valid=false
    let wrong_mac_b64 = URL_SAFE_NO_PAD.encode(&[0_u8; 32]);
    let req = test::TestRequest::post()
        .uri("/v1/crypto/mac")
        .set_json(&json!({"kid": kid, "alg": "HS256", "data": data_b64, "mac": wrong_mac_b64}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    if resp.status() == actix_web::http::StatusCode::OK {
        let body = test::read_body(resp).await;
        let parsed: Value = serde_json::from_slice(&body).expect("JSON");
        assert_eq!(
            parsed["valid"].as_bool(),
            Some(false),
            "wrong MAC should yield valid=false"
        );
    }

    Ok(())
}
