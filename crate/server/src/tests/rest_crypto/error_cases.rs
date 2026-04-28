//! Error-path tests: unknown algorithms, bad key IDs, wrong key types.

use actix_web::{http::StatusCode, test};
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
