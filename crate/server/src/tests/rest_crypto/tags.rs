//! Tag management endpoint tests for `POST/DELETE/GET /v1/crypto/keys/{kid}/tags`.

use actix_http::Request;
use actix_web::body::MessageBody;
use actix_web::{
    dev::{Service, ServiceResponse},
    http::StatusCode,
    test,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
    kmip_operations::CreateResponse,
    kmip_types::CryptographicAlgorithm,
    requests::symmetric_key_create_request,
};
use cosmian_logger::log_init;
use serde_json::{Value, json};

use crate::{result::KResult, tests::test_utils};

/// Create a fresh AES-256 symmetric key; return its KID.
async fn create_test_key<S, B>(app: &S) -> KResult<String>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let req = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    let cr: CreateResponse = test_utils::post_2_1(app, req).await?;
    Ok(cr.unique_identifier.to_string())
}

/// POST tags to a key; returns the parsed response body.
async fn post_tags<S, B>(app: &S, kid: &str, tags: &[&str]) -> KResult<Value>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    test_utils::post_json_with_uri(
        app,
        json!({"tags": tags}),
        &format!("/v1/crypto/keys/{kid}/tags"),
    )
    .await
}

/// DELETE tags from a key; returns the parsed response body.
async fn delete_tags<S, B>(app: &S, kid: &str, tags: &[&str]) -> KResult<Value>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let req = test::TestRequest::delete()
        .uri(&format!("/v1/crypto/keys/{kid}/tags"))
        .set_json(json!({"tags": tags}))
        .to_request();
    let res = test::call_service(app, req).await;
    if res.status() != StatusCode::OK {
        crate::kms_bail!(
            "{}",
            String::from_utf8(test::read_body(res).await.to_vec())
                .unwrap_or_else(|_| "[N/A]".to_owned())
        );
    }
    let body = test::read_body(res).await;
    Ok(serde_json::from_slice(&body)?)
}

/// GET tags from a key; returns the parsed response body.
async fn get_tags<S, B>(app: &S, kid: &str) -> KResult<Value>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    test_utils::get_json_with_uri(app, &format!("/v1/crypto/keys/{kid}/tags")).await
}

/// Extract the `tags` array from a response body as a sorted `Vec<String>`.
fn extract_tags(body: &Value) -> Vec<String> {
    let mut tags: Vec<String> = body["tags"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
        .collect();
    tags.sort_unstable();
    tags
}

/// POST adds tags; GET returns them.
#[tokio::test]
async fn test_add_tags_happy_path() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;
    let kid = create_test_key(&app).await?;

    let resp = post_tags(&app, &kid, &["jwks", "prod"]).await?;
    assert_eq!(resp["kid"], kid);
    assert_eq!(extract_tags(&resp), vec!["jwks", "prod"]);

    // GET must reflect the same state
    let get_resp = get_tags(&app, &kid).await?;
    assert_eq!(extract_tags(&get_resp), vec!["jwks", "prod"]);

    Ok(())
}

/// POSTing the same tag twice results in exactly one occurrence (idempotent).
#[tokio::test]
async fn test_add_tags_idempotent() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;
    let kid = create_test_key(&app).await?;

    post_tags(&app, &kid, &["jwks"]).await?;
    let resp = post_tags(&app, &kid, &["jwks"]).await?;

    assert_eq!(extract_tags(&resp), vec!["jwks"]);

    Ok(())
}

/// POST "a", "b" → DELETE "a" → GET returns only "b".
#[tokio::test]
async fn test_remove_tags_happy_path() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;
    let kid = create_test_key(&app).await?;

    post_tags(&app, &kid, &["alpha", "beta"]).await?;
    let resp = delete_tags(&app, &kid, &["alpha"]).await?;

    assert_eq!(extract_tags(&resp), vec!["beta"]);

    Ok(())
}

/// DELETE a tag that is not on the key — should succeed with unchanged list.
#[tokio::test]
async fn test_remove_nonexistent_tag_is_noop() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;
    let kid = create_test_key(&app).await?;

    post_tags(&app, &kid, &["keep"]).await?;
    let resp = delete_tags(&app, &kid, &["does-not-exist"]).await?;

    assert_eq!(extract_tags(&resp), vec!["keep"]);

    Ok(())
}

/// Fresh key has no user tags.
#[tokio::test]
async fn test_get_tags_empty() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;
    let kid = create_test_key(&app).await?;

    let resp = get_tags(&app, &kid).await?;
    assert_eq!(extract_tags(&resp), Vec::<String>::new());

    Ok(())
}

/// System tags (e.g. `_kk` added by the server on create) must never appear
/// in GET responses.
#[tokio::test]
async fn test_system_tags_not_exposed() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;
    let kid = create_test_key(&app).await?;

    let resp = get_tags(&app, &kid).await?;
    for tag in extract_tags(&resp) {
        assert!(
            !tag.starts_with('_'),
            "system tag '{tag}' must not appear in GET /tags response"
        );
    }

    Ok(())
}

/// POST with a `_`-prefixed tag must be rejected with 400.
#[tokio::test]
async fn test_reject_system_tag_add() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;
    let kid = create_test_key(&app).await?;

    let req = test::TestRequest::post()
        .uri(&format!("/v1/crypto/keys/{kid}/tags"))
        .set_json(json!({"tags": ["_system"]}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// DELETE with a `_`-prefixed tag must be rejected with 400.
#[tokio::test]
async fn test_reject_system_tag_delete() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;
    let kid = create_test_key(&app).await?;

    let req = test::TestRequest::delete()
        .uri(&format!("/v1/crypto/keys/{kid}/tags"))
        .set_json(json!({"tags": ["_kk"]}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// POST with an empty string tag must be rejected with 400.
#[tokio::test]
async fn test_reject_empty_tag() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;
    let kid = create_test_key(&app).await?;

    let req = test::TestRequest::post()
        .uri(&format!("/v1/crypto/keys/{kid}/tags"))
        .set_json(json!({"tags": [""]}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// All three methods with a non-existent KID must return 404.
#[tokio::test]
async fn test_unknown_kid_returns_404() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;
    let ghost = "00000000-0000-0000-0000-000000000000";

    // GET
    let req = test::TestRequest::get()
        .uri(&format!("/v1/crypto/keys/{ghost}/tags"))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::NOT_FOUND
    );

    // POST
    let req = test::TestRequest::post()
        .uri(&format!("/v1/crypto/keys/{ghost}/tags"))
        .set_json(json!({"tags": ["x"]}))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::NOT_FOUND
    );

    // DELETE
    let req = test::TestRequest::delete()
        .uri(&format!("/v1/crypto/keys/{ghost}/tags"))
        .set_json(json!({"tags": ["x"]}))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::NOT_FOUND
    );

    Ok(())
}

/// Core JWKS use-case: operator tags a key "jwks"; GET confirms it.
#[tokio::test]
async fn test_add_jwks_tag_then_list() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None).await;
    let kid = create_test_key(&app).await?;

    let resp = post_tags(&app, &kid, &["jwks"]).await?;
    assert_eq!(extract_tags(&resp), vec!["jwks"]);

    let get_resp = get_tags(&app, &kid).await?;
    assert!(
        extract_tags(&get_resp).contains(&"jwks".to_owned()),
        "tag 'jwks' must be present after POST"
    );

    Ok(())
}
