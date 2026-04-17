//! CORS configuration tests.
//!
//! Verifies that the KMIP API endpoint enforces a restrictive CORS policy
//! by default (no `cors_allowed_origins` configured). Cross-origin `OPTIONS`
//! preflight and `POST` requests from foreign origins must not receive an
//! `Access-Control-Allow-Origin` response header that mirrors the attacker's
//! origin.
//!
//! Covered scenarios:
//!   C1 - Request without Origin header receives no ACAO header
//!   C2 - OPTIONS preflight from a foreign origin receives no ACAO header
//!   C3 - POST from a foreign origin is not reflected in ACAO header
//!
//! Framework: NIST PR.AC-3 · CIS 13.9 · ISO 27034 L2 · OSSTMM Access

use test_kms_server::start_default_test_kms_server;

use crate::error::result::KmsCliResult;

const ATTACKER_ORIGIN: &str = "http://attacker.example.com";

// ---------------------------------------------------------------------------
// C1: Request without an Origin header — no ACAO header in response.
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn c01_no_origin_no_acao() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/kmip/2_1", ctx.server_port))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await
        .expect("request must succeed");

    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "No ACAO header expected when no Origin is sent, got: {:?}",
        resp.headers().get("access-control-allow-origin")
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// C2: OPTIONS preflight from foreign origin — ACAO must not reflect attacker origin.
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn c02_options_preflight_foreign_origin_not_reflected() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let resp = reqwest::Client::new()
        .request(
            reqwest::Method::OPTIONS,
            format!("http://127.0.0.1:{}/kmip/2_1", ctx.server_port),
        )
        .header("Origin", ATTACKER_ORIGIN)
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "content-type")
        .send()
        .await
        .expect("OPTIONS request must succeed");

    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert_ne!(
        acao, ATTACKER_ORIGIN,
        "CORS preflight must not reflect attacker origin"
    );
    assert_ne!(acao, "*", "CORS preflight must not return wildcard ACAO");
    Ok(())
}

// ---------------------------------------------------------------------------
// C3: POST from foreign origin — ACAO must not reflect attacker origin.
// ---------------------------------------------------------------------------
#[tokio::test]
pub(crate) async fn c03_post_foreign_origin_not_reflected() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let resp = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/kmip/2_1", ctx.server_port))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("Origin", ATTACKER_ORIGIN)
        .body("{}")
        .send()
        .await
        .expect("POST request must succeed");

    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert_ne!(
        acao, ATTACKER_ORIGIN,
        "POST response must not reflect attacker origin in ACAO"
    );
    assert_ne!(acao, "*", "POST response must not return wildcard ACAO");
    Ok(())
}
