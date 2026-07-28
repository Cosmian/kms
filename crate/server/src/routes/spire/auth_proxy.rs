//! Transparent reverse proxy for the auth-verifier `/auth/*` scope.
//!
//! When `vault_api_enabled = true`, the KMS becomes the single `vault_addr`
//! endpoint for SPIRE. All `/v1/auth/*` requests (`AppRole` login, token
//! `lookup-self`, `renew-self`, `revoke-self`) are forwarded to the
//! auth-verifier instance configured via `vault_auth_verifier_url`, with the
//! `/v1` prefix stripped (auth-verifier registers routes without `/v1`).
//!
//! The proxy:
//! - preserves the HTTP method, full path minus `/v1`, query string,
//!   `X-Vault-Token`, `Content-Type`, and raw request body;
//! - returns the auth-verifier response status and body byte-for-byte;
//! - returns HTTP 502 if auth-verifier is unreachable.

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse, web};
use cosmian_logger::{debug, warn};
use reqwest::Client;
use url::Url;

/// Forward a `/v1/auth/{tail}` request to the configured auth-verifier.
///
/// Injected via `app_data` on the `/v1/auth` scope in `start_kms_server.rs`.
pub(crate) async fn proxy_auth_request(
    req: HttpRequest,
    client: web::Data<Arc<Client>>,
    auth_verifier_url: web::Data<Url>,
    body: web::Bytes,
) -> HttpResponse {
    // Build target URL: auth-verifier routes are registered WITHOUT the `/v1` prefix.
    // Strip it from the incoming KMS path so `/v1/auth/{tail}` → `/auth/{tail}`.
    let base = auth_verifier_url.as_str().trim_end_matches('/');
    let path = req.path().strip_prefix("/v1").unwrap_or_else(|| req.path());
    let target = if req.query_string().is_empty() {
        format!("{base}{path}")
    } else {
        format!("{base}{path}?{}", req.query_string())
    };

    debug!("SPIRE auth proxy → {target}");

    let method = match req.method().as_str() {
        "GET" => reqwest::Method::GET,
        "DELETE" => reqwest::Method::DELETE,
        "PUT" => reqwest::Method::PUT,
        _ => reqwest::Method::POST,
    };

    let mut rb = client.request(method, &target);

    // Forward Vault token and content-type headers via string to avoid the
    // `http 0.2` (actix-web) vs `http 1.x` (reqwest) HeaderValue type mismatch.
    for header_name in &["X-Vault-Token", "Content-Type", "Authorization"] {
        if let Some(val) = req.headers().get(*header_name) {
            if let Ok(s) = val.to_str() {
                rb = rb.header(*header_name, s);
            }
        }
    }

    if !body.is_empty() {
        rb = rb.body(body);
    }

    match rb.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            // Preserve content-type from upstream response.
            let ct = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_owned();
            let resp_body = resp.bytes().await.unwrap_or_default();

            HttpResponse::build(
                actix_web::http::StatusCode::from_u16(status)
                    .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR),
            )
            .content_type(ct)
            .body(resp_body)
        }
        Err(e) => {
            warn!("vault auth proxy: auth-verifier unreachable: {e}");
            HttpResponse::BadGateway().json(serde_json::json!({
                "errors": [format!("auth-verifier unreachable: {e}")]
            }))
        }
    }
}
