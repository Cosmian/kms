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

    // Security: this proxy is intentionally unauthenticated and scoped to `/auth/*`.
    // Actix does not normalize the path, so `req.path()` may still contain `.`/`..`
    // segments. If we forwarded them verbatim, the outgoing `reqwest` URL parser would
    // resolve `.../auth/../admin` down to `.../admin`, escaping the `/auth/*` scope and
    // reaching arbitrary auth-verifier endpoints. Reject such paths *before* building
    // the outgoing request rather than relying on the HTTP client to "do the right thing".
    if path_has_dot_segment(path) {
        warn!("SPIRE auth proxy: rejected path traversal attempt: {path}");
        return HttpResponse::BadRequest().json(serde_json::json!({
            "errors": ["invalid path: '.' and '..' segments are not allowed"]
        }));
    }

    let target = if req.query_string().is_empty() {
        format!("{base}{path}")
    } else {
        format!("{base}{path}?{}", req.query_string())
    };

    debug!("SPIRE auth proxy → {target}");

    let method = match reqwest_method(req.method().as_str()) {
        Ok(m) => m,
        Err(resp) => return resp,
    };

    let mut rb = client.request(method, &target);

    // Forward only the headers the auth-verifier needs. `Authorization` is
    // intentionally excluded: SPIRE uses `X-Vault-Token` for authentication,
    // and forwarding `Authorization` could allow the proxy to reach unintended
    // auth-verifier endpoints that accept bearer tokens.
    for header_name in &["X-Vault-Token", "Content-Type"] {
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
            // A mid-transfer body read failure (e.g. connection reset) must not be
            // silently turned into an empty, success-shaped response: surface it as
            // a 502 so the caller can distinguish it from a legitimately empty body.
            let resp_body = match resp.bytes().await {
                Ok(body) => body,
                Err(e) => {
                    warn!("vault auth proxy: failed to read auth-verifier response body: {e}");
                    return HttpResponse::BadGateway().json(serde_json::json!({
                        "errors": ["auth-verifier response body read failed"]
                    }));
                }
            };

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
                "errors": ["auth-verifier unreachable"]
            }))
        }
    }
}

/// Translate an incoming actix-web HTTP method string into a `reqwest::Method`,
/// preserving the verb byte-for-byte.
///
/// The auth proxy must forward the client's method unchanged: mapping every
/// non-`GET`/`DELETE`/`PUT` verb to `POST` would silently rewrite `PATCH`,
/// `HEAD`, `OPTIONS`, etc., breaking any auth-verifier route that distinguishes
/// them. Returns an error if the method cannot be parsed rather than silently
/// substituting `POST`.
fn reqwest_method(method: &str) -> Result<reqwest::Method, HttpResponse> {
    reqwest::Method::from_bytes(method.as_bytes()).map_err(|_e| {
        HttpResponse::BadRequest().json(serde_json::json!({
            "errors": [format!("unsupported HTTP method: {method}")]
        }))
    })
}

/// Return `true` if any segment of `path` resolves to a `.` or `..` (dot or
/// dot-dot) segment, in either plain or percent-encoded form.
///
/// Only the literal `.` character and its percent-encoding `%2e`/`%2E` decode to
/// `.`, so normalizing `%2e` to `.` (case-insensitively) is sufficient to detect
/// every encoding of a dot segment. This is used to block path-traversal attempts
/// in the unauthenticated auth proxy before the path is handed to the outgoing
/// HTTP client (whose URL parser would otherwise silently collapse `..`).
///
/// Segments are split on **both** `/` and `\`: actix does not normalize `\` in
/// the request path, but the outgoing `reqwest`/`url` crate's WHATWG-compliant
/// parser treats `\` as a path separator and resolves `..` across it (e.g.
/// `/auth/..\admin` → `/admin`). Splitting on `/` alone let that raw-backslash
/// form through unnoticed.
fn path_has_dot_segment(path: &str) -> bool {
    path.split(['/', '\\']).any(|segment| {
        let normalized = segment.to_ascii_lowercase().replace("%2e", ".");
        normalized == "." || normalized == ".."
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{path_has_dot_segment, reqwest_method};

    #[test]
    fn preserves_http_method() {
        assert_eq!(reqwest_method("GET").unwrap(), reqwest::Method::GET);
        assert_eq!(reqwest_method("POST").unwrap(), reqwest::Method::POST);
        assert_eq!(reqwest_method("PUT").unwrap(), reqwest::Method::PUT);
        assert_eq!(reqwest_method("DELETE").unwrap(), reqwest::Method::DELETE);
        assert_eq!(reqwest_method("PATCH").unwrap(), reqwest::Method::PATCH);
        assert_eq!(reqwest_method("HEAD").unwrap(), reqwest::Method::HEAD);
        assert_eq!(reqwest_method("OPTIONS").unwrap(), reqwest::Method::OPTIONS);
    }

    #[test]
    fn rejects_plain_dot_segments() {
        assert!(path_has_dot_segment("/auth/../admin"));
        assert!(path_has_dot_segment("/auth/./admin"));
        assert!(path_has_dot_segment("/../admin"));
        assert!(path_has_dot_segment("/auth/.."));
        assert!(path_has_dot_segment(".."));
        assert!(path_has_dot_segment("."));
    }

    #[test]
    fn rejects_percent_encoded_dot_segments() {
        assert!(path_has_dot_segment("/auth/%2e%2e/admin"));
        assert!(path_has_dot_segment("/auth/%2E%2E/admin"));
        assert!(path_has_dot_segment("/auth/%2e/admin"));
        assert!(path_has_dot_segment("/auth/.%2e/admin"));
        assert!(path_has_dot_segment("/auth/%2e./admin"));
    }

    #[test]
    fn rejects_backslash_dot_segments() {
        // `reqwest`'s WHATWG URL parser treats `\` as a path separator and
        // resolves `..` across it, even though `req.path()` never normalizes it.
        assert!(path_has_dot_segment("/auth/..\\admin"));
        assert!(path_has_dot_segment("/auth\\../admin"));
        assert!(path_has_dot_segment("\\auth\\..\\admin"));
        assert!(path_has_dot_segment("/auth/.\\admin"));
        assert!(path_has_dot_segment("\\.."));
        assert!(path_has_dot_segment("\\."));
    }

    #[test]
    fn accepts_safe_paths() {
        assert!(!path_has_dot_segment("/auth/approle/login"));
        assert!(!path_has_dot_segment("/auth/token/lookup-self"));
        assert!(!path_has_dot_segment("/auth/token/renew-self"));
        assert!(!path_has_dot_segment(
            "/auth/approle/role/spire-server/secret-id"
        ));
        assert!(!path_has_dot_segment("/"));
        assert!(!path_has_dot_segment(""));
    }

    #[test]
    fn accepts_segments_containing_but_not_equal_to_dots() {
        // Dots inside a longer segment are legitimate and must not be flagged.
        assert!(!path_has_dot_segment("/auth/token.self"));
        assert!(!path_has_dot_segment("/auth/v1.2/login"));
        assert!(!path_has_dot_segment("/auth/...login"));
        assert!(!path_has_dot_segment("/auth/a..b"));
    }
}
