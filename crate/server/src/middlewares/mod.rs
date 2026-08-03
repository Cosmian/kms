mod tls_auth;
pub(crate) use tls_auth::{extract_peer_certificate, tls_auth_fn};

mod api_token;
pub(crate) use api_token::api_token_middleware;

mod auth_verifier;
pub(crate) use auth_verifier::{AuthVerifier, verify_auth_verifier_jwt_subject};

mod ensure_auth;
pub(crate) use ensure_auth::ensure_auth_middleware;

mod jwt;
pub(crate) use jwt::{JwksManager, JwtConfig, JwtTokenHeaders, UserClaim, jwt_auth_middleware};

mod rate_limiter;
pub(crate) use rate_limiter::{RateLimiterConfig, RateLimiterMiddleware};

mod otel_http_middleware;
pub(crate) use otel_http_middleware::otel_http_metrics_middleware;

mod spire_token;
pub(crate) use spire_token::{
    SpireTokenCache, spire_token_middleware, vault_token_optional_middleware,
};

mod session_auth;
use actix_web::{dev::ServiceRequest, http::header};
pub(crate) use session_auth::SessionAuth;

use crate::{error::KmsError, result::KResult};

/// Extract a Bearer token from the `Authorization` header of a request.
///
/// Returns the raw token string (trimmed) on success, or an `Unauthorized`
/// error when the header is missing, malformed, or empty.
///
/// Shared by the API-token, Auth Verifier server, and any future Bearer-based
/// middleware so the parsing logic stays in one place.
pub(crate) fn extract_bearer_token(req: &ServiceRequest) -> KResult<&str> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let mut parts = auth_header.splitn(2, ' ');
    let scheme = parts.next().unwrap_or("");
    let token = parts.next().unwrap_or("").trim();

    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return Err(KmsError::Unauthorized(
            "missing or malformed Authorization header (expected Bearer token)".to_owned(),
        ));
    }
    Ok(token)
}

/// Represents an authenticated user
///
/// This struct is stored in the request extensions after successful
/// authentication and can be used by request handlers.
#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedUser {
    /// The authenticated username
    pub username: String,
}
