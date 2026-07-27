mod tls_auth;
pub(crate) use tls_auth::{extract_peer_certificate, tls_auth_fn};

mod api_token;
pub(crate) use api_token::api_token_middleware;

mod ensure_auth;
pub(crate) use ensure_auth::ensure_auth_middleware;

mod jwt;
pub(crate) use jwt::{JwksManager, JwtConfig, JwtTokenHeaders, UserClaim, jwt_auth_middleware};

mod rate_limiter;
pub(crate) use rate_limiter::{RateLimiterConfig, RateLimiterMiddleware};

mod otel_http_middleware;
pub(crate) use otel_http_middleware::otel_http_metrics_middleware;

mod vault_token;
pub(crate) use vault_token::{VaultTokenCache, vault_token_middleware};

/// Represents an authenticated user
///
/// This struct is stored in the request extensions after successful
/// authentication and can be used by request handlers.
#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedUser {
    /// The authenticated username
    pub username: String,
}
