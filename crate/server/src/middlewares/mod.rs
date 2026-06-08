mod tls_auth;
pub(crate) use tls_auth::{TlsAuth, extract_peer_certificate};

mod api_token;
pub(crate) use api_token::ApiTokenAuth;

mod ensure_auth;
pub(crate) use ensure_auth::EnsureAuth;

mod jwt;
pub(crate) use jwt::{JwksManager, JwtAuth, JwtConfig, JwtTokenHeaders, UserClaim};

mod rate_limiter;
pub(crate) use rate_limiter::{RateLimiterConfig, RateLimiterMiddleware};

/// Represents an authenticated user
///
/// This struct is stored in the request extensions after successful
/// authentication and can be used by request handlers.
#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedUser {
    /// The authenticated username
    pub username: String,
    /// RBAC context extracted from JWT claims (populated when RBAC is configured).
    #[allow(dead_code)]
    pub rbac_context: Option<RbacUserContext>,
}

/// RBAC-specific user context extracted from JWT claims.
///
/// Populated during JWT authentication when RBAC config is present.
/// Carried through the request lifecycle for policy evaluation.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct RbacUserContext {
    /// Roles extracted from the configured claim path.
    pub roles: Vec<String>,
    /// Tenant ID extracted from the configured claim path.
    pub tenant_id: Option<String>,
}
