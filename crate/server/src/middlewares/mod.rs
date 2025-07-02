mod ssl_auth;
pub(crate) use ssl_auth::{SslAuth, extract_peer_certificate};

mod api_token;
pub(crate) use api_token::ApiTokenAuth;

mod ensure_auth;
pub(crate) use ensure_auth::EnsureAuth;

mod log_requests;
pub(crate) use log_requests::LogAllRequests;

mod jwt;
pub(crate) use jwt::{JwksManager, JwtAuth, JwtConfig, JwtTokenHeaders, UserClaim};

/// Represents an authenticated user
///
/// This struct is stored in the request extensions after successful
/// authentication and can be used by request handlers.
#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedUser {
    /// The authenticated username
    pub username: String,
}
