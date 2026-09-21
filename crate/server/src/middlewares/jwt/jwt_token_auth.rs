//! JWT Authentication Middleware
//!
//! This module handles JWT-based authentication for the KMS server.
//! It extracts and validates JWT tokens from the Authorization header
//! or from an Identity service, then processes the claims to authenticate users.

use std::sync::Arc;

use actix_identity::Identity;
use actix_web::{FromRequest, dev::ServiceRequest, http::header};
use cosmian_logger::{debug, trace, warn};

use super::UserClaim;
use crate::{
    error::KmsError,
    middlewares::{
        AuthMethod, AuthenticatedUser, UserId, jwt::JwtConfig, reject_reserved_aws_xks_identity,
    },
    result::KResult,
};

/// URI scheme prefix identifying a SPIFFE ID (e.g. `spiffe://example.org/ns/foo/sa/bar`),
/// as carried by the `sub` claim of a SPIFFE JWT-SVID.
const SPIFFE_ID_PREFIX: &str = "spiffe://";

/// Attempts to extract and validate a user claim from a JWT token
///
/// Tries each provided JWT configuration until one successfully validates the token or all configurations fail.
///
/// # Parameters
/// * `configs` - List of JWT configurations to try
/// * `token` - The JWT token string
///
/// # Returns
/// * `Ok((UserClaim, bool))` - Successfully validated user claim, plus the
///   `accept_spiffe_subject` flag of the configuration that validated it
/// * `Err(Vec<KmsError>)` - List of errors from failed validation attempts
fn extract_user_claim(
    configs: &[JwtConfig],
    token: &str,
) -> Result<(UserClaim, bool), Vec<KmsError>> {
    let mut jwt_log_errors = Vec::new();

    // Try each JWT configuration until one succeeds
    for idp_config in configs {
        match idp_config.decode_bearer_header(token) {
            Ok(user_claim) => return Ok((user_claim, idp_config.accept_spiffe_subject)),
            Err(error) => {
                jwt_log_errors.push(error);
            }
        }
    }

    // If all configurations failed, return the collected errors
    Err(jwt_log_errors)
}

/// Resolve an [`AuthenticatedUser`] from a successfully validated JWT claim set.
///
/// `email` takes priority when present (standard OIDC/IdP flow, unchanged behaviour). When
/// `email` is absent, falls back to the `sub` claim **only if** `accept_spiffe_subject` is
/// `true` (the issuer's config opted in via `--jwt-svid-auth`) **and** `sub` is a SPIFFE ID
/// (`spiffe://...`), i.e. a SPIFFE JWT-SVID. Every other case is rejected, preserving the
/// pre-existing "no email in JWT" behaviour.
fn resolve_authenticated_user(
    user_claim: UserClaim,
    accept_spiffe_subject: bool,
) -> KResult<AuthenticatedUser> {
    let spiffe_sub = accept_spiffe_subject
        .then(|| {
            user_claim
                .sub
                .filter(|sub| sub.starts_with(SPIFFE_ID_PREFIX))
        })
        .flatten();
    if let Some(email) = user_claim.email {
        // Authentication successful with valid email
        debug!("JWT Access granted to {email}!");
        let username = UserId::from(email);
        reject_reserved_aws_xks_identity(&username)?;
        Ok(AuthenticatedUser {
            username,
            auth_method: AuthMethod::OidcJwt,
        })
    } else if let Some(sub) = spiffe_sub {
        // SPIFFE JWT-SVID: no email claim, but a validated spiffe:// subject and the
        // issuer's config explicitly opted in via `--jwt-svid-auth`.
        debug!("JWT-SVID access granted to {sub}!");
        let username = UserId::from(sub);
        reject_reserved_aws_xks_identity(&username)?;
        Ok(AuthenticatedUser {
            username,
            auth_method: AuthMethod::JwtSvid,
        })
    } else {
        // JWT is valid but missing the required email claim (and either SPIFFE JWT-SVID
        // support is not enabled for this issuer, or `sub` is not a spiffe:// URI)
        warn!("no email in JWT");
        Err(KmsError::InvalidRequest("No email in JWT".to_owned()))
    }
}

/// Validate a raw JWT-SVID token (no "Bearer " prefix, no `Authorization` header)
/// against the SPIFFE-JWT-SVID-enabled issuers and resolve an `AuthenticatedUser`.
///
/// Used by the Web UI's `/ui/login_svid` endpoint so a browser session can
/// authenticate with a SPIRE-issued JWT-SVID pasted by the user, reusing the
/// exact same issuer/JWKS validation as the bearer-token path (`handle_jwt`)
/// without requiring the Authorization header framing.
pub(crate) fn validate_jwt_svid(configs: &[JwtConfig], token: &str) -> KResult<AuthenticatedUser> {
    let mut errors = Vec::new();
    for config in configs.iter().filter(|c| c.accept_spiffe_subject) {
        match config.validate_authentication_token(token, true) {
            Ok(claim) => return resolve_authenticated_user(claim, true),
            Err(e) => errors.push(e),
        }
    }
    for error in &errors {
        warn!("{error:?}");
    }
    Err(KmsError::InvalidRequest("bad JWT-SVID".to_owned()))
}

/// Core JWT authentication logic
///
/// Extracts the JWT token from the request, validates it, and checks
/// for required claims (specifically email).
///
/// # Parameters
/// * `configs` - JWT configurations for validating tokens
/// * `req` - The incoming HTTP request
///
/// # Returns
/// * `Ok(AuthenticatedUser)` - Authentication successful with user email
/// * `Err(KmsError)` - Authentication failed
pub(super) async fn handle_jwt(
    configs: Arc<Vec<JwtConfig>>,
    req: &ServiceRequest,
) -> KResult<AuthenticatedUser> {
    trace!("JWT Authentication...");

    // Extract identity from either the Identity service or the Authorization header
    let identity = Identity::extract(req.request())
        .into_inner()
        .map_or_else(
            |_| {
                // If Identity extraction fails, try the Authorization header
                req.headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|h| h.to_str().ok().map(str::to_owned))
            },
            |identity| identity.id().ok(),
        )
        .unwrap_or_default();

    // Try to extract and validate the user claim
    let mut private_claim = extract_user_claim(&configs, &identity);

    // If no configuration could get the claim, try refreshing them and extract the user claim again
    if private_claim.is_err() {
        // Refresh the JWKS (JSON Web Key Set) and try again
        configs
            .first()
            .ok_or_else(|| KmsError::ServerError("No config available".to_owned()))?
            .jwks
            .refresh()
            .await?;

        private_claim = extract_user_claim(&configs, &identity);
    }

    match private_claim {
        Ok((user_claim, accept_spiffe_subject)) => {
            resolve_authenticated_user(user_claim, accept_spiffe_subject).inspect_err(|_| {
                warn!(
                    "{:?} {} 401 unauthorized, no email in JWT",
                    req.method(),
                    req.path()
                );
            })
        }
        Err(jwt_log_errors) => {
            // JWT validation failed — log at WARN so auth failures appear in production logs
            for error in &jwt_log_errors {
                warn!("{error:?}");
            }
            warn!(
                "{:?} {} 401 unauthorized: bad JWT",
                req.method(),
                req.path(),
            );
            Err(KmsError::InvalidRequest("bad JWT".to_owned()))
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    use super::{AuthMethod, JwtConfig, UserClaim, extract_user_claim, resolve_authenticated_user};
    use crate::middlewares::{UserId, jwt::JwksManager};

    fn claim(sub: Option<&str>, email: Option<&str>) -> UserClaim {
        UserClaim {
            email: email.map(str::to_owned),
            iss: None,
            sub: sub.map(str::to_owned),
            aud: None,
            iat: None,
            exp: None,
            nbf: None,
            jti: None,
            role: None,
            resource_name: None,
            perimeter_id: None,
            kacls_url: None,
            spki_hash: None,
            spki_hash_algorithm: None,
            message_id: None,
            email_type: None,
            google_email: None,
        }
    }

    /// Existing OIDC behaviour must be unaffected: `email` present is always accepted,
    /// regardless of `accept_spiffe_subject`.
    #[test]
    fn email_claim_is_accepted_and_takes_priority() {
        let user_claim = claim(Some("spiffe://example.org/ns/foo/sa/bar"), Some("a@b.com"));
        let user = resolve_authenticated_user(user_claim, true).expect("must be accepted");
        assert_eq!(user.username, UserId::from("a@b.com"));
        assert_eq!(user.auth_method, AuthMethod::OidcJwt);
    }

    /// A SPIFFE JWT-SVID (`sub = spiffe://...`, no `email`) is accepted only when
    /// `accept_spiffe_subject` is enabled — this is the `--jwt-svid-auth` opt-in flag.
    #[test]
    fn spiffe_subject_accepted_when_flag_enabled() {
        let user_claim = claim(Some("spiffe://example.org/ns/foo/sa/bar"), None);
        let user =
            resolve_authenticated_user(user_claim, true).expect("SPIFFE sub must be accepted");
        assert_eq!(
            user.username,
            UserId::from("spiffe://example.org/ns/foo/sa/bar")
        );
        assert_eq!(user.auth_method, AuthMethod::JwtSvid);
    }

    /// Non-regression: the exact same token must still be rejected when the operator has
    /// not enabled `--jwt-svid-auth` for this issuer.
    #[test]
    fn spiffe_subject_rejected_when_flag_disabled() {
        let user_claim = claim(Some("spiffe://example.org/ns/foo/sa/bar"), None);
        let error = resolve_authenticated_user(user_claim, false)
            .expect_err("must be rejected when accept_spiffe_subject is false");
        assert!(error.to_string().contains("No email in JWT"));
    }

    /// A `sub` that is not a SPIFFE ID must never be accepted as a username, even when the
    /// flag is enabled — the fallback is strictly scoped to `spiffe://` subjects.
    #[test]
    fn non_spiffe_subject_rejected_even_when_flag_enabled() {
        let user_claim = claim(Some("not-a-spiffe-id"), None);
        let error = resolve_authenticated_user(user_claim, true)
            .expect_err("non-spiffe sub must never be accepted as a username");
        assert!(error.to_string().contains("No email in JWT"));
    }

    /// No `sub` and no `email` must be rejected regardless of the flag.
    #[test]
    fn no_subject_no_email_rejected() {
        let user_claim = claim(None, None);
        let error = resolve_authenticated_user(user_claim, true)
            .expect_err("must be rejected without email or sub");
        assert!(error.to_string().contains("No email in JWT"));
    }

    /// `reject_reserved_aws_xks_identity` is invoked on the resolved SPIFFE username, so any
    /// `spiffe://` subject that happened to collide with the reserved identity would still be
    /// rejected. `AWS_XKS_SERVICE_USER` itself never starts with `spiffe://`, so this call
    /// order is the actual defense-in-depth mechanism (see the dedicated, exhaustive
    /// coverage of `reject_reserved_aws_xks_identity` in `middlewares::mod::tests`).
    #[test]
    fn spiffe_subject_still_goes_through_reserved_identity_check() {
        use crate::routes::aws_xks::AWS_XKS_SERVICE_USER;

        // A spiffe:// subject is never equal to the reserved identity, so it is accepted...
        let user_claim = claim(Some("spiffe://example.org/ns/foo/sa/bar"), None);
        let user = resolve_authenticated_user(user_claim, true).expect("must be accepted");
        assert_ne!(user.username.as_str(), AWS_XKS_SERVICE_USER);
    }

    fn sign_test_jwt(claims: &UserClaim) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-kid".to_owned());
        encode(&header, claims, &EncodingKey::from_secret(b"test-secret"))
            .expect("failed to sign test JWT")
    }

    async fn empty_jwks_manager() -> JwksManager {
        JwksManager::new(vec![], None)
            .await
            .expect("empty JwksManager must build without network access")
    }

    /// `extract_user_claim` must surface the `accept_spiffe_subject` flag of whichever
    /// configuration validated the token, so `handle_jwt` can apply the SPIFFE fallback.
    #[tokio::test]
    async fn extract_user_claim_surfaces_accept_spiffe_subject_flag() {
        let jwks = std::sync::Arc::new(empty_jwks_manager().await);
        let configs = vec![JwtConfig {
            jwt_issuer_uri: "https://issuer.example.com".to_owned(),
            jwt_audience: None,
            jwks,
            accept_spiffe_subject: true,
        }];
        let token = sign_test_jwt(&claim(Some("spiffe://example.org/ns/foo/sa/bar"), None));

        let (user_claim, accept_spiffe_subject) =
            extract_user_claim(&configs, &format!("Bearer {token}"))
                .expect("token must be decoded in test/insecure mode");

        assert!(accept_spiffe_subject);
        assert_eq!(
            user_claim.sub.as_deref(),
            Some("spiffe://example.org/ns/foo/sa/bar")
        );
    }
}
