//! JWT Authentication Middleware
//!
//! This module handles JWT-based authentication for the KMS server.
//! It extracts and validates JWT tokens from the `Authorization: Bearer` header,
//! then processes the claims to authenticate users.

use std::sync::Arc;

use actix_web::{dev::ServiceRequest, http::header};
use cosmian_logger::{debug, trace, warn};

use super::UserClaim;
use crate::{
    error::KmsError,
    middlewares::{AuthMethod, AuthenticatedUser, UserId, jwt::JwtConfig},
    result::KResult,
};

/// Attempts to extract and validate a user claim from a JWT token
///
/// Tries each provided JWT configuration until one successfully validates the token or all configurations fail.
///
/// # Parameters
/// * `configs` - List of JWT configurations to try
/// * `token` - The JWT token string
///
/// # Returns
/// * `Ok(UserClaim)` - Successfully validated user claim
/// * `Err(Vec<KmsError>)` - List of errors from failed validation attempts
fn extract_user_claim(configs: &[JwtConfig], token: &str) -> Result<UserClaim, Vec<KmsError>> {
    let mut jwt_log_errors = Vec::new();

    // Try each JWT configuration until one succeeds
    for idp_config in configs {
        match idp_config.decode_bearer_header(token) {
            Ok(user_claim) => return Ok(user_claim),
            Err(error) => {
                jwt_log_errors.push(error);
            }
        }
    }

    // If all configurations failed, return the collected errors
    Err(jwt_log_errors)
}

/// Core JWT authentication logic
///
/// Extracts the bearer JWT from the `Authorization` header, validates it
/// against the provided OIDC configurations, and constructs an
/// [`AuthenticatedUser`] that includes `roles` and `domain` for OPA.
///
/// # Parameters
/// * `configs` - JWT configurations for validating tokens
/// * `req` - The incoming HTTP request
///
/// # Returns
/// * `Ok(AuthenticatedUser)` - Authentication successful
/// * `Err(KmsError)` - Authentication failed
pub(super) async fn handle_jwt(
    configs: Arc<Vec<JwtConfig>>,
    req: &ServiceRequest,
) -> KResult<AuthenticatedUser> {
    trace!("JWT Authentication...");

    // Read the raw `Authorization` header value (e.g. `"Bearer eyJ…"`).
    // `decode_bearer_header` called by `extract_user_claim` will strip the
    // `"Bearer "` prefix and decode the token payload.
    let identity = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok().map(str::to_owned))
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

    // Process the validation result and extract the email claim
    match private_claim {
        Ok(user_claim) => {
            // Accept `email` (Google/Auth0 style) or fall back to `sub` (standard JWT subject,
            // used by the Cosmian auth server and other issuer-agnostic IdPs).
            let username = user_claim.email.or(user_claim.sub);
            if let Some(username) = username {
                // Authentication successful
                debug!("JWT Access granted to {username}!");
                Ok(AuthenticatedUser {
                    username: UserId::from(username),
                    auth_method: AuthMethod::OidcJwt,
                    roles: user_claim.roles.unwrap_or_default(),
                    domain: user_claim.domain,
                })
            } else {
                // JWT is valid but missing both email and sub claims
                warn!(
                    "{:?} {} 401 unauthorized, no email or sub in JWT",
                    req.method(),
                    req.path()
                );
                Err(KmsError::InvalidRequest(
                    "No email or sub in JWT".to_owned(),
                ))
            }
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
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::{collections::HashMap, sync::RwLock};

    use actix_web::dev::ServiceRequest;

    use super::*;
    use crate::middlewares::jwt::jwks::JwksManager;

    // ── Helpers ────────────────────────────────────────────────────────────────

    /// Build a minimal, unsigned JWT carrying the given OIDC-style claims.
    ///
    /// Uses `HS256` in the header because `insecure_decode` (active in test
    /// builds) requires a recognised algorithm in the header but ignores the
    /// signature entirely.
    ///
    /// Fields match [`UserClaim`]:
    /// - `email` / `sub` for username resolution (`email` wins if both present)
    /// - `roles` for OPA RBAC
    /// - `as_rid` for domain (alias accepted: `as_domain`)
    fn make_test_jwt(
        email: Option<&str>,
        sub: &str,
        roles: &[&str],
        domain: Option<&str>,
    ) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let email_json = email.map_or_else(|| "null".to_owned(), |e| format!("\"{e}\""));
        let roles_json = {
            let parts: Vec<String> = roles.iter().map(|r| format!("\"{r}\"")).collect();
            format!("[{}]", parts.join(","))
        };
        let domain_json = domain.map_or_else(|| "null".to_owned(), |d| format!("\"{d}\""));
        let payload = URL_SAFE_NO_PAD.encode(format!(
                r#"{{"email":{email_json},"sub":"{sub}","roles":{roles_json},"as_rid":{domain_json},"exp":9999999999}}"#
            ));
        // Signature is ignored by `insecure_decode`; a single underscore is a valid placeholder.
        format!("{header}.{payload}._")
    }

    /// Build a [`JwtConfig`] backed by an in-memory no-op JWKS.
    ///
    /// In test builds `insecure_decode` is used — the JWKS is never consulted —
    /// so an empty manager is a valid stand-in.
    fn test_jwt_config() -> JwtConfig {
        JwtConfig {
            jwt_issuer_uri: "https://test.issuer.local".to_owned(),
            jwt_audience: None,
            jwks: Arc::new(JwksManager {
                uris: vec![],
                jwks: RwLock::new(HashMap::new()),
                last_update: RwLock::new(None),
                last_force_refresh: RwLock::new(None),
                proxy_params: None,
                accept_invalid_certs: false,
            }),
        }
    }

    /// Build a [`ServiceRequest`] with an `Authorization: Bearer <token>` header.
    ///
    /// `handle_jwt` reads the identity from `actix_identity::Identity` first; in
    /// tests that fails and it falls back to this header, which is the path we
    /// want to exercise.
    fn srv_req_with_bearer(token: &str) -> ServiceRequest {
        actix_web::test::TestRequest::get()
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_srv_request()
    }

    // ── Tests ──────────────────────────────────────────────────────────────────

    /// `handle_jwt` propagates the `as_rid` domain claim all the way through to
    /// `AuthenticatedUser.domain`.  This is the critical path for OPA
    /// `same_domain` checks.
    #[tokio::test]
    async fn test_handle_jwt_domain_propagated_to_authenticated_user() {
        let token = make_test_jwt(
            Some("officer@acme.com"),
            "officer@acme.com",
            &["CryptoOfficer"],
            Some("acme.com"),
        );
        let configs = Arc::new(vec![test_jwt_config()]);
        let req = srv_req_with_bearer(&token);
        let result = handle_jwt(configs, &req).await;
        assert!(result.is_ok(), "handle_jwt must succeed: {result:?}");
        let user = result.expect("already checked is_ok");
        assert_eq!(user.domain.as_deref(), Some("acme.com"));
    }

    /// `handle_jwt` propagates the `roles` claim to `AuthenticatedUser.roles`.
    #[tokio::test]
    async fn test_handle_jwt_roles_propagated_to_authenticated_user() {
        let token = make_test_jwt(
            Some("officer@acme.com"),
            "officer@acme.com",
            &["CryptoOfficer"],
            Some("acme.com"),
        );
        let configs = Arc::new(vec![test_jwt_config()]);
        let req = srv_req_with_bearer(&token);
        let result = handle_jwt(configs, &req).await;
        assert!(result.is_ok(), "handle_jwt must succeed: {result:?}");
        let user = result.expect("already checked is_ok");
        assert_eq!(user.roles, vec!["CryptoOfficer"]);
    }

    /// When the JWT carries no `email` claim, `sub` is used as the username
    /// (Cosmian auth server compatibility — it only sets `sub`).
    #[tokio::test]
    async fn test_handle_jwt_falls_back_to_sub_when_no_email() {
        let token = make_test_jwt(None, "sub-only@acme.com", &[], None);
        let configs = Arc::new(vec![test_jwt_config()]);
        let req = srv_req_with_bearer(&token);
        let result = handle_jwt(configs, &req).await;
        assert!(result.is_ok(), "handle_jwt must succeed: {result:?}");
        let user = result.expect("already checked is_ok");
        assert_eq!(user.username.as_ref(), "sub-only@acme.com");
    }

    /// When the JWT carries both `email` and `sub`, `email` wins as the username
    /// (Google / Auth0 style `IdPs` set `email` as the primary identity).
    #[tokio::test]
    async fn test_handle_jwt_prefers_email_over_sub() {
        let token = make_test_jwt(Some("alice@acme.com"), "alice-sub@acme.com", &[], None);
        let configs = Arc::new(vec![test_jwt_config()]);
        let req = srv_req_with_bearer(&token);
        let result = handle_jwt(configs, &req).await;
        assert!(result.is_ok(), "handle_jwt must succeed: {result:?}");
        let user = result.expect("already checked is_ok");
        assert_eq!(user.username.as_ref(), "alice@acme.com");
    }

    /// When the JWT carries no `as_rid` / `as_domain` claim, `domain` must be
    /// `None` — not an empty string or an error.
    #[tokio::test]
    async fn test_handle_jwt_no_domain_when_claim_absent() {
        let token = make_test_jwt(Some("user@acme.com"), "user@acme.com", &["User"], None);
        let configs = Arc::new(vec![test_jwt_config()]);
        let req = srv_req_with_bearer(&token);
        let result = handle_jwt(configs, &req).await;
        assert!(result.is_ok(), "handle_jwt must succeed: {result:?}");
        let user = result.expect("already checked is_ok");
        assert!(
            user.domain.is_none(),
            "domain must be None when claim is absent, got {:?}",
            user.domain
        );
    }
}
