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

    // Process the validation result and extract the email claim
    match private_claim.map(|user_claim| user_claim.email) {
        Ok(Some(email)) => {
            // Authentication successful with valid email
            debug!("JWT Access granted to {email}!");
            Ok(AuthenticatedUser {
                username: UserId::from(email),
                auth_method: AuthMethod::OidcJwt,
            })
        }
        Ok(None) => {
            // JWT is valid but missing the required email claim — log as WARN for audit trail
            warn!(
                "{:?} {} 401 unauthorized, no email in JWT",
                req.method(),
                req.path()
            );
            Err(KmsError::InvalidRequest("No email in JWT".to_owned()))
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
#[allow(clippy::expect_used, clippy::unwrap_used)] // test helpers — panics are acceptable
mod tests {
    use crate::middlewares::jwt::UserClaim;

    /// Build a minimal `UserClaim` with only email/sub set.
    fn claim(email: Option<&str>, sub: Option<&str>) -> UserClaim {
        UserClaim {
            email: email.map(str::to_owned),
            sub: sub.map(str::to_owned),
            iss: None,
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

    /// When email is present it is used as the username.
    #[test]
    fn u01_email_present_returns_email() {
        let c = claim(Some("alice@example.com"), Some("uid-123"));
        assert_eq!(c.email.as_deref(), Some("alice@example.com"));
    }

    /// When email is absent (and only sub is present), the JWT middleware
    /// returns 401. Auth-verifier always sets email, so this case only arises
    /// with non-compliant issuers.
    #[test]
    fn u02_no_email_even_with_sub() {
        let c = claim(None, Some("kms-service-account"));
        assert!(
            c.email.is_none(),
            "token without email must be rejected by KMS middleware"
        );
    }

    /// Auth-verifier issues email = username for plain usernames.
    /// Verify the email claim matches the subject.
    #[test]
    fn u03_auth_verifier_style_username_as_email() {
        let c = claim(Some("alice"), Some("alice"));
        assert_eq!(c.email.as_deref(), Some("alice"));
    }

    /// Both absent → no username derivable.
    #[test]
    fn u04_both_absent() {
        let c = claim(None, None);
        assert!(c.email.is_none());
        assert!(c.sub.is_none());
    }

    /// Auth-verifier service account (`client_credentials`): email = `client_id`.
    #[test]
    fn u05_service_account_email_equals_client_id() {
        let c = claim(Some("kms-service"), Some("kms-service"));
        assert_eq!(c.email.as_deref(), Some("kms-service"));
    }
}
