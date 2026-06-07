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
