//! JWT Authentication Middleware
//!
//! This module handles JWT-based authentication for the KMS server.
//! It extracts and validates JWT tokens from the Authorization header
//! or from an Identity service, then processes the claims to authenticate users.

use std::sync::Arc;

use actix_identity::Identity;
use actix_web::{FromRequest, dev::ServiceRequest, http::header};
use tracing::{debug, trace};

use super::UserClaim;
use crate::{
    error::KmsError,
    middlewares::{AuthenticatedUser, jwt::JwtConfig},
    result::KResult,
};

/// Attempts to extract and validate a user claim from a JWT token
///
/// Tries each provided JWT configuration until one successfully validates the token or all configurations fail.
///
/// # Parameters
/// * `configs` - List of JWT configurations to try
/// * `identity` - The JWT token string
///
/// # Returns
/// * `Ok(UserClaim)` - Successfully validated user claim
/// * `Err(Vec<KmsError>)` - List of errors from failed validation attempts
fn extract_user_claim(configs: &[JwtConfig], identity: &str) -> Result<UserClaim, Vec<KmsError>> {
    let mut jwt_log_errors = Vec::new();

    // Try each JWT configuration until one succeeds
    for idp_config in configs {
        match idp_config.decode_bearer_header(identity) {
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
pub(crate) async fn handle_jwt(
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
                    .and_then(|h| h.to_str().ok().map(std::string::ToString::to_string))
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
            Ok(AuthenticatedUser { username: email })
        }
        Ok(None) => {
            // JWT is valid but missing the required email claim
            debug!(
                "{:?} {} 401 unauthorized, no email in JWT",
                req.method(),
                req.path()
            );
            Err(KmsError::InvalidRequest("No email in JWT".to_owned()))
        }
        Err(jwt_log_errors) => {
            // JWT validation failed
            for error in &jwt_log_errors {
                tracing::debug!("{error:?}");
            }
            debug!(
                "{:?} {} 401 unauthorized: bad JWT",
                req.method(),
                req.path(),
            );
            Err(KmsError::InvalidRequest("bad JWT".to_owned()))
        }
    }
}
