//! Cosmian Authentication Server Token Validation
//!
//! Validates bearer tokens issued by the Cosmian authentication server.
//!
//! Key differences from the standard OIDC/JWT middleware (`JwtAuth`):
//!
//! - **No `kid` header**: Cosmian tokens do not carry a `kid` field in their
//!   header.  Rather than a direct key-lookup, every public key in the JWKS
//!   is tried in sequence until the signature validates.
//!
//! - **`sub` as identity**: Cosmian tokens carry the username in the `sub`
//!   claim, not in `email`.  The authenticated username is set to `sub`.
//!
//! - **Same algorithm allowlist**: Only asymmetric algorithms (RS*, ES*, PS*)
//!   are accepted, mirroring the restriction in `JwtAuth` to prevent
//!   algorithm-confusion attacks.

use std::sync::Arc;

use actix_web::{dev::ServiceRequest, http::header};
#[cfg(all(not(test), not(feature = "insecure")))]
use jsonwebtoken::Algorithm;
#[cfg(any(test, feature = "insecure"))]
use jsonwebtoken::dangerous;
#[cfg(all(not(test), not(feature = "insecure")))]
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

use crate::{
    error::KmsError,
    middlewares::{AuthenticatedUser, JwksManager},
    result::KResult,
};

/// Subset of JWT algorithms the Cosmian auth middleware accepts.
///
/// HS* algorithms are excluded: they use a shared secret and an attacker who
/// obtains the JWKS public key could forge tokens.
#[cfg(all(not(test), not(feature = "insecure")))]
const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

/// Claims extracted from a Cosmian auth server JWT.
#[derive(Debug, Deserialize)]
struct CosmianClaims {
    /// Subject — used as the KMS user identity.
    pub sub: String,
}

/// Core authentication handler for Cosmian auth server tokens.
///
/// Extracts the bearer token from the `Authorization` header and validates it
/// against every key in the JWKS (since these tokens carry no `kid`).
///
/// Returns the authenticated username (`sub`) on success, or an error.
pub(super) async fn handle_cosmian_auth(
    jwks_manager: &Arc<JwksManager>,
    req: &ServiceRequest,
) -> KResult<AuthenticatedUser> {
    // Extract the raw Authorization header.
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // Parse "Bearer <token>".
    let mut parts = auth_header.splitn(2, ' ');
    let scheme = parts.next().unwrap_or("");
    let token = parts.next().unwrap_or("").trim();

    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return Err(KmsError::Unauthorized(
            "Cosmian auth: missing or malformed Authorization header (expected Bearer token)"
                .to_owned(),
        ));
    }

    let username = verify_cosmian_jwt_subject(jwks_manager, token).await?;
    Ok(AuthenticatedUser { username })
}

/// Validate a Cosmian auth server JWT and return its `sub` claim (the
/// authenticated username).
///
/// Shared between the bearer-token `CosmianAuth` middleware
/// (`handle_cosmian_auth`) and the UI's BFF login proxy
/// (`crate::routes::ui_auth::login_as`), which validates the JWT the Cosmian
/// authentication server returns via `Set-Cookie: _ea_=<jwt>` before storing
/// the resulting username in the actix session. Keeping a single
/// implementation avoids the two call sites drifting apart on trust logic.
///
/// In test / insecure builds the signature check is skipped (same behaviour
/// as the existing `JwtAuth` middleware).
#[cfg_attr(any(test, feature = "insecure"), allow(unused_variables))]
#[cfg_attr(any(test, feature = "insecure"), allow(clippy::unused_async))]
pub(crate) async fn verify_cosmian_jwt_subject(
    jwks_manager: &Arc<JwksManager>,
    token: &str,
) -> KResult<String> {
    // In test/insecure builds skip signature validation — decode only.
    #[cfg(any(test, feature = "insecure"))]
    {
        let token_data = dangerous::insecure_decode::<CosmianClaims>(token).map_err(|e| {
            KmsError::Unauthorized(format!("Cosmian auth: cannot decode token: {e}"))
        })?;
        Ok(token_data.claims.sub)
    }

    // Production: full validation.
    #[cfg(all(not(test), not(feature = "insecure")))]
    {
        let header = decode_header(token).map_err(|e| {
            KmsError::Unauthorized(format!("Cosmian auth: cannot decode token header: {e}"))
        })?;

        if !ALLOWED_ALGORITHMS.contains(&header.alg) {
            return Err(KmsError::Unauthorized(format!(
                "Cosmian auth: algorithm {:?} is not permitted; only asymmetric algorithms (RS*, ES*, PS*) are accepted",
                header.alg
            )));
        }

        // Fetch all public keys — Cosmian tokens have no `kid` so we try them all.
        let jwks = jwks_manager.find_any()?;
        if jwks.is_empty() {
            // JWKS cache is empty — the initial fetch at startup may have failed, or the
            // IdP may have been unreachable. Force a refresh, bypassing the normal
            // throttle: a plain `refresh()` call could be a no-op here for up to
            // `REFRESH_INTERVAL` seconds if `last_update` was already set by that earlier
            // failed attempt, even though the cache never got populated.
            jwks_manager.force_refresh().await?;
        }
        let jwks = jwks_manager.find_any()?;

        let mut last_error: Option<String> = None;

        for jwk in &jwks {
            let decoding_key = match DecodingKey::from_jwk(jwk) {
                Ok(k) => k,
                Err(e) => {
                    last_error = Some(format!("cannot build decoding key: {e}"));
                    continue;
                }
            };

            let mut validation = Validation::new(header.alg);
            validation.algorithms = vec![header.alg];
            // Do not validate issuer — the Cosmian auth server may not set `iss`.
            validation.set_issuer::<String>(&[]);
            validation.validate_exp = true;
            validation.validate_aud = false;
            validation.required_spec_claims.clear();
            validation.set_required_spec_claims(&["sub", "exp"]);

            match decode::<CosmianClaims>(token, &decoding_key, &validation) {
                Ok(data) => {
                    return Ok(data.claims.sub);
                }
                Err(e) => {
                    last_error = Some(format!("{e}"));
                }
            }
        }

        Err(KmsError::Unauthorized(format!(
            "Cosmian auth: token signature validation failed against all {} JWKS key(s): {}",
            jwks.len(),
            last_error.unwrap_or_else(|| "no keys available".to_owned())
        )))
    }
}
