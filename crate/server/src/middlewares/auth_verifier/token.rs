//! Auth Verifier Token Validation
//!
//! Validates bearer tokens issued by the Auth Verifier server.
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

use actix_web::dev::ServiceRequest;
#[cfg(all(not(test), not(feature = "insecure")))]
use jsonwebtoken::Algorithm;
#[cfg(any(test, feature = "insecure"))]
use jsonwebtoken::dangerous;
#[cfg(all(not(test), not(feature = "insecure")))]
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

use crate::{
    error::KmsError,
    middlewares::{
        AuthMethod, AuthenticatedUser, JwksManager, UserId, extract_bearer_token,
        reject_reserved_aws_xks_identity,
    },
    result::KResult,
};

/// Subset of JWT algorithms the Auth Verifier middleware accepts.
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

/// Claims extracted from a Auth Verifier server JWT.
#[derive(Debug, Deserialize)]
struct AuthVerifierClaims {
    /// Subject — used as the KMS user identity.
    pub sub: String,
    /// Auth Verifier realm that issued the token.
    #[serde(rename = "as_rid", default)]
    pub realm_id: Option<String>,
}

/// Name of the session cookie set by the Auth Verifier server; it carries the session JWT.
pub(crate) const AUTH_VERIFIER_SESSION_COOKIE: &str = "_ea_";

/// Core authentication handler for Auth Verifier server tokens.
///
/// Validates the bearer token from the `Authorization` header against every key in
/// the JWKS (these tokens carry no `kid`). When no bearer token is present and
/// `session_cookie_realm` is set, falls back to the Auth Verifier `_ea_` session
/// cookie, accepted only for that realm.
pub(super) async fn handle_auth_verifier(
    jwks_manager: &Arc<JwksManager>,
    req: &ServiceRequest,
    session_cookie_realm: Option<&str>,
) -> KResult<AuthenticatedUser> {
    let token = match extract_bearer_token(req) {
        Ok(token) => token,
        Err(e) => {
            let (Some(realm), Some(cookie)) = (
                session_cookie_realm,
                req.cookie(AUTH_VERIFIER_SESSION_COOKIE),
            ) else {
                return Err(KmsError::Unauthorized(format!("Auth Verifier: {e}")));
            };
            return Ok(AuthenticatedUser {
                username: authenticate_auth_verifier_session_cookie(
                    jwks_manager,
                    cookie.value(),
                    realm,
                )
                .await?,
                auth_method: AuthMethod::AuthVerifierSession,
            });
        }
    };

    let username = UserId::from(verify_auth_verifier_jwt_subject(jwks_manager, token).await?);
    reject_reserved_aws_xks_identity(&username)?;
    Ok(AuthenticatedUser {
        username,
        auth_method: AuthMethod::AuthVerifierJwt,
    })
}

/// Validate an Auth Verifier `_ea_` session cookie and return the authenticated user.
///
/// Unlike bearer tokens, a browser cookie is sent ambiently, so the token must have
/// been issued for `expected_realm`: a session from any other realm of the same
/// Auth Verifier (another application, the admin realm, ...) is rejected.
pub(crate) async fn authenticate_auth_verifier_session_cookie(
    jwks_manager: &Arc<JwksManager>,
    token: &str,
    expected_realm: &str,
) -> KResult<UserId> {
    let claims = verify_auth_verifier_jwt(jwks_manager, token).await?;
    if claims.realm_id.as_deref() != Some(expected_realm) {
        return Err(KmsError::Unauthorized(format!(
            "Auth Verifier: session cookie was not issued for realm `{expected_realm}`"
        )));
    }
    let username = UserId::try_new(claims.sub)
        .map_err(|e| KmsError::Unauthorized(format!("Auth Verifier: {e}")))?;
    reject_reserved_aws_xks_identity(&username)?;
    Ok(username)
}

/// Validate a Auth Verifier server JWT and return its `sub` claim (the
/// authenticated username).
///
/// Shared between the bearer-token `AuthVerifier` middleware
/// (`handle_auth_verifier`) and the UI's BFF login proxy
/// (`crate::routes::ui_auth::login_as`), which validates the JWT the Cosmian
/// authentication server returns via `Set-Cookie: _ea_=<jwt>` before storing
/// the resulting username in the actix session. Keeping a single
/// implementation avoids the two call sites drifting apart on trust logic.
pub(crate) async fn verify_auth_verifier_jwt_subject(
    jwks_manager: &Arc<JwksManager>,
    token: &str,
) -> KResult<String> {
    Ok(verify_auth_verifier_jwt(jwks_manager, token).await?.sub)
}

/// Validate a Auth Verifier server JWT and return its claims.
///
/// In test / insecure builds the signature check is skipped (same behaviour
/// as the existing `JwtAuth` middleware).
#[cfg_attr(any(test, feature = "insecure"), allow(unused_variables))]
#[cfg_attr(any(test, feature = "insecure"), allow(clippy::unused_async))]
async fn verify_auth_verifier_jwt(
    jwks_manager: &Arc<JwksManager>,
    token: &str,
) -> KResult<AuthVerifierClaims> {
    // In test/insecure builds skip signature validation — decode only.
    #[cfg(any(test, feature = "insecure"))]
    {
        let token_data = dangerous::insecure_decode::<AuthVerifierClaims>(token).map_err(|e| {
            KmsError::Unauthorized(format!("Auth Verifier: cannot decode token: {e}"))
        })?;
        Ok(token_data.claims)
    }

    // Production: full validation.
    #[cfg(all(not(test), not(feature = "insecure")))]
    {
        let header = decode_header(token).map_err(|e| {
            KmsError::Unauthorized(format!("Auth Verifier: cannot decode token header: {e}"))
        })?;

        if !ALLOWED_ALGORITHMS.contains(&header.alg) {
            return Err(KmsError::Unauthorized(format!(
                "Auth Verifier: algorithm {:?} is not permitted; only asymmetric algorithms (RS*, ES*, PS*) are accepted",
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
            // Do not validate issuer — the Auth Verifier server may not set `iss`.
            validation.set_issuer::<String>(&[]);
            validation.validate_exp = true;
            validation.validate_aud = false;
            validation.required_spec_claims.clear();
            validation.set_required_spec_claims(&["sub", "exp"]);

            match decode::<AuthVerifierClaims>(token, &decoding_key, &validation) {
                Ok(data) => {
                    return Ok(data.claims);
                }
                Err(e) => {
                    last_error = Some(format!("{e}"));
                }
            }
        }

        Err(KmsError::Unauthorized(format!(
            "Auth Verifier: token signature validation failed against all {} JWKS key(s): {}",
            jwks.len(),
            last_error.unwrap_or_else(|| "no keys available".to_owned())
        )))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) mod tests {
    use std::sync::Arc;

    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    use super::authenticate_auth_verifier_session_cookie;
    use crate::{
        error::KmsError,
        middlewares::{JwksManager, UserId},
        routes::aws_xks::AWS_XKS_SERVICE_USER,
    };

    /// An Auth Verifier-shaped JWT; signatures are not checked in test builds.
    pub(crate) fn auth_verifier_token(sub: &str, realm: Option<&str>) -> String {
        let claims = serde_json::json!({
            "sub": sub,
            "exp": 4_102_444_800_u64,
            "as_as": "sa",
            "as_rid": realm,
        });
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("sign test JWT")
    }

    pub(crate) async fn empty_jwks_manager() -> Arc<JwksManager> {
        Arc::new(
            JwksManager::new(vec![], None)
                .await
                .expect("empty JwksManager must build without network access"),
        )
    }

    #[tokio::test]
    async fn session_cookie_of_configured_realm_is_accepted() {
        let token = auth_verifier_token("alice@example.com", Some("kms-saml"));
        let user = authenticate_auth_verifier_session_cookie(
            &empty_jwks_manager().await,
            &token,
            "kms-saml",
        )
        .await
        .expect("cookie of the configured realm must be accepted");
        assert_eq!(user, UserId::from("alice@example.com"));
    }

    /// Security: sessions of other realms of the same Auth Verifier (other applications,
    /// the `_` admin realm) or without a realm claim must never authenticate to the KMS.
    #[tokio::test]
    async fn session_cookie_of_another_or_no_realm_is_rejected() {
        let jwks = empty_jwks_manager().await;
        for realm in [Some("other-app"), Some("_"), Some(""), None] {
            let token = auth_verifier_token("alice@example.com", realm);
            let error = authenticate_auth_verifier_session_cookie(&jwks, &token, "kms-saml")
                .await
                .expect_err("cookie of another realm must be rejected");
            assert!(
                matches!(error, KmsError::Unauthorized(_)),
                "{realm:?}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn session_cookie_with_empty_or_reserved_subject_is_rejected() {
        let jwks = empty_jwks_manager().await;
        for sub in ["", AWS_XKS_SERVICE_USER] {
            let token = auth_verifier_token(sub, Some("kms-saml"));
            let error = authenticate_auth_verifier_session_cookie(&jwks, &token, "kms-saml")
                .await
                .expect_err("empty or reserved subject must be rejected");
            assert!(matches!(error, KmsError::Unauthorized(_)), "{sub}: {error}");
        }
    }

    #[tokio::test]
    async fn malformed_session_cookie_is_rejected() {
        let error = authenticate_auth_verifier_session_cookie(
            &empty_jwks_manager().await,
            "not-a-jwt",
            "kms-saml",
        )
        .await
        .expect_err("a malformed cookie must be rejected");
        assert!(matches!(error, KmsError::Unauthorized(_)));
    }
}
