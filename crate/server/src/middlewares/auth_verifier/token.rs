//! Auth Verifier Token Validation
//!
//! Validates bearer tokens issued by the Auth Verifier server.  Two token
//! types are accepted:
//!
//! - **OIDC `at+jwt` access tokens** (issued by the auth-verifier OIDC
//!   Provider): carry a `kid` header that identifies the signing key in the
//!   combined JWKS (`/oidc/jwks`).  A fast direct key-lookup via
//!   `JwksManager::find(kid)` is used.
//!
//! - **Legacy session JWTs** (issued before the OIDC OP was added): do **not**
//!   carry a `kid` header.  Every public key in the JWKS is tried in sequence
//!   until the signature validates (unchanged behaviour).
//!
//! Common properties of both token types:
//! - **`sub` as identity**: the username is taken from the `sub` claim.
//! - **Same algorithm allowlist**: only asymmetric algorithms (RS*, ES*, PS*)
//!   are accepted to prevent algorithm-confusion attacks.

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
    middlewares::{AuthMethod, AuthenticatedUser, JwksManager, extract_bearer_token},
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
}

/// Core authentication handler for Auth Verifier server tokens.
///
/// Extracts the bearer token from the `Authorization` header and validates it.
/// Dispatches to the fast `kid`-lookup path for OIDC `at+jwt` access tokens
/// (which carry a `kid` header), or falls back to the try-all-keys loop for
/// legacy session JWTs (which have no `kid`).
///
/// Returns the authenticated username (`sub`) on success, or an error.
pub(super) async fn handle_auth_verifier(
    jwks_manager: &Arc<JwksManager>,
    req: &ServiceRequest,
) -> KResult<AuthenticatedUser> {
    let token = extract_bearer_token(req)
        .map_err(|e| KmsError::Unauthorized(format!("Auth Verifier: {e}")))?;

    let username = verify_auth_verifier_jwt_subject(jwks_manager, token).await?;
    Ok(AuthenticatedUser {
        username: username.into(),
        auth_method: AuthMethod::AuthVerifierJwt,
    })
}

/// Validate a Auth Verifier server JWT and return its `sub` claim (the
/// authenticated username).
///
/// Dispatches on the presence of a `kid` header in the JWT:
/// - **`kid` present** (OIDC `at+jwt` access tokens): performs a fast direct
///   key-lookup via `JwksManager::find(kid)`.  If the key is not found,
///   triggers a JWKS refresh and retries once.
/// - **No `kid`** (legacy session JWTs): tries every key in the JWKS
///   sequentially until one validates the signature.
///
/// Shared between the bearer-token `AuthVerifier` middleware
/// (`handle_auth_verifier`) and the UI's BFF login proxy
/// (`crate::routes::ui_auth::login_as`).
///
/// In test / insecure builds the signature check is skipped.
#[cfg_attr(any(test, feature = "insecure"), allow(unused_variables))]
#[cfg_attr(any(test, feature = "insecure"), allow(clippy::unused_async))]
pub(crate) async fn verify_auth_verifier_jwt_subject(
    jwks_manager: &Arc<JwksManager>,
    token: &str,
) -> KResult<String> {
    // In test/insecure builds skip signature validation — decode only.
    #[cfg(any(test, feature = "insecure"))]
    {
        let token_data = dangerous::insecure_decode::<AuthVerifierClaims>(token).map_err(|e| {
            KmsError::Unauthorized(format!("Auth Verifier: cannot decode token: {e}"))
        })?;
        Ok(token_data.claims.sub)
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

        // Dispatch: OIDC at+jwt tokens carry a kid header → fast direct lookup.
        // Legacy session JWTs have no kid → try-all-keys fallback.
        if let Some(kid) = header.kid.as_deref() {
            verify_with_kid(jwks_manager, token, &header, kid).await
        } else {
            verify_with_any_key(jwks_manager, token, &header).await
        }
    }
}

/// Validate a JWT that carries a `kid` header by looking up the key directly.
///
/// If the key is not found in the cache, forces a JWKS refresh and retries
/// once — this handles signing-key rotation on the auth-verifier side without
/// requiring a server restart.
#[cfg(all(not(test), not(feature = "insecure")))]
async fn verify_with_kid(
    jwks_manager: &Arc<JwksManager>,
    token: &str,
    header: &jsonwebtoken::Header,
    kid: &str,
) -> KResult<String> {
    // Try the cache first; refresh-on-miss for key rotation.
    let jwk = match jwks_manager.find(kid)? {
        Some(k) => k,
        None => {
            jwks_manager.force_refresh().await?;
            jwks_manager.find(kid)?.ok_or_else(|| {
                KmsError::Unauthorized(format!(
                    "Auth Verifier: unknown kid '{kid}' — not found in JWKS after refresh"
                ))
            })?
        }
    };

    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
        KmsError::Unauthorized(format!(
            "Auth Verifier: cannot build decoding key for kid '{kid}': {e}"
        ))
    })?;

    let mut validation = Validation::new(header.alg);
    validation.algorithms = vec![header.alg];
    validation.set_issuer::<String>(&[]);
    validation.validate_exp = true;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    validation.set_required_spec_claims(&["sub", "exp"]);

    let data = decode::<AuthVerifierClaims>(token, &decoding_key, &validation).map_err(|e| {
        KmsError::Unauthorized(format!(
            "Auth Verifier: token validation failed for kid '{kid}': {e}"
        ))
    })?;
    Ok(data.claims.sub)
}

/// Validate a JWT that carries no `kid` by trying every key in the JWKS.
///
/// Used for legacy session JWTs issued before the OIDC OP was added.
#[cfg(all(not(test), not(feature = "insecure")))]
async fn verify_with_any_key(
    jwks_manager: &Arc<JwksManager>,
    token: &str,
    header: &jsonwebtoken::Header,
) -> KResult<String> {
    let jwks = jwks_manager.find_any()?;
    if jwks.is_empty() {
        // Cache empty — force refresh (may have failed at startup).
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
        validation.set_issuer::<String>(&[]);
        validation.validate_exp = true;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        validation.set_required_spec_claims(&["sub", "exp"]);

        match decode::<AuthVerifierClaims>(token, &decoding_key, &validation) {
            Ok(data) => {
                return Ok(data.claims.sub);
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)] // test helpers — panics are acceptable
mod tests {
    use std::sync::Arc;

    use jsonwebtoken::{EncodingKey, Header, encode};

    use super::verify_auth_verifier_jwt_subject;
    use crate::middlewares::JwksManager;

    /// Build a minimal JWT with the given `sub` for use in insecure-mode unit tests.
    ///
    /// In test builds `verify_auth_verifier_jwt_subject` calls
    /// `dangerous::insecure_decode`, which does NOT validate the signature.
    /// Therefore the key material passed here does not matter for the test
    /// outcome — we use a throw-away in-memory secret for encoding only.
    fn make_jwt(sub: &str, kid: Option<&str>) -> String {
        // Throwaway HMAC secret — only used to produce a syntactically valid JWT.
        let key = EncodingKey::from_secret(b"test-secret");
        let header = Header {
            kid: kid.map(std::borrow::ToOwned::to_owned),
            ..Default::default()
        };
        let claims = serde_json::json!({ "sub": sub, "exp": 9_999_999_999_u64 });
        encode(&header, &claims, &key).expect("encode test JWT")
    }

    /// Create a minimal no-op `JwksManager` for tests that use the insecure path
    /// (no real JWKS fetching occurs).
    async fn dummy_jwks_manager() -> Arc<JwksManager> {
        Arc::new(
            JwksManager::new(vec![], None)
                .await
                .expect("create dummy JwksManager"),
        )
    }

    /// An OIDC `at+jwt` token carrying a `kid` header is accepted in insecure
    /// mode, and the `sub` claim is returned as the username.
    #[tokio::test]
    async fn test_oidc_access_token_with_kid_accepted() {
        let jwks = dummy_jwks_manager().await;
        let token = make_jwt("alice@example.com", Some("oidc-signing-key-1"));
        let sub = verify_auth_verifier_jwt_subject(&jwks, &token)
            .await
            .expect("should accept token with kid");
        assert_eq!(sub, "alice@example.com");
    }

    /// A legacy session JWT without a `kid` header is accepted in insecure
    /// mode, and the `sub` claim is returned as the username.
    #[tokio::test]
    async fn test_legacy_session_jwt_without_kid_accepted() {
        let jwks = dummy_jwks_manager().await;
        let token = make_jwt("bob", None);
        let sub = verify_auth_verifier_jwt_subject(&jwks, &token)
            .await
            .expect("should accept token without kid");
        assert_eq!(sub, "bob");
    }
}
