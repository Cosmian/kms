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

/// Claims extracted from a Cosmian Auth Verifier JWT.
///
/// The auth server includes the RBAC `roles` (RFC 9068 private claim) and
/// the realm identifier in `as_rid` so that OPA can enforce domain-scoped
/// policies without an additional lookup.
#[derive(Debug, Deserialize)]
pub(crate) struct AuthVerifierClaims {
    /// Subject — used as the KMS user identity (username / email).
    pub sub: String,
    /// RBAC roles emitted by the auth server (RFC 9068 `roles` private claim).
    /// Defaults to an empty list for tokens that predate role support.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Realm / domain the authenticated user belongs to.
    ///
    /// The auth server sets this as `as_rid` (realm ID). The legacy alias
    /// `as_domain` is also accepted for tokens issued before the field was
    /// renamed, matching the same alias on [`UserClaim`].
    #[serde(alias = "as_domain", alias = "as_rid")]
    pub domain: Option<String>,
}

/// Core authentication handler for Auth Verifier server tokens.
///
/// Extracts the bearer token from the `Authorization` header, validates it
/// against every key in the JWKS (Cosmian tokens carry no `kid`), and
/// populates [`AuthenticatedUser`] with the full claims — including `roles`
/// and `domain` — so OPA can evaluate role-based and domain-scoped policies.
pub(super) async fn handle_auth_verifier(
    jwks_manager: &Arc<JwksManager>,
    req: &ServiceRequest,
) -> KResult<AuthenticatedUser> {
    let token = extract_bearer_token(req)
        .map_err(|e| KmsError::Unauthorized(format!("Auth Verifier: {e}")))?;

    let claims = verify_auth_verifier_jwt(jwks_manager, token).await?;
    Ok(AuthenticatedUser {
        username: claims.sub.into(),
        auth_method: AuthMethod::AuthVerifierJwt,
        domain: claims.domain,
        roles: claims.roles,
    })
}

/// Validate a Cosmian Auth Verifier JWT and return its full claims.
///
/// Validates the signature against every public key in the JWKS (Cosmian
/// tokens carry no `kid`). Returns all claims — `sub`, `roles`, and
/// `domain` (`as_rid` / `as_domain`) — so callers can populate
/// [`AuthenticatedUser`] or store them in a session without re-parsing.
///
/// In test / insecure builds the signature check is skipped; only the
/// claim structure is decoded (same behaviour as [`JwtAuth`]).
#[cfg_attr(any(test, feature = "insecure"), allow(unused_variables))]
#[cfg_attr(any(test, feature = "insecure"), allow(clippy::unused_async))]
pub(crate) async fn verify_auth_verifier_jwt(
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
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::{collections::HashMap, sync::RwLock};

    use actix_web::dev::ServiceRequest;

    use super::*;

    /// Craft a minimal JWT with `HS256` header.
    ///
    /// In test/insecure builds `insecure_decode` is used, which skips signature
    /// validation but still requires a known algorithm in the header. `HS256` is
    /// the smallest valid choice. The signature segment is left as an empty dummy.
    fn make_test_jwt(sub: &str, roles: &[&str], domain: Option<&str>) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);

        let roles_json: String = {
            let parts: Vec<String> = roles.iter().map(|r| format!("\"{r}\"")).collect();
            format!("[{}]", parts.join(","))
        };
        let domain_json = domain.map_or_else(|| "null".to_owned(), |d| format!("\"{d}\""));
        let payload_str = format!(
            r#"{{"sub":"{sub}","roles":{roles_json},"as_rid":{domain_json},"exp":9999999999}}"#
        );
        let payload = URL_SAFE_NO_PAD.encode(payload_str);
        // Signature is ignored by `insecure_decode`; use a single underscore as placeholder.
        format!("{header}.{payload}._")
    }

    /// Build a no-op JWKS manager directly (no async, no Result).
    ///
    /// In test builds `insecure_decode` is used so the JWKS is never consulted;
    /// the empty struct is a valid stand-in.  Constructing it synchronously avoids
    /// `expect_used` / `panic_in_result_fn` lints.
    fn empty_jwks() -> Arc<JwksManager> {
        Arc::new(JwksManager {
            uris: vec![],
            jwks: RwLock::new(HashMap::new()),
            last_update: RwLock::new(None),
            last_force_refresh: RwLock::new(None),
            proxy_params: None,
            accept_invalid_certs: false,
        })
    }

    /// Build a `ServiceRequest` that carries a bare JWT in the `Authorization: Bearer` header.
    ///
    /// `handle_auth_verifier` uses `extract_bearer_token` which reads this header directly,
    /// so all full-pipeline tests below use this helper.
    fn srv_req_with_bearer(token: &str) -> ServiceRequest {
        actix_web::test::TestRequest::get()
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_srv_request()
    }

    /// Roles and domain are extracted correctly for a `SuperAdmin` JWT.
    #[tokio::test]
    async fn test_verify_auth_verifier_jwt_extracts_sub_roles_domain() {
        let token = make_test_jwt("super.admin@acme.com", &["SuperAdmin"], Some("acme.com"));
        let result = verify_auth_verifier_jwt(&empty_jwks(), &token).await;
        assert!(result.is_ok(), "JWT decode must succeed: {result:?}");
        if let Ok(claims) = result {
            assert_eq!(claims.sub, "super.admin@acme.com");
            assert_eq!(claims.roles, vec!["SuperAdmin"]);
            assert_eq!(claims.domain.as_deref(), Some("acme.com"));
        }
    }

    /// A `CryptoOfficer` JWT carries the correct role and domain.
    #[tokio::test]
    async fn test_verify_auth_verifier_jwt_crypto_officer_role() {
        let token = make_test_jwt("officer@acme.com", &["CryptoOfficer"], Some("acme.com"));
        let result = verify_auth_verifier_jwt(&empty_jwks(), &token).await;
        assert!(result.is_ok(), "JWT decode must succeed: {result:?}");
        if let Ok(claims) = result {
            assert_eq!(claims.roles, vec!["CryptoOfficer"]);
            assert_eq!(claims.domain.as_deref(), Some("acme.com"));
        }
    }

    /// Tokens without roles or domain must still parse (legacy format compatibility).
    #[tokio::test]
    async fn test_verify_auth_verifier_jwt_empty_roles_no_domain() {
        let token = make_test_jwt("user@acme.com", &[], None);
        let result = verify_auth_verifier_jwt(&empty_jwks(), &token).await;
        assert!(result.is_ok(), "JWT decode must succeed: {result:?}");
        if let Ok(claims) = result {
            assert_eq!(claims.sub, "user@acme.com");
            assert!(claims.roles.is_empty());
            assert!(claims.domain.is_none());
        }
    }

    /// The `as_domain` alias (pre-rename) is accepted for backward compatibility.
    #[tokio::test]
    async fn test_verify_auth_verifier_jwt_as_domain_alias() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            r#"{"sub":"officer@acme.com","roles":["CryptoOfficer"],"as_domain":"acme.com","exp":9999999999}"#,
        );
        let token = format!("{header}.{payload}._");
        let result = verify_auth_verifier_jwt(&empty_jwks(), &token).await;
        assert!(result.is_ok(), "JWT decode must succeed: {result:?}");
        if let Ok(claims) = result {
            assert_eq!(claims.domain.as_deref(), Some("acme.com"));
            assert_eq!(claims.roles, vec!["CryptoOfficer"]);
        }
    }

    /// `verify_auth_verifier_jwt` correctly propagates errors for a malformed token.
    #[tokio::test]
    async fn test_verify_auth_verifier_jwt_subject_wrapper() {
        let token = make_test_jwt("admin@acme.com", &["SuperAdmin"], Some("acme.com"));
        let result = verify_auth_verifier_jwt(&empty_jwks(), &token).await;
        assert!(result.is_ok(), "JWT decode must succeed: {result:?}");
        if let Ok(claims) = result {
            assert_eq!(claims.sub, "admin@acme.com");
        }
    }

    /// Multiple roles in the same JWT are all preserved.
    #[tokio::test]
    async fn test_verify_auth_verifier_jwt_multiple_roles() {
        let token = make_test_jwt(
            "multi@acme.com",
            &["CryptoOfficer", "Auditor"],
            Some("acme.com"),
        );
        let result = verify_auth_verifier_jwt(&empty_jwks(), &token).await;
        assert!(result.is_ok(), "JWT decode must succeed: {result:?}");
        if let Ok(claims) = result {
            assert_eq!(claims.roles, vec!["CryptoOfficer", "Auditor"]);
        }
    }

    // ── Full-pipeline tests for `handle_auth_verifier` ─────────────────────────
    //
    // The tests above verify only `verify_auth_verifier_jwt` (claim parsing).
    // The tests below exercise the full middleware pipeline:
    //
    //   `handle_auth_verifier`
    //     → `extract_bearer_token` (reads `Authorization: Bearer` header)
    //     → `verify_auth_verifier_jwt` (decodes + validates claims)
    //     → constructs `AuthenticatedUser{username, roles, domain}`
    //
    // They are the definitive proof that `domain` and `roles` survive all the
    // way from the JWT claim through to the struct that OPA and the permission
    // checks consume.

    /// `handle_auth_verifier` propagates `domain` from `as_rid` through to
    /// `AuthenticatedUser.domain` without dropping or mangling the value.
    #[tokio::test]
    async fn test_handle_auth_verifier_domain_propagated_to_authenticated_user() {
        let token = make_test_jwt("officer@acme.com", &["CryptoOfficer"], Some("acme.com"));
        let req = srv_req_with_bearer(&token);
        let result = handle_auth_verifier(&empty_jwks(), &req).await;
        assert!(
            result.is_ok(),
            "handle_auth_verifier must succeed: {result:?}"
        );
        let user = result.expect("already checked is_ok");
        assert_eq!(user.domain.as_deref(), Some("acme.com"));
    }

    /// `handle_auth_verifier` propagates `roles` through to
    /// `AuthenticatedUser.roles` without dropping any entry.
    #[tokio::test]
    async fn test_handle_auth_verifier_roles_propagated_to_authenticated_user() {
        let token = make_test_jwt("officer@acme.com", &["CryptoOfficer"], Some("acme.com"));
        let req = srv_req_with_bearer(&token);
        let result = handle_auth_verifier(&empty_jwks(), &req).await;
        assert!(
            result.is_ok(),
            "handle_auth_verifier must succeed: {result:?}"
        );
        let user = result.expect("already checked is_ok");
        assert_eq!(user.roles, vec!["CryptoOfficer"]);
    }

    /// `handle_auth_verifier` uses the `sub` claim as `AuthenticatedUser.username`.
    ///
    /// The Cosmian auth server puts the username in `sub`, not `email`.
    #[tokio::test]
    async fn test_handle_auth_verifier_sub_becomes_username() {
        let token = make_test_jwt("alice@acme.com", &["Auditor"], Some("acme.com"));
        let req = srv_req_with_bearer(&token);
        let result = handle_auth_verifier(&empty_jwks(), &req).await;
        assert!(
            result.is_ok(),
            "handle_auth_verifier must succeed: {result:?}"
        );
        let user = result.expect("already checked is_ok");
        assert_eq!(user.username.as_ref(), "alice@acme.com");
    }

    /// A missing `Authorization` header must cause `handle_auth_verifier` to
    /// return an error rather than proceeding with an empty identity.
    #[tokio::test]
    async fn test_handle_auth_verifier_missing_bearer_returns_error() {
        let req = actix_web::test::TestRequest::get().to_srv_request();
        let result = handle_auth_verifier(&empty_jwks(), &req).await;
        assert!(
            result.is_err(),
            "must fail when no Authorization header is present"
        );
    }

    /// When the JWT carries no `as_rid` / `as_domain` claim, `domain` must be
    /// `None` on the resulting `AuthenticatedUser` — not a spurious empty string
    /// or an error.
    #[tokio::test]
    async fn test_handle_auth_verifier_domain_none_when_claim_absent() {
        let token = make_test_jwt("user@acme.com", &["User"], None);
        let req = srv_req_with_bearer(&token);
        let result = handle_auth_verifier(&empty_jwks(), &req).await;
        assert!(
            result.is_ok(),
            "handle_auth_verifier must succeed: {result:?}"
        );
        let user = result.expect("already checked is_ok");
        assert!(
            user.domain.is_none(),
            "domain must be None when the claim is absent, got {:?}",
            user.domain
        );
    }
}
