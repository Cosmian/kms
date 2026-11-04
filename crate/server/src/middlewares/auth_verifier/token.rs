//! Auth Verifier Token Validation
//!
//! Validates bearer tokens and `_ea_` session cookies issued by the Auth Verifier server:
//! signature against its JWKS, then liveness of the session against the Auth Verifier
//! itself (see [`super::session`]), so logout and revocation are enforced by the KMS.
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

use actix_web::{
    dev::ServiceRequest,
    http::{Method, header::CONTENT_TYPE},
};
#[cfg(all(not(test), not(feature = "insecure")))]
use jsonwebtoken::Algorithm;
#[cfg(any(test, feature = "insecure"))]
use jsonwebtoken::dangerous;
#[cfg(all(not(test), not(feature = "insecure")))]
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header, jwk::Jwk};
use serde::Deserialize;

use super::AuthVerifierValidator;
use crate::{
    error::KmsError,
    middlewares::{
        AuthMethod, AuthenticatedUser, JwksManager, JwtTokenHeaders, UserId, extract_bearer_token,
        reject_reserved_service_identity,
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
    /// The auth server sets this as `as_rid` (realm ID). The legacy `as_domain`
    /// claim is also accepted for tokens issued before the field was renamed.
    #[serde(alias = "as_domain", alias = "as_rid")]
    pub domain: Option<String>,
}

/// Name of the session cookie set by the Auth Verifier server; it carries the session JWT.
pub(crate) const AUTH_VERIFIER_SESSION_COOKIE: &str = "_ea_";

/// Core authentication handler for Auth Verifier server tokens.
///
/// Validates the bearer token from the `Authorization` header against every key in
/// the JWKS (these tokens carry no `kid`), then checks that its session is still live.
/// When no bearer token is present and `session_cookie_realm` is set, falls back to the
/// Auth Verifier `_ea_` session cookie, accepted only for that realm. Full token
/// claims are copied into [`AuthenticatedUser`] so OPA receives the same context
/// for bearer and browser-session authentication.
pub(super) async fn handle_auth_verifier(
    auth_verifier: &AuthVerifierValidator,
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
            if !is_not_forgeable_cross_origin(req) {
                return Err(KmsError::Unauthorized(
                    "Auth Verifier: a state-changing request authenticated by the session cookie \
                     must have an `application/json` or `application/octet-stream` Content-Type"
                        .to_owned(),
                ));
            }
            return authenticate_auth_verifier_session_cookie(auth_verifier, cookie.value(), realm)
                .await;
        }
    };

    let claims = verify_auth_verifier_jwt(&auth_verifier.jwks, token).await?;
    auth_verifier.ensure_live_session(token).await?;
    let username = UserId::try_new(claims.sub)
        .map_err(|e| KmsError::Unauthorized(format!("Auth Verifier: {e}")))?;
    reject_reserved_service_identity(&username)?;
    Ok(AuthenticatedUser {
        username,
        auth_method: AuthMethod::AuthVerifierJwt,
        domain: claims.domain,
        roles: claims.roles,
    })
}

/// CSRF guard for the ambient `_ea_` cookie: a safe method, or a body whose Content-Type is
/// not CORS-safelisted (`text/plain`, form types), so that a cross-origin page, including
/// one on a same-site sibling origin the `SameSite=Strict` cookie is still sent to, cannot
/// forge it without a CORS preflight, which the allow-list CORS of the API scopes refuses.
fn is_not_forgeable_cross_origin(req: &ServiceRequest) -> bool {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    req.headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|essence| {
            essence.eq_ignore_ascii_case("application/json")
                || essence.eq_ignore_ascii_case("application/octet-stream")
        })
}

/// Validate an Auth Verifier `_ea_` session cookie and return the authenticated user.
///
/// Unlike bearer tokens, a browser cookie is sent ambiently, so the token must have
/// been issued for `expected_realm`: a session from any other realm of the same
/// Auth Verifier (another application, the admin realm, ...) is rejected. The session
/// must still be live on the Auth Verifier.
pub(crate) async fn authenticate_auth_verifier_session_cookie(
    auth_verifier: &AuthVerifierValidator,
    token: &str,
    expected_realm: &str,
) -> KResult<AuthenticatedUser> {
    let claims = verify_auth_verifier_jwt(&auth_verifier.jwks, token).await?;
    if claims.domain.as_deref() != Some(expected_realm) {
        return Err(KmsError::Unauthorized(format!(
            "Auth Verifier: session cookie was not issued for realm `{expected_realm}`"
        )));
    }
    let username = UserId::try_new(claims.sub)
        .map_err(|e| KmsError::Unauthorized(format!("Auth Verifier: {e}")))?;
    reject_reserved_service_identity(&username)?;
    auth_verifier.ensure_live_session(token).await?;
    Ok(AuthenticatedUser {
        username,
        auth_method: AuthMethod::AuthVerifierSession,
        roles: claims.roles,
        domain: claims.domain,
    })
}

fn reject_unsupported_auth_verifier_jwt_extensions(token: &str) -> KResult<()> {
    // RFC 7515 §4.1.11: `jsonwebtoken` ignores `crit`, so enforce it here, in every build.
    JwtTokenHeaders::from_token(token)?.reject_unsupported_extensions()?;
    Ok(())
}

#[cfg(any(test, feature = "insecure"))]
fn validate_auth_verifier_jwt_signature(
    _jwks_manager: &Arc<JwksManager>,
    token: &str,
) -> impl std::future::Future<Output = KResult<AuthVerifierClaims>> {
    let result = dangerous::insecure_decode::<AuthVerifierClaims>(token)
        .map(|token_data| token_data.claims)
        .map_err(|e| KmsError::Unauthorized(format!("Auth Verifier: cannot decode token: {e}")));
    std::future::ready(result)
}

#[cfg(all(not(test), not(feature = "insecure")))]
async fn validate_auth_verifier_jwt_signature(
    jwks_manager: &Arc<JwksManager>,
    token: &str,
) -> KResult<AuthVerifierClaims> {
    let header = decode_header(token).map_err(|e| {
        KmsError::Unauthorized(format!("Auth Verifier: cannot decode token header: {e}"))
    })?;

    if !ALLOWED_ALGORITHMS.contains(&header.alg) {
        return Err(KmsError::Unauthorized(format!(
            "Auth Verifier: algorithm {:?} is not permitted; only asymmetric algorithms (RS*, ES*, PS*) are accepted",
            header.alg
        )));
    }

    // Look up key by kid if header provides it, otherwise try all keys without cloning the cache.
    if jwks_manager.is_empty()? {
        // JWKS cache is empty — the initial fetch at startup may have failed, or the
        // IdP may have been unreachable. Force a refresh, bypassing the normal
        // throttle: a plain `refresh()` call could be a no-op here for up to
        // `REFRESH_INTERVAL` seconds if `last_update` was already set by that earlier
        // failed attempt, even though the cache never got populated.
        jwks_manager.force_refresh().await?;
    }

    let mut last_error: Option<String> = None;
    let mut tried_keys = 0_usize;

    let validate_with_jwk = |jwk: &Jwk| -> Result<AuthVerifierClaims, String> {
        let decoding_key =
            DecodingKey::from_jwk(jwk).map_err(|e| format!("cannot build decoding key: {e}"))?;

        let mut validation = Validation::new(header.alg);
        validation.algorithms = vec![header.alg];
        // Do not validate issuer — the Auth Verifier server may not set `iss`.
        validation.set_issuer::<String>(&[]);
        validation.validate_exp = true;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        validation.set_required_spec_claims(&["sub", "exp"]);

        decode::<AuthVerifierClaims>(token, &decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| format!("{e}"))
    };

    if let Some(kid) = header.kid.as_deref() {
        if let Some(jwk) = jwks_manager.find(kid)? {
            match validate_with_jwk(&jwk) {
                Ok(claims) => return Ok(claims),
                Err(e) => last_error = Some(e),
            }
            tried_keys = 1;
        }
    } else {
        let verified = jwks_manager.find_map_key(|jwk| {
            tried_keys += 1;
            match validate_with_jwk(jwk) {
                Ok(claims) => Some(claims),
                Err(e) => {
                    last_error = Some(e);
                    None
                }
            }
        })?;
        if let Some(claims) = verified {
            return Ok(claims);
        }
    }

    Err(KmsError::Unauthorized(format!(
        "Auth Verifier: token signature validation failed against all {} JWKS key(s): {}",
        tried_keys,
        last_error.unwrap_or_else(|| "no keys available".to_owned())
    )))
}

/// Validate a Cosmian Auth Verifier JWT and return its full claims.
///
/// The returned claims include the subject, roles, and realm/domain, and are shared by bearer
/// and session-cookie authentication paths. In test / insecure builds the signature check is
/// skipped; only the claim structure is decoded.
pub(crate) async fn verify_auth_verifier_jwt(
    jwks_manager: &Arc<JwksManager>,
    token: &str,
) -> KResult<AuthVerifierClaims> {
    reject_unsupported_auth_verifier_jwt_extensions(token)?;
    validate_auth_verifier_jwt_signature(jwks_manager, token).await
}

/// Validate a bearer token, ensure its Auth Verifier session is still live, and return `sub`.
///
/// The UI BFF uses this helper when it needs only the subject; the Auth Verifier middleware
/// validates the same claims directly so it can also retain roles and domain for OPA.
#[cfg(test)]
async fn verify_auth_verifier_jwt_subject(
    auth_verifier: &AuthVerifierValidator,
    token: &str,
) -> KResult<String> {
    let claims = verify_auth_verifier_jwt(&auth_verifier.jwks, token).await?;
    auth_verifier.ensure_live_session(token).await?;
    Ok(claims.sub)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
pub(crate) mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Arc, RwLock,
            atomic::{AtomicBool, Ordering},
        },
    };

    use actix_web::dev::ServiceRequest;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{
        config::AuthVerifierConfig,
        error::KmsError,
        middlewares::{JwksManager, UserId},
        routes::aws_xks::AWS_XKS_SERVICE_USER,
    };

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

    async fn handle_auth_verifier_live(req: &ServiceRequest) -> KResult<AuthenticatedUser> {
        let auth_verifier = live_auth_verifier().await;
        handle_auth_verifier(&auth_verifier, req, None).await
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
        let result = handle_auth_verifier_live(&req).await;
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
        let result = handle_auth_verifier_live(&req).await;
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
        let result = handle_auth_verifier_live(&req).await;
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
        let result = handle_auth_verifier_live(&req).await;
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
        let result = handle_auth_verifier_live(&req).await;
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

    /// Build a signature-less token with the given JOSE header and the subject `alice`.
    fn token_with_header(header: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        format!(
            "{}.{}.c2ln",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(r#"{"sub":"alice"}"#)
        )
    }

    async fn verify(header: &str) -> KResult<AuthVerifierClaims> {
        verify_auth_verifier_jwt(&empty_jwks(), &token_with_header(header)).await
    }

    #[tokio::test]
    async fn token_with_crit_header_is_rejected() {
        let err = verify(r#"{"alg":"RS256","crit":["b64"],"b64":false}"#)
            .await
            .expect_err("a token with `crit` must be rejected");
        assert!(err.to_string().contains("critical"), "{err}");
    }

    #[tokio::test]
    async fn nested_jwt_is_rejected() {
        let err = verify(r#"{"alg":"RS256","cty":"JWT"}"#)
            .await
            .expect_err("a nested JWT must be rejected");
        assert!(err.to_string().contains("Nested"), "{err}");
    }

    #[tokio::test]
    async fn plain_token_still_yields_its_subject() {
        let claims = verify(r#"{"alg":"RS256","typ":"JWT"}"#)
            .await
            .expect("a plain token must be accepted in test builds");
        assert_eq!(claims.sub, "alice");
    }

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

    /// A validator of a mock Auth Verifier whose `GET /whoami` answers 200 to an `_ea_`
    /// cookie while `live` is set (the session exists), and 401 otherwise.
    pub(crate) async fn mock_auth_verifier(live: Arc<AtomicBool>) -> Arc<AuthVerifierValidator> {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local address").port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0_u8; 8192];
                let read = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(buf.get(..read).unwrap_or_default());
                let status = if live.load(Ordering::SeqCst)
                    && request.starts_with("GET /whoami ")
                    && request.contains(&format!("{AUTH_VERIFIER_SESSION_COOKIE}="))
                {
                    "200 OK"
                } else {
                    "401 Unauthorized"
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("mock Auth Verifier response");
            }
        });
        let jwks = Arc::new(
            JwksManager::new(vec![], None)
                .await
                .expect("empty JwksManager must build without network access"),
        );
        let config = AuthVerifierConfig {
            auth_verifier_url: Some(format!("http://127.0.0.1:{port}")),
            ..AuthVerifierConfig::default()
        };
        Arc::new(AuthVerifierValidator::new(jwks, &config).expect("Auth Verifier validator"))
    }

    /// A validator of a mock Auth Verifier on which every session is live.
    pub(crate) async fn live_auth_verifier() -> Arc<AuthVerifierValidator> {
        mock_auth_verifier(Arc::new(AtomicBool::new(true))).await
    }

    /// Regression: a correctly signed token whose Auth Verifier session ended (logout,
    /// revocation, idle timeout) must no longer authenticate, as a cookie or a bearer.
    #[tokio::test]
    async fn token_of_ended_session_is_rejected() {
        let ended = mock_auth_verifier(Arc::new(AtomicBool::new(false))).await;
        let token = auth_verifier_token("alice@example.com", Some("kms-saml"));
        let error = authenticate_auth_verifier_session_cookie(&ended, &token, "kms-saml")
            .await
            .expect_err("the cookie of an ended session must be rejected");
        assert!(matches!(error, KmsError::Unauthorized(_)), "{error}");
        let error = verify_auth_verifier_jwt_subject(&ended, &token)
            .await
            .expect_err("the bearer token of an ended session must be rejected");
        assert!(matches!(error, KmsError::Unauthorized(_)), "{error}");
    }

    #[tokio::test]
    async fn session_cookie_of_configured_realm_is_accepted() {
        let token = auth_verifier_token("alice@example.com", Some("kms-saml"));
        let user = authenticate_auth_verifier_session_cookie(
            &*live_auth_verifier().await,
            &token,
            "kms-saml",
        )
        .await
        .expect("cookie of the configured realm must be accepted");
        assert_eq!(user.username, UserId::from("alice@example.com"));
    }

    /// Security: sessions of other realms of the same Auth Verifier (other applications,
    /// the `_` admin realm) or without a realm claim must never authenticate to the KMS.
    #[tokio::test]
    async fn session_cookie_of_another_or_no_realm_is_rejected() {
        let auth_verifier = live_auth_verifier().await;
        for realm in [Some("other-app"), Some("_"), Some(""), None] {
            let token = auth_verifier_token("alice@example.com", realm);
            let error =
                authenticate_auth_verifier_session_cookie(&auth_verifier, &token, "kms-saml")
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
        let auth_verifier = live_auth_verifier().await;
        for sub in ["", AWS_XKS_SERVICE_USER] {
            let token = auth_verifier_token(sub, Some("kms-saml"));
            let error =
                authenticate_auth_verifier_session_cookie(&auth_verifier, &token, "kms-saml")
                    .await
                    .expect_err("empty or reserved subject must be rejected");
            assert!(matches!(error, KmsError::Unauthorized(_)), "{sub}: {error}");
        }
    }

    #[tokio::test]
    async fn malformed_session_cookie_is_rejected() {
        let error = authenticate_auth_verifier_session_cookie(
            &*live_auth_verifier().await,
            "not-a-jwt",
            "kms-saml",
        )
        .await
        .expect_err("a malformed cookie must be rejected");
        assert!(matches!(error, KmsError::Unauthorized(_)));
    }
}
