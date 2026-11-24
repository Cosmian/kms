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

use actix_web::dev::ServiceRequest;
#[cfg(not(feature = "insecure"))]
use jsonwebtoken::Algorithm;
#[cfg(any(test, feature = "insecure"))]
use jsonwebtoken::dangerous;
#[cfg(not(feature = "insecure"))]
use jsonwebtoken::{DecodingKey, Header, Validation, decode, decode_header, jwk::Jwk};
use serde::Deserialize;

use super::AuthVerifierValidator;
use crate::{
    error::KmsError,
    middlewares::{
        AuthMethod, AuthenticatedUser, JwksManager, JwtTokenHeaders, UserId, extract_bearer_token,
        is_not_forgeable_cross_origin, reject_reserved_service_identity, request_cookie,
    },
    result::KResult,
};

/// Subset of JWT algorithms the Auth Verifier middleware accepts.
///
/// HS* algorithms are excluded: they use a shared secret and an attacker who
/// obtains the JWKS public key could forge tokens.
#[cfg(not(feature = "insecure"))]
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
/// the JWKS (these tokens carry no `kid`), then checks that its session is still live.
/// When no bearer token is present and `session_cookie_realm` is set, falls back to the
/// Auth Verifier `_ea_` session cookie, accepted only for that realm.
pub(super) async fn handle_auth_verifier(
    auth_verifier: &AuthVerifierValidator,
    req: &ServiceRequest,
    session_cookie_realm: Option<&str>,
    expected_realm: Option<&str>,
) -> KResult<AuthenticatedUser> {
    let token = match extract_bearer_token(req) {
        Ok(token) => token,
        Err(e) => {
            let (Some(realm), Some(cookie)) = (
                session_cookie_realm,
                request_cookie(req.headers(), AUTH_VERIFIER_SESSION_COOKIE),
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
            return Ok(AuthenticatedUser {
                username: authenticate_auth_verifier_session_cookie(auth_verifier, cookie, realm)
                    .await?,
                auth_method: AuthMethod::AuthVerifierSession,
            });
        }
    };

    let username =
        UserId::from(verify_auth_verifier_jwt_subject(auth_verifier, token, expected_realm).await?);
    reject_reserved_service_identity(&username)?;
    Ok(AuthenticatedUser {
        username,
        auth_method: AuthMethod::AuthVerifierJwt,
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
) -> KResult<UserId> {
    let claims = verify_auth_verifier_jwt(&auth_verifier.jwks, token).await?;
    if claims.realm_id.as_deref() != Some(expected_realm) {
        return Err(KmsError::Unauthorized(format!(
            "Auth Verifier: session cookie was not issued for realm `{expected_realm}`"
        )));
    }
    let username = UserId::try_new(claims.sub)
        .map_err(|e| KmsError::Unauthorized(format!("Auth Verifier: {e}")))?;
    reject_reserved_service_identity(&username)?;
    auth_verifier.ensure_live_session(token).await?;
    Ok(username)
}

/// Validate a Auth Verifier server JWT, check that its session is still live, and return
/// its `sub` claim (the authenticated username).
///
/// Shared between the bearer-token `AuthVerifier` middleware
/// (`handle_auth_verifier`) and the UI's BFF login proxy
/// (`crate::routes::ui_auth::login_as`), which validates the JWT the Cosmian
/// authentication server returns via `Set-Cookie: _ea_=<jwt>` before storing
/// the resulting username in the actix session. Keeping a single
/// implementation avoids the two call sites drifting apart on trust logic.
pub(crate) async fn verify_auth_verifier_jwt_subject(
    auth_verifier: &AuthVerifierValidator,
    token: &str,
    expected_realm: Option<&str>,
) -> KResult<String> {
    let claims = verify_auth_verifier_jwt(&auth_verifier.jwks, token).await?;
    if claims.realm_id.as_deref() == Some("_") {
        return Err(KmsError::Unauthorized(
            "Auth Verifier: tokens of the admin realm are not accepted".to_owned(),
        ));
    }
    if let Some(realm) = expected_realm
        && claims.realm_id.as_deref() != Some(realm)
    {
        return Err(KmsError::Unauthorized(format!(
            "Auth Verifier: token was not issued for realm `{realm}`"
        )));
    }
    auth_verifier.ensure_live_session(token).await?;
    Ok(claims.sub)
}

/// Validate a Auth Verifier server JWT and return its claims.
///
/// In test / insecure builds the signature check is skipped (same behaviour
/// as the existing `JwtAuth` middleware).
#[cfg(any(test, feature = "insecure"))]
fn verify_auth_verifier_jwt(
    _jwks_manager: &Arc<JwksManager>,
    token: &str,
) -> std::future::Ready<KResult<AuthVerifierClaims>> {
    // Synchronous body in a `Ready` so the async signature of the production build is kept
    // without an `.await`-less `async fn`.
    fn decode_only(token: &str) -> KResult<AuthVerifierClaims> {
        // RFC 7515 §4.1.11: `jsonwebtoken` ignores `crit`, so enforce it here, in every build.
        JwtTokenHeaders::from_token(token)?.reject_unsupported_extensions()?;
        let token_data = dangerous::insecure_decode::<AuthVerifierClaims>(token).map_err(|e| {
            KmsError::Unauthorized(format!("Auth Verifier: cannot decode token: {e}"))
        })?;
        Ok(token_data.claims)
    }
    std::future::ready(decode_only(token))
}

/// Production variant of [`verify_auth_verifier_jwt`]: full signature validation.
#[cfg(all(not(test), not(feature = "insecure")))]
async fn verify_auth_verifier_jwt(
    jwks_manager: &Arc<JwksManager>,
    token: &str,
) -> KResult<AuthVerifierClaims> {
    verify_signed_auth_verifier_jwt(jwks_manager, token).await
}

/// Validate the signature of a Auth Verifier server JWT against its JWKS.
///
/// The JWKS is refreshed periodically (throttled). When no cached key validates the token,
/// it is fetched once more outside that throttle (but within the `force_refresh` cooldown)
/// and the keys are tried again, so that a rotation of the signing key of the Auth
/// Verifier is picked up without waiting for the next periodic refresh.
#[cfg(not(feature = "insecure"))]
async fn verify_signed_auth_verifier_jwt(
    jwks_manager: &JwksManager,
    token: &str,
) -> KResult<AuthVerifierClaims> {
    // RFC 7515 §4.1.11: `jsonwebtoken` ignores `crit`, so enforce it here, in every build.
    JwtTokenHeaders::from_token(token)?.reject_unsupported_extensions()?;

    let header = decode_header(token).map_err(|e| {
        KmsError::Unauthorized(format!("Auth Verifier: cannot decode token header: {e}"))
    })?;

    if !ALLOWED_ALGORITHMS.contains(&header.alg) {
        return Err(KmsError::Unauthorized(format!(
            "Auth Verifier: algorithm {:?} is not permitted; only asymmetric algorithms (RS*, ES*, PS*) are accepted",
            header.alg
        )));
    }

    jwks_manager.refresh().await?;
    let mut outcome = verify_with_cached_keys(jwks_manager, token, &header)?;
    if outcome.is_err() {
        jwks_manager.force_refresh().await?;
        outcome = verify_with_cached_keys(jwks_manager, token, &header)?;
    }
    outcome.map_err(KmsError::Unauthorized)
}

/// Verify `token` against the cached keys: the one named by the `kid` header when there is
/// one, otherwise every key in turn (these tokens usually carry no `kid`).
///
/// The inner `Err` is the message of the signature failure.
#[cfg(not(feature = "insecure"))]
fn verify_with_cached_keys(
    jwks_manager: &JwksManager,
    token: &str,
    header: &Header,
) -> KResult<Result<AuthVerifierClaims, String>> {
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
                Ok(claims) => return Ok(Ok(claims)),
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
            return Ok(Ok(claims));
        }
    }

    Ok(Err(format!(
        "Auth Verifier: token signature validation failed against all {} JWKS key(s): {}",
        tried_keys,
        last_error.unwrap_or_else(|| "no keys available".to_owned())
    )))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::{
        AUTH_VERIFIER_SESSION_COOKIE, AuthVerifierValidator,
        authenticate_auth_verifier_session_cookie, verify_auth_verifier_jwt_subject,
    };
    use crate::{
        config::AuthVerifierConfig,
        error::KmsError,
        middlewares::{JwksManager, UserId},
        routes::aws_xks::AWS_XKS_SERVICE_USER,
    };

    fn token(header: &str) -> String {
        format!(
            "{}.{}.c2ln",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(r#"{"sub":"alice"}"#)
        )
    }

    async fn verify(header: &str) -> crate::result::KResult<String> {
        verify_auth_verifier_jwt_subject(&*live_auth_verifier().await, &token(header), None).await
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
        let sub = verify(r#"{"alg":"RS256","typ":"JWT"}"#)
            .await
            .expect("a plain token must be accepted in test builds");
        assert_eq!(sub, "alice");
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
        let error = verify_auth_verifier_jwt_subject(&ended, &token, None)
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
        assert_eq!(user, UserId::from("alice@example.com"));
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

    /// F-004 (#1486): bearer tokens of the `_` admin realm never authenticate, and when an
    /// `auth_verifier_realm` is configured, bearer tokens of any other realm (or none) are
    /// rejected too. Both checks run before the session liveness lookup.
    #[tokio::test]
    async fn bearer_token_of_another_or_admin_realm_is_rejected() {
        let auth_verifier = live_auth_verifier().await;
        for expected in [None, Some("kms-api")] {
            let token = auth_verifier_token("alice@example.com", Some("_"));
            let error = verify_auth_verifier_jwt_subject(&auth_verifier, &token, expected)
                .await
                .expect_err("a bearer token of the admin realm must be rejected");
            assert!(
                matches!(&error, KmsError::Unauthorized(m) if m.contains("admin realm")),
                "{expected:?}: {error}"
            );
        }
        for realm in [Some("other-app"), Some(""), None] {
            let token = auth_verifier_token("alice@example.com", realm);
            let error = verify_auth_verifier_jwt_subject(&auth_verifier, &token, Some("kms-api"))
                .await
                .expect_err("a bearer token of another realm must be rejected");
            assert!(
                matches!(&error, KmsError::Unauthorized(m) if m.contains("realm `kms-api`")),
                "{realm:?}: {error}"
            );
        }

        let token = auth_verifier_token("alice@example.com", Some("kms-api"));
        let sub = verify_auth_verifier_jwt_subject(&auth_verifier, &token, Some("kms-api"))
            .await
            .expect("a bearer token of the configured realm must be accepted");
        assert_eq!(sub, "alice@example.com");
        for realm in [Some("other-app"), None] {
            let token = auth_verifier_token("alice@example.com", realm);
            let sub = verify_auth_verifier_jwt_subject(&auth_verifier, &token, None)
                .await
                .expect("without a configured realm, a non-admin realm must be accepted");
            assert_eq!(sub, "alice@example.com", "{realm:?}");
        }

        // The realm checks precede the liveness lookup: the realm error wins on an ended session.
        let ended = mock_auth_verifier(Arc::new(AtomicBool::new(false))).await;
        let token = auth_verifier_token("alice@example.com", Some("_"));
        let error = verify_auth_verifier_jwt_subject(&ended, &token, None)
            .await
            .expect_err("a bearer token of the admin realm must be rejected");
        assert!(error.to_string().contains("admin realm"), "{error}");
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

    /// Signature validation against a JWKS that rotates (the other tests skip signatures).
    #[cfg(not(feature = "insecure"))]
    mod signed {
        use std::sync::atomic::AtomicUsize;

        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        use openssl::rsa::Rsa;

        use super::{
            Arc, AsyncReadExt, AsyncWriteExt, Engine, JwksManager, KmsError, Ordering, TcpListener,
            URL_SAFE_NO_PAD,
        };
        use crate::middlewares::auth_verifier::token::verify_signed_auth_verifier_jwt;

        fn jwks_of(rsa: &Rsa<openssl::pkey::Private>) -> String {
            serde_json::json!({"keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
                "e": URL_SAFE_NO_PAD.encode(rsa.e().to_vec()),
            }]})
            .to_string()
        }

        /// Serve `bodies[i]` to the i-th request (the last one afterwards); returns the URL.
        async fn jwks_server(bodies: Vec<String>, hits: Arc<AtomicUsize>) -> String {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let port = listener.local_addr().expect("local address").port();
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let mut buf = vec![0_u8; 4096];
                    drop(stream.read(&mut buf).await);
                    let index = hits.fetch_add(1, Ordering::SeqCst);
                    let body = bodies
                        .get(index)
                        .or(bodies.last())
                        .cloned()
                        .unwrap_or_default();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    drop(stream.write_all(response.as_bytes()).await);
                }
            });
            format!("http://127.0.0.1:{port}/jwks.json")
        }

        /// A `kid`-less RS256 token, as the Auth Verifier issues them.
        fn token_signed_by(rsa: &Rsa<openssl::pkey::Private>) -> String {
            let key = EncodingKey::from_rsa_der(&rsa.private_key_to_der().expect("DER key"));
            let claims = serde_json::json!({"sub": "alice", "exp": 4_102_444_800_u64});
            encode(&Header::new(Algorithm::RS256), &claims, &key).expect("sign test JWT")
        }

        /// F-036: a token signed by a key published after the last (throttled) refresh must
        /// validate: the keys are fetched again once the cached ones failed.
        #[tokio::test]
        async fn rotated_signing_key_is_picked_up_on_failure() {
            let (old, new) = (
                Rsa::generate(2048).expect("RSA key"),
                Rsa::generate(2048).expect("RSA key"),
            );
            let hits = Arc::new(AtomicUsize::new(0));
            let url = jwks_server(vec![jwks_of(&old), jwks_of(&new)], hits.clone()).await;
            let manager = JwksManager::new(vec![url], None)
                .await
                .expect("JWKS manager");

            let claims = verify_signed_auth_verifier_jwt(&manager, &token_signed_by(&new))
                .await
                .expect("the rotated key must be fetched and accepted");

            assert_eq!(claims.sub, "alice");
            assert_eq!(hits.load(Ordering::SeqCst), 2);
        }

        /// A token signed by a key the Auth Verifier never published is still rejected, after
        /// a single forced refresh.
        #[tokio::test]
        async fn token_of_an_unknown_key_is_rejected() {
            let (published, rogue) = (
                Rsa::generate(2048).expect("RSA key"),
                Rsa::generate(2048).expect("RSA key"),
            );
            let hits = Arc::new(AtomicUsize::new(0));
            let url = jwks_server(vec![jwks_of(&published)], hits.clone()).await;
            let manager = JwksManager::new(vec![url], None)
                .await
                .expect("JWKS manager");

            let error = verify_signed_auth_verifier_jwt(&manager, &token_signed_by(&rogue))
                .await
                .expect_err("a token of an unknown key must be rejected");

            assert!(matches!(error, KmsError::Unauthorized(_)), "{error}");
            assert_eq!(hits.load(Ordering::SeqCst), 2);
        }
    }
}
