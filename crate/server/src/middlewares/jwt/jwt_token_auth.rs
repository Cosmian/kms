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
    middlewares::{
        AuthMethod, AuthenticatedUser, UserId, jwt::JwtConfig, reject_reserved_aws_xks_identity,
    },
    result::KResult,
};

/// URI scheme prefix identifying a SPIFFE ID (e.g. `spiffe://example.org/ns/foo/sa/bar`),
/// as carried by the `sub` claim of a SPIFFE JWT-SVID.
const SPIFFE_ID_PREFIX: &str = "spiffe://";

/// `true` when `sub` is a SPIFFE ID: the `spiffe://` scheme followed by a non-empty trust
/// domain (a bare `spiffe://` or `spiffe:///path` never names a workload).
fn is_spiffe_id(sub: &str) -> bool {
    sub.strip_prefix(SPIFFE_ID_PREFIX)
        .and_then(|rest| rest.split('/').next())
        .is_some_and(|trust_domain| !trust_domain.is_empty())
}

/// Attempts to extract and validate a user claim from a JWT token
///
/// Tries each provided JWT configuration until one successfully validates the token or all configurations fail.
///
/// # Parameters
/// * `configs` - List of JWT configurations to try
/// * `token` - The JWT token string
///
/// # Returns
/// * `Ok((UserClaim, bool))` - Successfully validated user claim, plus the
///   `accept_spiffe_subject` flag of the configuration that validated it
/// * `Err(Vec<KmsError>)` - List of errors from failed validation attempts
fn extract_user_claim(
    configs: &[JwtConfig],
    token: &str,
) -> Result<(UserClaim, bool), Vec<KmsError>> {
    let mut jwt_log_errors = Vec::new();

    // Try each JWT configuration until one succeeds
    for idp_config in configs {
        match idp_config.decode_bearer_header(token) {
            Ok(user_claim) => return Ok((user_claim, idp_config.accept_spiffe_subject)),
            Err(error) => {
                jwt_log_errors.push(error);
            }
        }
    }

    // If all configurations failed, return the collected errors
    Err(jwt_log_errors)
}

/// Build the [`AuthenticatedUser`] for a validated SPIFFE JWT-SVID claim set.
///
/// Requirements, on top of the signature/issuer/expiry/audience checks already done by
/// [`JwtConfig::validate_authentication_token`]:
/// * `sub` MUST be a SPIFFE ID (`spiffe://...`);
/// * `aud` MUST be present and non-empty. `jsonwebtoken` only compares `aud` when the claim
///   is present, so without this check an SVID minted for *another* service (or one without
///   any audience) could be replayed against the KMS. The SPIFFE JWT-SVID specification
///   requires validators to reject SVIDs whose audience does not include their own.
fn spiffe_authenticated_user(user_claim: &UserClaim) -> KResult<AuthenticatedUser> {
    let sub = user_claim
        .sub
        .as_deref()
        .filter(|sub| is_spiffe_id(sub))
        .ok_or_else(|| {
            KmsError::InvalidRequest("JWT-SVID subject must be a spiffe:// ID".to_owned())
        })?;
    if !user_claim
        .aud
        .as_ref()
        .is_some_and(|aud| aud.iter().any(|audience| !audience.is_empty()))
    {
        warn!("JWT-SVID for {sub} rejected: missing or empty 'aud' claim");
        return Err(KmsError::InvalidRequest(
            "JWT-SVID must carry a non-empty 'aud' claim".to_owned(),
        ));
    }
    debug!("JWT-SVID access granted to {sub}!");
    let username = UserId::from(sub.to_owned());
    reject_reserved_aws_xks_identity(&username)?;
    Ok(AuthenticatedUser {
        username,
        auth_method: AuthMethod::JwtSvid,
    })
}

/// Resolve an [`AuthenticatedUser`] from a successfully validated JWT claim set.
///
/// `email` takes priority when present (standard OIDC/IdP flow, unchanged behaviour). When
/// `email` is absent, falls back to the `sub` claim **only if** `accept_spiffe_subject` is
/// `true` (the issuer's config opted in via `--jwt-svid-auth`) **and** `sub` is a SPIFFE ID
/// (`spiffe://...`), i.e. a SPIFFE JWT-SVID (see [`spiffe_authenticated_user`]). Every other
/// case is rejected, preserving the pre-existing "no email in JWT" behaviour.
fn resolve_authenticated_user(
    user_claim: &UserClaim,
    accept_spiffe_subject: bool,
) -> KResult<AuthenticatedUser> {
    if let Some(email) = user_claim.email.as_deref() {
        // Authentication successful with valid email
        debug!("JWT Access granted to {email}!");
        let username = UserId::from(email.to_owned());
        reject_reserved_aws_xks_identity(&username)?;
        return Ok(AuthenticatedUser {
            username,
            auth_method: AuthMethod::OidcJwt,
        });
    }
    let has_spiffe_subject = user_claim
        .sub
        .as_deref()
        .is_some_and(is_spiffe_id);
    if accept_spiffe_subject && has_spiffe_subject {
        // SPIFFE JWT-SVID: no email claim, but a validated spiffe:// subject and the
        // issuer's config explicitly opted in via `--jwt-svid-auth`.
        return spiffe_authenticated_user(user_claim);
    }
    // JWT is valid but missing the required email claim (and either SPIFFE JWT-SVID
    // support is not enabled for this issuer, or `sub` is not a spiffe:// URI)
    warn!("no email in JWT");
    Err(KmsError::InvalidRequest("No email in JWT".to_owned()))
}

/// Validate `token` against every SPIFFE-enabled configuration, returning the first
/// successfully validated claim set or the collected validation errors.
fn extract_svid_claim(
    spiffe_configs: &[&JwtConfig],
    token: &str,
) -> Result<UserClaim, Vec<KmsError>> {
    let mut errors = Vec::new();
    for config in spiffe_configs {
        match config.validate_authentication_token(token, true) {
            Ok(claim) => return Ok(claim),
            Err(error) => errors.push(error),
        }
    }
    Err(errors)
}

/// Validate a raw JWT-SVID token (no "Bearer " prefix, no `Authorization` header)
/// against the SPIFFE-JWT-SVID-enabled issuers and resolve an `AuthenticatedUser`.
///
/// Used by the Web UI's `/ui/login_svid` endpoint so a browser session can be established
/// with a SPIRE-issued JWT-SVID, reusing the same issuer/JWKS validation as the bearer-token
/// path (`handle_jwt`) without requiring the Authorization header framing.
///
/// Unlike the bearer path this endpoint only ever accepts SPIFFE subjects: a token that
/// merely carries an `email` claim is rejected, so `/ui/login_svid` cannot be used to turn an
/// ordinary OIDC bearer token into a 24h browser session.
///
/// When validation fails, the JWKS is refreshed once (throttled) and validation retried, so a
/// SPIRE signing-key rotation, or a JWKS endpoint that was unreachable at startup, does not
/// break the login until the next restart.
pub(crate) async fn validate_jwt_svid(
    configs: &[JwtConfig],
    token: &str,
) -> KResult<AuthenticatedUser> {
    let spiffe_configs: Vec<&JwtConfig> = configs
        .iter()
        .filter(|config| config.accept_spiffe_subject)
        .collect();

    let mut claim = extract_svid_claim(&spiffe_configs, token);
    if claim.is_err() {
        if let Some(config) = spiffe_configs.first() {
            if let Err(error) = config.jwks.refresh().await {
                warn!("JWKS refresh failed while validating a JWT-SVID: {error:?}");
            }
        }
        claim = extract_svid_claim(&spiffe_configs, token);
    }

    match claim {
        Ok(user_claim) => spiffe_authenticated_user(&user_claim),
        Err(errors) => {
            for error in &errors {
                warn!("{error:?}");
            }
            Err(KmsError::InvalidRequest("bad JWT-SVID".to_owned()))
        }
    }
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

    match private_claim {
        Ok((user_claim, accept_spiffe_subject)) => {
            resolve_authenticated_user(&user_claim, accept_spiffe_subject).inspect_err(|error| {
                warn!(
                    "{:?} {} 401 unauthorized: {error}",
                    req.method(),
                    req.path()
                );
            })
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
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    use super::{
        AuthMethod, JwtConfig, UserClaim, extract_user_claim, resolve_authenticated_user,
        validate_jwt_svid,
    };
    use crate::middlewares::{UserId, jwt::JwksManager};

    const SPIFFE_ID: &str = "spiffe://example.org/ns/foo/sa/bar";

    fn claim(sub: Option<&str>, email: Option<&str>) -> UserClaim {
        UserClaim {
            email: email.map(str::to_owned),
            iss: None,
            sub: sub.map(str::to_owned),
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

    /// A SPIFFE JWT-SVID claim set: `spiffe://` subject, no `email`, with an audience.
    fn svid_claim(sub: &str) -> UserClaim {
        UserClaim {
            aud: Some(vec!["cosmian-kms".to_owned()]),
            ..claim(Some(sub), None)
        }
    }

    /// Existing OIDC behaviour must be unaffected: `email` present is always accepted,
    /// regardless of `accept_spiffe_subject`.
    #[test]
    fn email_claim_is_accepted_and_takes_priority() {
        let user_claim = claim(Some(SPIFFE_ID), Some("a@b.com"));
        let user = resolve_authenticated_user(&user_claim, true).expect("must be accepted");
        assert_eq!(user.username, UserId::from("a@b.com"));
        assert_eq!(user.auth_method, AuthMethod::OidcJwt);
    }

    /// A SPIFFE JWT-SVID (`sub = spiffe://...`, no `email`) is accepted only when
    /// `accept_spiffe_subject` is enabled — this is the `--jwt-svid-auth` opt-in flag.
    #[test]
    fn spiffe_subject_accepted_when_flag_enabled() {
        let user = resolve_authenticated_user(&svid_claim(SPIFFE_ID), true)
            .expect("SPIFFE sub must be accepted");
        assert_eq!(user.username, UserId::from(SPIFFE_ID));
        assert_eq!(user.auth_method, AuthMethod::JwtSvid);
    }

    /// Non-regression: the exact same token must still be rejected when the operator has
    /// not enabled `--jwt-svid-auth` for this issuer.
    #[test]
    fn spiffe_subject_rejected_when_flag_disabled() {
        let error = resolve_authenticated_user(&svid_claim(SPIFFE_ID), false)
            .expect_err("must be rejected when accept_spiffe_subject is false");
        assert!(error.to_string().contains("No email in JWT"));
    }

    /// A `sub` that is not a SPIFFE ID must never be accepted as a username, even when the
    /// flag is enabled — the fallback is strictly scoped to `spiffe://` subjects.
    #[test]
    fn non_spiffe_subject_rejected_even_when_flag_enabled() {
        for sub in ["not-a-spiffe-id", "spiffe://", "spiffe:///no-trust-domain"] {
            let error = resolve_authenticated_user(&svid_claim(sub), true)
                .expect_err("non-spiffe sub must never be accepted as a username");
            assert!(error.to_string().contains("No email in JWT"), "{sub}");
        }
    }

    /// No `sub` and no `email` must be rejected regardless of the flag.
    #[test]
    fn no_subject_no_email_rejected() {
        let error = resolve_authenticated_user(&claim(None, None), true)
            .expect_err("must be rejected without email or sub");
        assert!(error.to_string().contains("No email in JWT"));
    }

    /// An SVID without an `aud` claim (or with only empty audiences) is never a valid KMS
    /// credential: `jsonwebtoken` skips audience matching when the claim is absent, so this is
    /// the only check preventing replay of an SVID minted for another service.
    #[test]
    fn spiffe_subject_without_audience_rejected() {
        for aud in [None, Some(vec![]), Some(vec![String::new()])] {
            let user_claim = UserClaim {
                aud,
                ..claim(Some(SPIFFE_ID), None)
            };
            let error = resolve_authenticated_user(&user_claim, true)
                .expect_err("SVID without a usable audience must be rejected");
            assert!(error.to_string().contains("'aud'"), "{error}");
        }
    }

    fn sign_test_jwt(claims: &UserClaim) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-kid".to_owned());
        encode(&header, claims, &EncodingKey::from_secret(b"test-secret"))
            .expect("failed to sign test JWT")
    }

    async fn empty_jwks_manager() -> JwksManager {
        JwksManager::new(vec![], None)
            .await
            .expect("empty JwksManager must build without network access")
    }

    async fn config(accept_spiffe_subject: bool) -> JwtConfig {
        JwtConfig {
            jwt_issuer_uri: "https://issuer.example.com".to_owned(),
            jwt_audience: Some(vec!["cosmian-kms".to_owned()]),
            jwks: Arc::new(empty_jwks_manager().await),
            accept_spiffe_subject,
        }
    }

    /// `extract_user_claim` must surface the `accept_spiffe_subject` flag of whichever
    /// configuration validated the token, so `handle_jwt` can apply the SPIFFE fallback.
    #[tokio::test]
    async fn extract_user_claim_surfaces_accept_spiffe_subject_flag() {
        let configs = vec![config(true).await];
        let token = sign_test_jwt(&svid_claim(SPIFFE_ID));

        let (user_claim, accept_spiffe_subject) =
            extract_user_claim(&configs, &format!("Bearer {token}"))
                .expect("token must be decoded in test/insecure mode");

        assert!(accept_spiffe_subject);
        assert_eq!(user_claim.sub.as_deref(), Some(SPIFFE_ID));
    }

    /// `/ui/login_svid` only trusts issuers that opted in through `--jwt-svid-auth`.
    #[tokio::test]
    async fn validate_jwt_svid_ignores_configs_without_spiffe_opt_in() {
        let configs = vec![config(false).await];
        let token = sign_test_jwt(&svid_claim(SPIFFE_ID));
        validate_jwt_svid(&configs, &token)
            .await
            .expect_err("issuer without accept_spiffe_subject must not validate SVIDs");
    }

    /// The SVID login is not a generic bearer-to-session exchange: a token that only carries
    /// an `email` (ordinary OIDC token) must be rejected even though the issuer validates it.
    #[tokio::test]
    async fn validate_jwt_svid_rejects_email_tokens_without_spiffe_subject() {
        let configs = vec![config(true).await];
        let token = sign_test_jwt(&UserClaim {
            aud: Some(vec!["cosmian-kms".to_owned()]),
            ..claim(Some("oidc-subject"), Some("user@example.com"))
        });
        validate_jwt_svid(&configs, &token)
            .await
            .expect_err("email-only tokens must not be exchangeable for an SVID session");

        // Even an `email` alongside a SPIFFE subject is resolved as a SPIFFE identity.
        let token = sign_test_jwt(&UserClaim {
            aud: Some(vec!["cosmian-kms".to_owned()]),
            ..claim(Some(SPIFFE_ID), Some("user@example.com"))
        });
        let user = validate_jwt_svid(&configs, &token)
            .await
            .expect("SPIFFE subject must be accepted");
        assert_eq!(user.username, UserId::from(SPIFFE_ID));
        assert_eq!(user.auth_method, AuthMethod::JwtSvid);
    }

    #[tokio::test]
    async fn validate_jwt_svid_rejects_svid_without_audience() {
        let configs = vec![config(true).await];
        let token = sign_test_jwt(&claim(Some(SPIFFE_ID), None));
        validate_jwt_svid(&configs, &token)
            .await
            .expect_err("SVID without aud must be rejected");
    }
}

/// Tests that run the real signature/issuer/audience/expiry validation
/// ([`JwtConfig::validate_signed_token`]). Every other test in this crate goes through
/// `insecure_decode` (`cfg(test)`), so this module is what actually covers the production
/// validation path for SPIFFE JWT-SVIDs.
#[cfg(test)]
#[cfg(not(feature = "insecure"))]
#[allow(clippy::expect_used)]
mod real_validation {
    use std::{collections::HashMap, sync::Arc};

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::JwkSet};
    use openssl::{
        bn::{BigNum, BigNumContext},
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::PKey,
    };
    use serde_json::{Value, json};

    use super::{AuthMethod, JwtConfig, spiffe_authenticated_user};
    use crate::middlewares::jwt::JwksManager;

    const ISSUER: &str = "https://spire.example.org";
    const AUDIENCE: &str = "cosmian-kms";
    const SPIFFE_ID: &str = "spiffe://example.org/ns/foo/sa/bar";
    const KID: &str = "svid-key-1";

    /// An ES256 signing key together with its public JWK.
    struct TestKey {
        encoding_key: EncodingKey,
        jwk: Value,
    }

    fn generate_key() -> TestKey {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256 group");
        let ec_key = EcKey::generate(&group).expect("EC key generation");
        let mut ctx = BigNumContext::new().expect("bn ctx");
        let (mut x, mut y) = (BigNum::new().expect("bn"), BigNum::new().expect("bn"));
        ec_key
            .public_key()
            .affine_coordinates(&group, &mut x, &mut y, &mut ctx)
            .expect("affine coordinates");
        let pem = PKey::from_ec_key(ec_key)
            .expect("pkey")
            .private_key_to_pem_pkcs8()
            .expect("PKCS#8 PEM");
        TestKey {
            encoding_key: EncodingKey::from_ec_pem(&pem).expect("encoding key"),
            jwk: json!({
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "use": "sig",
                "kid": KID,
                "x": URL_SAFE_NO_PAD.encode(x.to_vec_padded(32).expect("x")),
                "y": URL_SAFE_NO_PAD.encode(y.to_vec_padded(32).expect("y")),
            }),
        }
    }

    /// A `JwtConfig` trusting `trusted` for `KID`, issuer `ISSUER`, audience `AUDIENCE`.
    async fn config(trusted: &TestKey) -> JwtConfig {
        let jwks = JwksManager::new(vec![], None)
            .await
            .expect("empty JwksManager must build without network access");
        let jwk_set: JwkSet =
            serde_json::from_value(json!({ "keys": [trusted.jwk.clone()] })).expect("JWK set");
        *jwks.jwks.write().expect("jwks lock") = HashMap::from([("test".to_owned(), jwk_set)]);
        JwtConfig {
            jwt_issuer_uri: ISSUER.to_owned(),
            jwt_audience: Some(vec![AUDIENCE.to_owned()]),
            jwks: Arc::new(jwks),
            accept_spiffe_subject: true,
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    fn valid_claims() -> Value {
        json!({
            "iss": ISSUER,
            "sub": SPIFFE_ID,
            "aud": [AUDIENCE],
            "iat": now(),
            "exp": now() + 3600,
        })
    }

    fn sign(key: &TestKey, kid: &str, alg: Algorithm, claims: &Value) -> String {
        let mut header = Header::new(alg);
        header.kid = Some(kid.to_owned());
        encode(&header, claims, &key.encoding_key).expect("sign JWT")
    }

    /// Full SVID acceptance decision: signature/issuer/audience/expiry, then the
    /// SPIFFE-specific subject and audience requirements.
    fn accept(config: &JwtConfig, token: &str) -> crate::result::KResult<super::AuthenticatedUser> {
        let claim = config.validate_signed_token(token, true)?;
        spiffe_authenticated_user(&claim)
    }

    #[tokio::test]
    async fn valid_svid_is_accepted() {
        let key = generate_key();
        let config = config(&key).await;
        let token = sign(&key, KID, Algorithm::ES256, &valid_claims());
        let user = accept(&config, &token).expect("valid SVID must be accepted");
        assert_eq!(user.username.as_str(), SPIFFE_ID);
        assert_eq!(user.auth_method, AuthMethod::JwtSvid);
    }

    /// SVID minted for another service (cross-service replay).
    #[tokio::test]
    async fn svid_for_another_audience_is_rejected() {
        let key = generate_key();
        let config = config(&key).await;
        let mut claims = valid_claims();
        claims["aud"] = json!(["some-other-service"]);
        let token = sign(&key, KID, Algorithm::ES256, &claims);
        accept(&config, &token).expect_err("wrong audience must be rejected");
    }

    /// `jsonwebtoken` only compares `aud` when the claim is present; the SVID acceptance
    /// path must still refuse a token with no audience at all.
    #[tokio::test]
    async fn svid_without_audience_is_rejected() {
        let key = generate_key();
        let config = config(&key).await;
        let mut claims = valid_claims();
        claims.as_object_mut().expect("object").remove("aud");
        let token = sign(&key, KID, Algorithm::ES256, &claims);
        accept(&config, &token).expect_err("missing audience must be rejected");
    }

    #[tokio::test]
    async fn expired_svid_is_rejected() {
        let key = generate_key();
        let config = config(&key).await;
        let mut claims = valid_claims();
        claims["exp"] = json!(now() - 3600);
        let token = sign(&key, KID, Algorithm::ES256, &claims);
        accept(&config, &token).expect_err("expired SVID must be rejected");
    }

    #[tokio::test]
    async fn svid_from_another_issuer_is_rejected() {
        let key = generate_key();
        let config = config(&key).await;
        let mut claims = valid_claims();
        claims["iss"] = json!("https://evil.example.org");
        let token = sign(&key, KID, Algorithm::ES256, &claims);
        accept(&config, &token).expect_err("wrong issuer must be rejected");
    }

    /// Token claiming the trusted `kid` but signed with a different private key.
    #[tokio::test]
    async fn svid_with_forged_signature_is_rejected() {
        let trusted = generate_key();
        let attacker = generate_key();
        let config = config(&trusted).await;
        let token = sign(&attacker, KID, Algorithm::ES256, &valid_claims());
        accept(&config, &token).expect_err("forged signature must be rejected");
    }

    #[tokio::test]
    async fn svid_with_unknown_kid_is_rejected() {
        let key = generate_key();
        let config = config(&key).await;
        let token = sign(&key, "unknown-kid", Algorithm::ES256, &valid_claims());
        accept(&config, &token).expect_err("unknown kid must be rejected");
    }

    /// Algorithm-confusion guard: symmetric algorithms are never accepted.
    #[tokio::test]
    async fn hs256_svid_is_rejected() {
        let key = generate_key();
        let config = config(&key).await;
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(KID.to_owned());
        let token = encode(
            &header,
            &valid_claims(),
            &EncodingKey::from_secret(b"any-secret"),
        )
        .expect("sign HS256 JWT");
        accept(&config, &token).expect_err("HS256 must be rejected");
    }
}
