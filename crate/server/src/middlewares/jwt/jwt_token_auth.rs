//! JWT Authentication Middleware
//!
//! This module handles JWT-based authentication for the KMS server.
//! It extracts and validates JWT tokens from the Authorization header,
//! then processes the claims to authenticate users.

use std::sync::Arc;

use actix_web::{dev::ServiceRequest, http::header};
use cosmian_logger::{debug, trace, warn};

use super::UserClaim;
use crate::{
    error::KmsError,
    middlewares::{
        AuthMethod, AuthenticatedUser, UserId,
        jwt::{JwtConfig, refresh_jwks_for_token},
        reject_reserved_service_identity,
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
/// * `Ok((UserClaim, bool, usize))` - Successfully validated user claim, plus the
///   `accept_spiffe_subject` flag and index of the configuration that validated it
/// * `Err(Vec<KmsError>)` - List of errors from failed validation attempts
fn extract_user_claim(
    configs: &[JwtConfig],
    token: &str,
) -> Result<(UserClaim, bool, usize), Vec<KmsError>> {
    let mut jwt_log_errors = Vec::new();

    // Try each JWT configuration until one succeeds
    for (index, idp_config) in configs.iter().enumerate() {
        match idp_config.decode_bearer_header(token) {
            Ok(user_claim) => return Ok((user_claim, idp_config.accept_spiffe_subject, index)),
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
    let username = UserId::from(sub);
    reject_reserved_service_identity(&username)?;
    Ok(AuthenticatedUser {
        username,
        auth_method: AuthMethod::JwtSvid,
    })
}

/// Resolve an [`AuthenticatedUser`] from a successfully validated JWT claim set.
///
/// A verified `email` takes priority when present and is namespaced for secondary identity providers. When
/// `email` is absent, falls back to the `sub` claim **only if** `accept_spiffe_subject` is
/// `true` (the issuer's config opted in via `--jwt-svid-auth`) **and** `sub` is a SPIFFE ID
/// (`spiffe://...`), i.e. a SPIFFE JWT-SVID (see [`spiffe_authenticated_user`]). Every other
/// case is rejected, preserving the pre-existing "no email in JWT" behaviour.
fn resolve_authenticated_user(
    user_claim: &UserClaim,
    accept_spiffe_subject: bool,
    issuer_namespace: Option<&str>,
) -> KResult<AuthenticatedUser> {
    if let Some(email) = user_claim.email.as_deref() {
        if user_claim.email_verified != Some(true) {
            return Err(KmsError::Unauthorized(
                "JWT email is not verified (email_verified must be true)".to_owned(),
            ));
        }
        let username = issuer_namespace.map_or_else(
            || UserId::from(email),
            |issuer| UserId::from(format!("{email}#{issuer}")),
        );
        reject_reserved_service_identity(&username)?;
        return Ok(AuthenticatedUser {
            username,
            auth_method: AuthMethod::OidcJwt,
        });
    }
    let has_spiffe_subject = user_claim.sub.as_deref().is_some_and(is_spiffe_id);
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
/// When validation fails, the JWKS of the token's issuer is refreshed once (throttled) and
/// validation retried, so a SPIRE signing-key rotation, or a JWKS endpoint that was
/// unreachable at startup, does not break the login until the next restart.
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
        if let Err(error) = refresh_jwks_for_token(spiffe_configs.iter().copied(), token).await {
            warn!("JWKS refresh failed while validating a JWT-SVID: {error:?}");
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

    // The identity is the bearer token of the Authorization header
    let identity: &str = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    // Try to extract and validate the user claim
    let mut private_claim = extract_user_claim(&configs, identity);

    // If no configuration could get the claim, refresh the JWKS of the token's issuer
    // (a key rotation or a failed startup fetch) and extract the user claim again
    if private_claim.is_err() {
        refresh_jwks_for_token(configs.iter(), identity).await?;
        private_claim = extract_user_claim(&configs, identity);
    }

    match private_claim {
        Ok((user_claim, accept_spiffe_subject, config_index)) => {
            // `config_index` comes from enumerating `configs`, so the lookup always succeeds.
            let issuer_namespace = configs
                .get(config_index)
                .and_then(|config| config.issuer_namespace.as_deref());
            resolve_authenticated_user(&user_claim, accept_spiffe_subject, issuer_namespace)
                .inspect_err(|error| {
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
mod tests {
    use std::sync::Arc;

    use actix_web::http::header::AUTHORIZATION;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::{Value, json};

    use super::{
        AuthMethod, JwtConfig, UserClaim, extract_user_claim, handle_jwt,
        resolve_authenticated_user, validate_jwt_svid,
    };
    use crate::middlewares::{UserId, jwt::JwksManager};

    const SPIFFE_ID: &str = "spiffe://example.org/ns/foo/sa/bar";
    /// Issuer of the second (secondary) provider configuration.
    const ISSUER_1: &str = "https://issuer1.example.com";

    fn claim(sub: Option<&str>, email: Option<&str>) -> UserClaim {
        UserClaim {
            email: email.map(str::to_owned),
            iss: None,
            email_verified: Some(true),
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

    /// A verified OIDC email takes priority regardless of `accept_spiffe_subject`.
    #[test]
    fn email_claim_is_accepted_and_takes_priority() {
        let user_claim = claim(Some(SPIFFE_ID), Some("a@b.com"));
        let user = resolve_authenticated_user(&user_claim, true, None).expect("must be accepted");
        assert_eq!(user.username, UserId::from("a@b.com"));
        assert_eq!(user.auth_method, AuthMethod::OidcJwt);
    }

    /// A SPIFFE JWT-SVID (`sub = spiffe://...`, no `email`) is accepted only when
    /// `accept_spiffe_subject` is enabled — this is the `--jwt-svid-auth` opt-in flag.
    #[test]
    fn spiffe_subject_accepted_when_flag_enabled() {
        let user = resolve_authenticated_user(&svid_claim(SPIFFE_ID), true, None)
            .expect("SPIFFE sub must be accepted");
        assert_eq!(user.username, UserId::from(SPIFFE_ID));
        assert_eq!(user.auth_method, AuthMethod::JwtSvid);
    }

    /// Non-regression: the exact same token must still be rejected when the operator has
    /// not enabled `--jwt-svid-auth` for this issuer.
    #[test]
    fn spiffe_subject_rejected_when_flag_disabled() {
        let error = resolve_authenticated_user(&svid_claim(SPIFFE_ID), false, None)
            .expect_err("must be rejected when accept_spiffe_subject is false");
        assert!(error.to_string().contains("No email in JWT"));
    }

    /// A `sub` that is not a SPIFFE ID must never be accepted as a username, even when the
    /// flag is enabled — the fallback is strictly scoped to `spiffe://` subjects.
    #[test]
    fn non_spiffe_subject_rejected_even_when_flag_enabled() {
        for sub in ["not-a-spiffe-id", "spiffe://", "spiffe:///no-trust-domain"] {
            let error = resolve_authenticated_user(&svid_claim(sub), true, None)
                .expect_err("non-spiffe sub must never be accepted as a username");
            assert!(error.to_string().contains("No email in JWT"), "{sub}");
        }
    }

    /// No `sub` and no `email` must be rejected regardless of the flag.
    #[test]
    fn no_subject_no_email_rejected() {
        let error = resolve_authenticated_user(&claim(None, None), true, None)
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
            let error = resolve_authenticated_user(&user_claim, true, None)
                .expect_err("SVID without a usable audience must be rejected");
            assert!(error.to_string().contains("'aud'"), "{error}");
        }
    }

    /// An OIDC claim set for `a@x` with the given `email_verified` claim.
    fn email_claim(email_verified: Option<bool>) -> UserClaim {
        UserClaim {
            email_verified,
            ..claim(Some("oidc-subject"), Some("a@x"))
        }
    }

    /// F-014: an `email` the `IdP` has not verified (`email_verified` false or absent) must
    /// never become the KMS identity, whatever the SPIFFE opt-in.
    #[test]
    fn unverified_email_claim_is_rejected() {
        for email_verified in [Some(false), None] {
            for accept_spiffe_subject in [false, true] {
                let error = resolve_authenticated_user(
                    &email_claim(email_verified),
                    accept_spiffe_subject,
                    None,
                )
                .expect_err("an unverified email must be rejected");
                assert!(
                    error.to_string().contains("email_verified"),
                    "{email_verified:?}: {error}"
                );
            }
        }
        let user = resolve_authenticated_user(&email_claim(Some(true)), false, None)
            .expect("a verified email must be accepted");
        assert_eq!(user.username, UserId::from("a@x"));
        assert_eq!(user.auth_method, AuthMethod::OidcJwt);
    }

    /// F-014: `email_verified` is read from the token as a JSON boolean or the strings
    /// `"true"`/`"false"` (some `IdP`s emit strings); only `true` authenticates, and an absent
    /// or `null` claim decodes (the token is well-formed) but is rejected.
    #[tokio::test]
    async fn email_verified_claim_accepts_bool_or_string_and_requires_true() {
        let configs = vec![config(false).await];
        let cases = [
            (Some(json!(true)), true),
            (Some(json!("true")), true),
            (Some(json!(false)), false),
            (Some(json!("false")), false),
            (Some(Value::Null), false),
            (None, false),
        ];
        for (email_verified, accepted) in cases {
            let mut claims =
                json!({ "sub": "oidc-subject", "email": "a@x", "aud": ["cosmian-kms"] });
            if let Some(value) = email_verified.clone() {
                claims["email_verified"] = value;
            }
            let (user_claim, accept_spiffe_subject, _) =
                extract_user_claim(&configs, &format!("Bearer {}", sign_test_jwt(&claims)))
                    .expect("the token must decode whatever its email_verified claim");
            let result = resolve_authenticated_user(&user_claim, accept_spiffe_subject, None);
            assert_eq!(
                result.is_ok(),
                accepted,
                "email_verified={email_verified:?}"
            );
        }
    }

    /// F-014: the same email asserted by the primary provider (config index 0) and by a
    /// secondary one (index 1) must resolve to two distinct KMS identities, so a secondary
    /// `IdP` cannot impersonate a primary-`IdP` user. SPIFFE IDs are never namespaced.
    #[tokio::test]
    async fn same_email_from_a_secondary_issuer_is_namespaced() {
        let configs = [
            config(false).await,
            JwtConfig {
                jwt_issuer_uri: ISSUER_1.to_owned(),
                ..config(false).await
            },
        ];
        let user_claim = email_claim(Some(true));

        let primary = resolve_authenticated_user(&user_claim, false, None).expect("index 0");
        assert_eq!(primary.username, UserId::from("a@x"));

        let secondary = resolve_authenticated_user(
            &user_claim,
            false,
            Some(configs[1].jwt_issuer_uri.as_str()),
        )
        .expect("index 1");
        assert_eq!(secondary.username.as_str(), format!("a@x#{ISSUER_1}"));
        assert_eq!(secondary.auth_method, AuthMethod::OidcJwt);

        let svid = resolve_authenticated_user(&svid_claim(SPIFFE_ID), true, Some(ISSUER_1))
            .expect("SPIFFE subject from a secondary issuer");
        assert_eq!(svid.username, UserId::from(SPIFFE_ID));
    }

    /// F-014 through the middleware entry point: a token validated by the first provider
    /// keeps the bare email, and an unverified email is refused.
    #[tokio::test]
    async fn handle_jwt_requires_a_verified_email() {
        let configs = Arc::new(vec![
            config(false).await,
            JwtConfig {
                jwt_issuer_uri: ISSUER_1.to_owned(),
                ..config(false).await
            },
        ]);
        let request = |token: String| {
            actix_web::test::TestRequest::default()
                .insert_header((AUTHORIZATION, format!("Bearer {token}")))
                .to_srv_request()
        };

        let user = handle_jwt(
            configs.clone(),
            &request(sign_test_jwt(&email_claim(Some(true)))),
        )
        .await
        .expect("a verified email must be accepted");
        assert_eq!(user.username, UserId::from("a@x"));

        for email_verified in [Some(false), None] {
            handle_jwt(
                configs.clone(),
                &request(sign_test_jwt(&email_claim(email_verified))),
            )
            .await
            .expect_err("an unverified email must be rejected");
        }
    }

    /// Namespace selection belongs to the validating configuration, not its list index.
    #[tokio::test]
    async fn handle_jwt_uses_the_configured_issuer_namespace() {
        for (namespace, expected) in [
            (None, "a@x".to_owned()),
            (Some(ISSUER_1.to_owned()), format!("a@x#{ISSUER_1}")),
        ] {
            let configs = Arc::new(vec![JwtConfig {
                issuer_namespace: namespace,
                ..config(false).await
            }]);
            let request = actix_web::test::TestRequest::default()
                .insert_header((
                    AUTHORIZATION,
                    format!("Bearer {}", sign_test_jwt(&email_claim(Some(true)))),
                ))
                .to_srv_request();
            let user = handle_jwt(configs, &request).await.expect("verified email");
            assert_eq!(user.username.as_str(), expected);
        }
    }

    fn sign_test_jwt(claims: &impl serde::Serialize) -> String {
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
            issuer_namespace: None,
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

        let (user_claim, accept_spiffe_subject, config_index) =
            extract_user_claim(&configs, &format!("Bearer {token}"))
                .expect("token must be decoded in test/insecure mode");

        assert!(accept_spiffe_subject);
        assert_eq!(config_index, 0);
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
            issuer_namespace: None,
            jwks: Arc::new(jwks),
            accept_spiffe_subject: true,
        }
    }

    fn now() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
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

    /// Overwrite one claim of a claim set built by [`valid_claims`].
    fn set_claim(claims: &mut Value, name: &str, value: Value) {
        claims
            .as_object_mut()
            .expect("object")
            .insert(name.to_owned(), value);
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
        set_claim(&mut claims, "aud", json!(["some-other-service"]));
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

    /// `jsonwebtoken` parses but never enforces `crit` (RFC 7515 §4.1.11): the production
    /// path must refuse such a token itself. The header segment is forged by hand, and the
    /// error message proves the refusal comes from the `crit` check, not the signature.
    #[tokio::test]
    async fn token_with_crit_header_is_rejected() {
        let key = generate_key();
        let config = config(&key).await;
        let token = sign(&key, KID, Algorithm::ES256, &valid_claims());
        let forged_header = URL_SAFE_NO_PAD
            .encode(json!({"alg": "ES256", "kid": KID, "crit": ["b64"]}).to_string());
        let forged = format!(
            "{forged_header}.{}",
            token.split_once('.').expect("compact JWT").1
        );
        let err = config
            .validate_signed_token(&forged, true)
            .expect_err("a token with `crit` must be rejected");
        assert!(err.to_string().contains("critical"), "{err}");
    }

    /// A correctly signed nested JWT (`cty: JWT`) is refused: it is not supported.
    #[tokio::test]
    async fn nested_jwt_is_rejected() {
        let key = generate_key();
        let config = config(&key).await;
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(KID.to_owned());
        header.cty = Some("JWT".to_owned());
        let token = encode(&header, &valid_claims(), &key.encoding_key).expect("sign JWT");
        let err = config
            .validate_signed_token(&token, true)
            .expect_err("a nested JWT must be rejected");
        assert!(err.to_string().contains("Nested"), "{err}");
    }

    #[tokio::test]
    async fn expired_svid_is_rejected() {
        let key = generate_key();
        let config = config(&key).await;
        let mut claims = valid_claims();
        set_claim(&mut claims, "exp", json!(now() - 3600));
        let token = sign(&key, KID, Algorithm::ES256, &claims);
        accept(&config, &token).expect_err("expired SVID must be rejected");
    }

    #[tokio::test]
    async fn svid_from_another_issuer_is_rejected() {
        let key = generate_key();
        let config = config(&key).await;
        let mut claims = valid_claims();
        set_claim(&mut claims, "iss", json!("https://evil.example.org"));
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
