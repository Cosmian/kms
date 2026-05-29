use std::{collections::HashMap, sync::Arc};

use cosmian_logger::{debug, trace};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};

use super::operations::Role;
use crate::{
    core::KMS,
    error::KmsError,
    kms_ensure,
    middlewares::{JwksManager, JwtConfig, JwtTokenHeaders, UserClaim},
    result::KResult,
    routes::google_cse::build_google_cse_url,
};

// Default JWT issuer URI
#[cfg(test)]
const JWT_ISSUER_URI: &str = "https://accounts.google.com";

// Default JWT Set URI
#[cfg(test)]
const JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";

static APPLICATIONS: &[&str; 6] = &[
    "meet",
    "drive",
    "gmail",
    "calendar",
    "migration",
    "gmail-sta",
];

fn get_jwks_uri(application: &str) -> String {
    if application == "migration" {
        "https://www.googleapis.com/service_accounts/v1/jwk/apps-security-cse-kaclscommunication@system.gserviceaccount.com".to_owned()
    } else {
        std::env::var(format!(
            "KMS_GOOGLE_CSE_{}_JWKS_URI",
            application.to_uppercase()
        ))
        .unwrap_or_else(|_| {
            format!(
                "https://www.googleapis.com/service_accounts/v1/jwk/gsuitecse-tokenissuer-{application}@system.gserviceaccount.com"
            )
        })
    }
}

/// List the possible JWKS URI for all the supported application
#[must_use]
pub fn list_jwks_uri(url_whitelist: Option<Vec<String>>) -> Vec<String> {
    let mut uris = APPLICATIONS
        .iter()
        .map(|app| get_jwks_uri(app))
        .collect::<Vec<_>>();

    if let Some(whitelist) = url_whitelist {
        uris.extend(whitelist.into_iter().map(|uri| format!("{uri}/certs")));
    }

    uris
}

#[must_use]
pub fn list_jwt_configurations(
    url_whitelist: &[String],
    jwks_manager: &Arc<JwksManager>,
) -> Vec<JwtConfig> {
    url_whitelist
        .iter()
        .map(|url| JwtConfig {
            jwt_issuer_uri: url.clone(),
            jwks: jwks_manager.clone(),
            // KACLS-to-KACLS migration tokens always carry `aud: "kacls-migration"`.
            // Setting the expected audience here ensures `validate_authentication_token`
            // calls `Validation::set_audience`, which makes jsonwebtoken 10.x accept
            // the token instead of rejecting it with InvalidAudience.
            jwt_audience: Some(vec!["kacls-migration".to_owned()]),
        })
        .collect::<Vec<_>>()
}

/// Fetch the JWT authorization configuration for Google CSE 'drive' or 'meet'
fn jwt_authorization_config_application(
    application: &str,
    jwks_manager: Arc<JwksManager>,
) -> Arc<JwtConfig> {
    let jwt_issuer_uri = if application == "migration" {
        "apps-security-cse-kaclscommunication@system.gserviceaccount.com".to_owned()
    } else {
        std::env::var(format!(
            "KMS_GOOGLE_CSE_{}_JWT_ISSUER",
            application.to_uppercase()
        ))
        .unwrap_or_else(|_| {
            format!("gsuitecse-tokenissuer-{application}@system.gserviceaccount.com")
        })
    };

    let jwt_audience = Some(vec![
        std::env::var("KMS_GOOGLE_CSE_AUDIENCE").unwrap_or_else(|_| "cse-authorization".to_owned()),
    ]);

    Arc::new(JwtConfig {
        jwt_issuer_uri,
        jwks: jwks_manager,
        jwt_audience,
    })
}

/// Fetch the JWT authorization configuration for Google CSE 'drive' and 'meet'
pub fn jwt_authorization_config(
    jwks_manager: &Arc<JwksManager>,
) -> HashMap<String, Arc<JwtConfig>> {
    APPLICATIONS
        .iter()
        .map(|app| {
            (
                (*app).to_owned(),
                jwt_authorization_config_application(app, jwks_manager.clone()),
            )
        })
        .collect::<HashMap<_, _>>()
}

/// Decode a json web token (JWT) used for Google CSE
pub(super) fn decode_jwt_authorization_token(
    jwt_config: &Arc<JwtConfig>,
    token: &str,
) -> KResult<(UserClaim, JwtTokenHeaders)> {
    kms_ensure!(
        !token.is_empty(),
        KmsError::Unauthorized("authorization token is empty".to_owned())
    );
    trace!(
        "validating CSE authorization token, expected issuer : {}",
        &jwt_config.jwt_issuer_uri
    );

    let header = decode_header(token)
        .map_err(|e| KmsError::Unauthorized(format!("Failed to decode token header: {e}")))?;

    let kid = header
        .kid
        .ok_or_else(|| KmsError::Unauthorized("No 'kid' claim present in token".to_owned()))?;

    let issuer_uri = jwt_config.jwt_issuer_uri.clone();

    trace!("Try to validate token from issuer: {issuer_uri:?}");

    let jwk = &jwt_config.jwks.find(&kid)?.ok_or_else(|| {
        // Only log JWKS on error
        KmsError::Unauthorized(format!(
            "[Google CSE auth] Specified key not found in set. Looking for kid `{kid}` in \
             JWKS:\n{:?}",
            jwt_config.jwks
        ))
    })?;
    trace!("JWK has been found:\n{jwk:?}");

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| KmsError::Unauthorized(format!("Failed to build decoding key: {e}")))?;

    let mut validation = Validation::new(header.alg);
    // Allow tokens to omit some standard claims (e.g., iat, nbf), but handle exp explicitly.
    validation.required_spec_claims.clear();
    validation.set_issuer(&[&jwt_config.jwt_issuer_uri]);

    // jsonwebtoken 10.x defaults to validate_aud = true and rejects tokens that
    // carry an `aud` claim when no expected audience is configured. Set the
    // expected audience from the JwtConfig so the library accepts the token.
    if let Some(ref jwt_audience) = jwt_config.jwt_audience {
        validation.set_audience(jwt_audience.as_slice());
    } else {
        validation.validate_aud = false;
    }

    #[cfg(all(not(test), not(feature = "insecure")))]
    {
        validation.validate_exp = true;
    }

    #[cfg(any(test, feature = "insecure"))]
    {
        validation.validate_exp = false;
    }

    // Keep `exp` required whenever expiration validation is enabled.
    if validation.validate_exp {
        validation.required_spec_claims.insert("exp".to_owned());
    } else {
        validation.required_spec_claims.remove("exp");
    }

    let token_data = decode::<UserClaim>(token, &decoding_key, &validation)
        .map_err(|e| KmsError::Unauthorized(format!("Cannot validate token: {e}")))?;

    let user_claims = token_data.claims;

    let jwt_headers = serde_json::to_value(token_data.header)
        .map_err(|err| KmsError::Unauthorized(format!("JWT headers are malformed: {err:?}")))
        .and_then(|v| {
            serde_json::from_value(v).map_err(|err| {
                KmsError::Unauthorized(format!("JWT headers are malformed: {err:?}"))
            })
        })?;
    trace!("valid_jwt user claims: {:?}", user_claims);
    trace!("valid_jwt headers: {:?}", jwt_headers);

    // Audience post-check in non-test, non-insecure builds
    #[cfg(all(not(test), not(feature = "insecure")))]
    {
        let configured = jwt_config.jwt_audience.as_ref().ok_or_else(|| {
            KmsError::ServerError(
                "JWT audience should be configured with Google Workspace client-side encryption"
                    .to_owned(),
            )
        })?;
        if !configured.is_empty() {
            let token_audiences = user_claims.aud.clone().unwrap_or_default();
            let matches_any = token_audiences
                .iter()
                .any(|aud| configured.iter().any(|allowed| allowed == aud));
            if !matches_any {
                let expected = format!("{configured:?}");
                let got = if token_audiences.is_empty() {
                    "<empty>".to_owned()
                } else {
                    format!("{token_audiences:?}")
                };
                return Err(KmsError::Unauthorized(format!(
                    "Authorization token audience not allowed. expected one of: {expected}, got: {got}"
                )));
            }
        }
    }

    Ok((user_claims, jwt_headers))
}

/// The configuration for Google CSE:
///  - JWT authentication and authorization configurations
#[derive(Debug, Clone)]
pub struct GoogleCseConfig {
    pub authentication: Arc<Vec<JwtConfig>>,
    pub authorization: HashMap<String, Arc<JwtConfig>>,
}

/// Validate the authentication token and return the calling user
/// See [doc](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data?hl=en)
/// # Errors
/// Returns an error if the authentication token is invalid, if the configuration is missing
pub async fn validate_cse_authentication_token(
    authentication_token: &str,
    cse_config: &Option<GoogleCseConfig>,
    google_cse_kacls_url: &str,
    kms_default_username: &str,
    is_priv_unwrap: Option<String>,
) -> KResult<String> {
    trace!("entering");
    let cse_config = cse_config.as_ref().ok_or_else(|| {
        KmsError::ServerError(
            "JWT authentication and authorization configurations for Google CSE are not set"
                .to_owned(),
        )
    })?;

    trace!("validate token: KACLS URL {google_cse_kacls_url}");

    let mut decoded_token = None;
    let mut working_jwt_config: Option<&JwtConfig> = None;
    for idp_config in cse_config.authentication.iter() {
        if let Ok(token) = idp_config.validate_authentication_token(authentication_token, false) {
            // store the decoded claim and break the loop if decoding succeeds
            decoded_token = Some(token);
            working_jwt_config = Some(idp_config);
            break;
        }
    }

    // If no config matched, refresh the JWKS and retry once.
    // The KACLS `/certs` key may have been evicted during a periodic refresh
    // failure (the JwksManager replaces the entire map on each refresh).
    if decoded_token.is_none() {
        if let Some(first) = cse_config.authentication.first() {
            first.jwks.refresh().await?;
        }
        for idp_config in cse_config.authentication.iter() {
            if let Ok(token) = idp_config.validate_authentication_token(authentication_token, false)
            {
                decoded_token = Some(token);
                working_jwt_config = Some(idp_config);
                break;
            }
        }
    }

    let authentication_token = decoded_token.ok_or_else(|| {
        KmsError::Unauthorized(
            "Fail to decode authentication token with the given config".to_owned(),
        )
    })?;
    #[cfg(all(not(test), not(feature = "insecure")))]
    if let Some(kacls_url) = authentication_token.kacls_url {
        kms_ensure!(
            kacls_url == google_cse_kacls_url,
            KmsError::Unauthorized(format!(
                "KACLS URLs should match: expected: {google_cse_kacls_url}, got: {kacls_url} "
            ))
        );
    }

    // When the authentication token contains the optional `google_email` claim, it must be compared against the email claim in the authorization token using a case-insensitive approach.
    // Don't use the email claim within the authentication token for this comparison.
    // In scenarios where the authentication token lacks the optional google_email claim, the email claim within the authentication token should be compared with the email claim in the authorization token, using a case-insensitive method. (Google Documentation)
    // Post-validation audience membership check under Google Drive resources only
    if let Some(resource_name) = &is_priv_unwrap {
        if resource_name.to_lowercase().contains("/drive/") {
            if let Some(cfg) = working_jwt_config {
                if let Some(allowed_audiences) = &cfg.jwt_audience {
                    let token_audiences = authentication_token.aud.clone().unwrap_or_default();
                    let matches_any = token_audiences
                        .iter()
                        .any(|aud| allowed_audiences.iter().any(|a| a == aud));
                    let expected = format!("{allowed_audiences:?}");
                    let got = if token_audiences.is_empty() {
                        "<empty>".to_owned()
                    } else {
                        format!("{token_audiences:?}")
                    };
                    kms_ensure!(
                        matches_any,
                        KmsError::Unauthorized(format!(
                            "Authentication token audience not allowed. expected one of: {expected}, got: {got}"
                        ))
                    );
                }
            }
        }
    }

    let authentication_email = if let Some(_resource_name) = is_priv_unwrap {
        // For `privileged_unwrap` endpoint, google_email or email claim are not provided in authentication token
        kms_default_username.to_owned()
    } else {
        authentication_token
            .google_email
            .or(authentication_token.email)
            .ok_or_else(|| {
                KmsError::Unauthorized(
                    "Authentication token should contain a google_email or an email".to_owned(),
                )
            })?
    };

    trace!("authentication token validated for {authentication_email}");

    Ok(authentication_email)
}

/// Validate the authorization token and return the calling user
/// See [doc](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data?hl=en)
#[expect(clippy::ref_option)]
pub(super) async fn validate_cse_authorization_token(
    authorization_token: &str,
    google_cse_kacls_url: &str,
    cse_config: &Option<GoogleCseConfig>,
    #[cfg_attr(any(test, feature = "insecure"), allow(unused_variables))] roles: Option<&[Role]>,
) -> KResult<UserClaim> {
    debug!("entering");

    trace!("validate_cse_authorization_token: KACLS URL {google_cse_kacls_url}");

    let cse_config = cse_config.as_ref().ok_or_else(|| {
        KmsError::ServerError(
            "JWT authentication and authorization configurations for Google CSE are not set"
                .to_owned(),
        )
    })?;

    // Try all JWT configs in the authorization map until one successfully decodes the token
    let mut decoded_token = None;
    for (app_name, jwt_config) in &cse_config.authorization {
        if let Ok((token, jwt_headers)) =
            decode_jwt_authorization_token(jwt_config, authorization_token)
        {
            trace!("token decoded with {app_name} jwt config");

            decoded_token = Some((token, jwt_headers));
            break;
        }
    }

    let (authorization_token, _jwt_headers) = decoded_token.ok_or_else(|| {
        KmsError::Unauthorized(
            "Failed to decode authorization token with any configured JWT authorization config"
                .to_owned(),
        )
    })?;

    trace!("authorization token validated successfully");

    #[cfg(all(not(test), not(feature = "insecure")))]
    if let Some(roles) = roles {
        let role = authorization_token.role.as_ref().ok_or_else(|| {
            KmsError::Unauthorized("Authorization token should contain a role".to_owned())
        })?;
        let roles_str: Vec<&str> = roles.iter().map(Role::str).collect();
        kms_ensure!(
            roles_str.contains(&role.as_str()),
            KmsError::Unauthorized(format!(
                "Authorization token should contain a role of {}",
                roles_str.join(" ")
            ))
        );
    }

    #[cfg(all(not(test), not(feature = "insecure")))]
    if authorization_token.resource_name.is_none() {
        return Err(KmsError::Unauthorized(
            "Authorization token should contain an resource_name".to_owned(),
        ));
    }
    #[cfg(all(not(test), not(feature = "insecure")))]
    if let Some(kacls_url) = authorization_token.kacls_url.clone() {
        kms_ensure!(
            kacls_url == google_cse_kacls_url,
            KmsError::Unauthorized(format!(
                "KACLS URLs should match: expected: {google_cse_kacls_url}, got: {kacls_url} "
            ))
        );
    }

    if authorization_token.email.is_none() {
        return Err(KmsError::Unauthorized(
            "Authorization token should contain an email".to_owned(),
        ));
    }

    Ok(authorization_token)
}

pub(super) struct TokenExtractedContent {
    pub user: String,
    pub resource_name: Option<Vec<u8>>,
}

/// Validate the authentication and the authorization tokens and return the calling user
/// See [doc](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data?hl=en)
#[expect(clippy::ref_option)]
pub(super) async fn validate_tokens(
    authentication_token: &str,
    authorization_token: &str,
    kms: &Arc<KMS>,
    cse_config: &Option<GoogleCseConfig>,
    roles: Option<&[Role]>,
) -> KResult<TokenExtractedContent> {
    let google_cse_kacls_url = build_google_cse_url(kms.params.kms_public_url.as_deref())?;

    let authentication_email = validate_cse_authentication_token(
        authentication_token,
        cse_config,
        &google_cse_kacls_url,
        &kms.params.default_username,
        None,
    )
    .await?;

    let authorization_token = validate_cse_authorization_token(
        authorization_token,
        &google_cse_kacls_url,
        cse_config,
        roles,
    )
    .await?;
    let authorization_email = authorization_token.email.ok_or_else(|| {
        KmsError::Unauthorized("Authorization token should contain an email".to_owned())
    })?;

    // The emails should match (case insensitive)
    kms_ensure!(
        authorization_email.to_lowercase() == authentication_email.to_lowercase(),
        KmsError::Unauthorized(
            "Authentication and authorization emails in tokens do not match".to_owned()
        )
    );

    debug!("Google CSE request authorized for user {authentication_email}");

    let resource_name = authorization_token.resource_name.unwrap_or(String::new());

    Ok(TokenExtractedContent {
        user: authentication_email,
        resource_name: Some(resource_name.into_bytes()),
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, unsafe_code, clippy::indexing_slicing)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use base64::{Engine, engine::general_purpose};
    use cosmian_logger::{debug, info, log_init, trace};
    use jsonwebtoken::{
        Algorithm, EncodingKey, Header, encode,
        jwk::{
            CommonParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse, RSAKeyParameters, RSAKeyType,
        },
    };
    use openssl::rsa::Rsa;
    use serde::Serialize;

    use crate::{
        config::IdpAuthConfig,
        middlewares::{JwksManager, JwtConfig},
        routes::google_cse::{
            self,
            jwt::{
                JWKS_URI, JWT_ISSUER_URI, decode_jwt_authorization_token, jwt_authorization_config,
                validate_cse_authentication_token,
            },
            operations::WrapRequest,
        },
        tests::google_cse::utils::generate_google_jwt,
    };

    /// Claims structure matching a real Google CSE authorization token (Gmail).
    #[derive(Serialize)]
    struct GoogleCseAuthzClaims {
        iss: String,
        aud: String,
        email: String,
        resource_name: String,
        role: String,
        kacls_url: String,
        perimeter_id: String,
        iat: usize,
        exp: usize,
        message_id: String,
        spki_hash: String,
        spki_hash_algorithm: String,
        kacls_owner_domain: String,
    }

    /// Minimal claims for negative tests.
    #[derive(Serialize)]
    struct MinimalClaims {
        iss: String,
        aud: String,
        email: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        role: Option<String>,
        iat: usize,
        exp: usize,
    }

    fn now_usize() -> usize {
        usize::try_from(chrono::Utc::now().timestamp()).unwrap()
    }

    /// Build a `JwksManager` pre-loaded with a single RSA public key (no HTTP fetch).
    fn build_jwks_manager_with_key(
        kid: &str,
        rsa: &Rsa<openssl::pkey::Private>,
    ) -> Arc<JwksManager> {
        let n = rsa.n().to_vec();
        let e = rsa.e().to_vec();

        let jwk = Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_algorithm: Some(KeyAlgorithm::RS256),
                key_id: Some(kid.to_owned()),
                ..Default::default()
            },
            algorithm: jsonwebtoken::jwk::AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: general_purpose::URL_SAFE_NO_PAD.encode(n),
                e: general_purpose::URL_SAFE_NO_PAD.encode(e),
            }),
        };

        let jwk_set = JwkSet { keys: vec![jwk] };

        let mut map = HashMap::new();
        map.insert("test".to_owned(), jwk_set);

        let manager = JwksManager {
            uris: vec![],
            jwks: std::sync::RwLock::new(map),
            last_update: std::sync::RwLock::new(Some(chrono::Utc::now())),
            proxy_params: None,
        };

        Arc::new(manager)
    }

    /// Helper: build a signed JWT with the given claims, kid, and RSA private key.
    fn sign_test_jwt<T: Serialize>(
        kid: &str,
        claims: &T,
        rsa: &Rsa<openssl::pkey::Private>,
    ) -> String {
        let der = rsa.private_key_to_der().unwrap();
        let encoding_key = EncodingKey::from_rsa_der(&der);

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_owned());

        encode(&header, claims, &encoding_key).unwrap()
    }

    /// Non-regression test for the Google CSE authorization token audience
    /// validation bug (jsonwebtoken 10.x). Tokens with `aud: "cse-authorization"`
    /// must be accepted when the configured audience matches.
    ///
    /// This reproduces the exact token structure from the issue report: a Google
    /// Gmail CSE authorization token with standard fields like `role`, `kacls_url`,
    /// `resource_name`, `spki_hash`, `kacls_owner_domain`, etc.
    #[test]
    fn test_cse_authorization_token_with_audience_is_accepted() {
        log_init(option_env!("RUST_LOG"));

        let kid = "test-kid-001";
        let issuer = "gsuitecse-tokenissuer-gmail@system.gserviceaccount.com";

        let rsa = Rsa::generate(2048).unwrap();
        let jwks_manager = build_jwks_manager_with_key(kid, &rsa);

        let jwt_config = Arc::new(JwtConfig {
            jwt_issuer_uri: issuer.to_owned(),
            jwks: jwks_manager,
            jwt_audience: Some(vec!["cse-authorization".to_owned()]),
        });

        let now = now_usize();
        let claims = GoogleCseAuthzClaims {
            iss: issuer.to_owned(),
            aud: "cse-authorization".to_owned(),
            email: "user@example.com".to_owned(),
            resource_name:
                "//gmail.googleapis.com/gmail/users/user%40example.com/settings/cse/keypairs/abc123"
                    .to_owned(),
            role: "decrypter".to_owned(),
            kacls_url: "https://kms.example.com/google_cse".to_owned(),
            perimeter_id: String::new(),
            iat: now,
            exp: now + 3600,
            message_id: "msg-id-12345".to_owned(),
            spki_hash: "dGVzdC1zcGtpLWhhc2g".to_owned(),
            spki_hash_algorithm: "SHA-256".to_owned(),
            kacls_owner_domain: "example.com".to_owned(),
        };

        let token = sign_test_jwt(kid, &claims, &rsa);

        // This was failing before the fix with:
        // "Cannot validate token: InvalidAudience"
        let result = decode_jwt_authorization_token(&jwt_config, &token);
        assert!(
            result.is_ok(),
            "decode_jwt_authorization_token should accept a token with aud matching the configured audience, got: {:?}",
            result.err()
        );

        let (user_claim, _headers) = result.unwrap();
        assert_eq!(user_claim.email.as_deref(), Some("user@example.com"));
        assert_eq!(user_claim.aud, Some(vec!["cse-authorization".to_owned()]));
        assert_eq!(user_claim.role.as_deref(), Some("decrypter"));
        assert_eq!(
            user_claim.kacls_url.as_deref(),
            Some("https://kms.example.com/google_cse")
        );
        assert_eq!(
            user_claim.resource_name.as_deref(),
            Some(
                "//gmail.googleapis.com/gmail/users/user%40example.com/settings/cse/keypairs/abc123"
            )
        );
        assert_eq!(user_claim.spki_hash.as_deref(), Some("dGVzdC1zcGtpLWhhc2g"));
        assert_eq!(user_claim.spki_hash_algorithm.as_deref(), Some("SHA-256"));
    }

    /// Verify that a token with a *wrong* audience is rejected.
    #[test]
    fn test_cse_authorization_token_wrong_audience_rejected() {
        log_init(option_env!("RUST_LOG"));

        let kid = "test-kid-002";
        let issuer = "gsuitecse-tokenissuer-gmail@system.gserviceaccount.com";

        let rsa = Rsa::generate(2048).unwrap();
        let jwks_manager = build_jwks_manager_with_key(kid, &rsa);

        let jwt_config = Arc::new(JwtConfig {
            jwt_issuer_uri: issuer.to_owned(),
            jwks: jwks_manager,
            jwt_audience: Some(vec!["cse-authorization".to_owned()]),
        });

        let now = now_usize();
        let claims = MinimalClaims {
            iss: issuer.to_owned(),
            aud: "wrong-audience".to_owned(),
            email: "user@example.com".to_owned(),
            role: Some("decrypter".to_owned()),
            iat: now,
            exp: now + 3600,
        };

        let token = sign_test_jwt(kid, &claims, &rsa);

        let result = decode_jwt_authorization_token(&jwt_config, &token);
        assert!(
            result.is_err(),
            "should reject a token whose audience does not match the configured one"
        );
    }

    /// Verify that tokens work when no audience is configured (`validate_aud` disabled).
    #[test]
    fn test_cse_authorization_token_no_configured_audience() {
        log_init(option_env!("RUST_LOG"));

        let kid = "test-kid-003";
        let issuer = "gsuitecse-tokenissuer-drive@system.gserviceaccount.com";

        let rsa = Rsa::generate(2048).unwrap();
        let jwks_manager = build_jwks_manager_with_key(kid, &rsa);

        let jwt_config = Arc::new(JwtConfig {
            jwt_issuer_uri: issuer.to_owned(),
            jwks: jwks_manager,
            jwt_audience: None,
        });

        let now = now_usize();
        let claims = MinimalClaims {
            iss: issuer.to_owned(),
            aud: "any-audience".to_owned(),
            email: "user@example.com".to_owned(),
            role: Some("reader".to_owned()),
            iat: now,
            exp: now + 3600,
        };

        let token = sign_test_jwt(kid, &claims, &rsa);

        let result = decode_jwt_authorization_token(&jwt_config, &token);
        assert!(
            result.is_ok(),
            "should accept a token when no audience is configured, got: {:?}",
            result.err()
        );
    }

    /// Verify that wrong issuer is rejected.
    #[test]
    fn test_cse_authorization_token_wrong_issuer_rejected() {
        log_init(option_env!("RUST_LOG"));

        let kid = "test-kid-004";
        let expected_issuer = "gsuitecse-tokenissuer-gmail@system.gserviceaccount.com";

        let rsa = Rsa::generate(2048).unwrap();
        let jwks_manager = build_jwks_manager_with_key(kid, &rsa);

        let jwt_config = Arc::new(JwtConfig {
            jwt_issuer_uri: expected_issuer.to_owned(),
            jwks: jwks_manager,
            jwt_audience: Some(vec!["cse-authorization".to_owned()]),
        });

        let now = now_usize();
        let claims = MinimalClaims {
            iss: "wrong-issuer@system.gserviceaccount.com".to_owned(),
            aud: "cse-authorization".to_owned(),
            email: "user@example.com".to_owned(),
            role: None,
            iat: now,
            exp: now + 3600,
        };

        let token = sign_test_jwt(kid, &claims, &rsa);

        let result = decode_jwt_authorization_token(&jwt_config, &token);
        assert!(result.is_err(), "should reject a token with a wrong issuer");
    }

    /// Claims matching a KACLS-to-KACLS migration JWT created by `create_jwt`.
    #[derive(Serialize)]
    struct KaclsMigrationClaims {
        iss: String,
        aud: String,
        exp: usize,
        iat: usize,
        kacls_url: String,
        resource_name: String,
    }

    /// Non-regression test for the KACLS-to-KACLS migration authentication flow
    /// (issue #947). When KMS-A calls `privilegedunwrap` on KMS-B, the JWT sent
    /// by KMS-A must be accepted by `validate_cse_authentication_token` on KMS-B.
    ///
    /// The token has `aud: "kacls-migration"` and is signed by KMS-A's migration
    /// RSA key. KMS-B's whitelist config must have a matching expected audience.
    #[tokio::test]
    async fn test_kacls_migration_authentication_token_accepted() {
        log_init(option_env!("RUST_LOG"));

        let kid = "kacls-migration-kid-001";
        let kms_a_url = "https://kms-a.example.com/google_cse";
        let kms_b_url = "https://kms-b.example.com/google_cse";

        let rsa = Rsa::generate(2048).unwrap();
        let jwks_manager = build_jwks_manager_with_key(kid, &rsa);

        // Build the whitelist JwtConfig as list_jwt_configurations would
        let whitelist_config = JwtConfig {
            jwt_issuer_uri: kms_a_url.to_owned(),
            jwks: jwks_manager.clone(),
            jwt_audience: Some(vec!["kacls-migration".to_owned()]),
        };

        let cse_config = super::GoogleCseConfig {
            authentication: vec![whitelist_config].into(),
            authorization: HashMap::new(),
        };

        let now = now_usize();
        let claims = KaclsMigrationClaims {
            iss: kms_a_url.to_owned(),
            aud: "kacls-migration".to_owned(),
            exp: now + 3600,
            iat: now,
            kacls_url: kms_b_url.to_owned(),
            resource_name: "//googleapis.com/drive/files/test-file-id".to_owned(),
        };

        let token = sign_test_jwt(kid, &claims, &rsa);

        let result = validate_cse_authentication_token(
            &token,
            &Some(cse_config),
            kms_b_url,
            "default_user",
            Some("//googleapis.com/drive/files/test-file-id".to_owned()),
        )
        .await;

        assert!(
            result.is_ok(),
            "KACLS migration authentication token should be accepted, got: {:?}",
            result.err()
        );
        // For privilegedunwrap, the returned user is the default username
        assert_eq!(result.unwrap(), "default_user");
    }

    /// Verify that a KACLS migration token with a wrong audience is rejected
    /// (post-decode audience check on Drive resources).
    #[tokio::test]
    async fn test_kacls_migration_token_wrong_audience_rejected() {
        log_init(option_env!("RUST_LOG"));

        let kid = "kacls-migration-kid-002";
        let kms_a_url = "https://kms-a.example.com/google_cse";
        let kms_b_url = "https://kms-b.example.com/google_cse";

        let rsa = Rsa::generate(2048).unwrap();
        let jwks_manager = build_jwks_manager_with_key(kid, &rsa);

        let whitelist_config = JwtConfig {
            jwt_issuer_uri: kms_a_url.to_owned(),
            jwks: jwks_manager.clone(),
            jwt_audience: Some(vec!["kacls-migration".to_owned()]),
        };

        let cse_config = super::GoogleCseConfig {
            authentication: vec![whitelist_config].into(),
            authorization: HashMap::new(),
        };

        let now = now_usize();
        let claims = KaclsMigrationClaims {
            iss: kms_a_url.to_owned(),
            aud: "wrong-audience".to_owned(),
            exp: now + 3600,
            iat: now,
            kacls_url: kms_b_url.to_owned(),
            resource_name: "//googleapis.com/drive/files/test-file-id".to_owned(),
        };

        let token = sign_test_jwt(kid, &claims, &rsa);

        let result = validate_cse_authentication_token(
            &token,
            &Some(cse_config),
            kms_b_url,
            "default_user",
            Some("//googleapis.com/drive/files/test-file-id".to_owned()),
        )
        .await;

        assert!(
            result.is_err(),
            "KACLS migration token with wrong audience should be rejected"
        );
    }

    #[ignore = "Requires Google CSE credentials; not available in CI"]
    #[tokio::test]
    async fn test_wrap_auth() {
        log_init(option_env!("RUST_LOG"));

        let jwt = generate_google_jwt().await.unwrap();

        let wrap_request = format!(
            r#"
        {{
            "authentication": "{jwt}",
            "authorization": "{jwt}",
            "key": "GiBtiozOv+COIrEPxPUYH9gFKw1tY9kBzHaW/gSi7u9ZLA==",
            "reason": ""
        }}
        "#
        );
        debug!("{wrap_request:?}");
        let wrap_request: WrapRequest = serde_json::from_str(&wrap_request).unwrap();

        let uris = {
            let mut uris = google_cse::list_jwks_uri(None);
            uris.push(IdpAuthConfig::uri(JWT_ISSUER_URI, Some(JWKS_URI)));
            uris
        };
        let jwks_manager = Arc::new(JwksManager::new(uris, None).await.unwrap());
        jwks_manager.refresh().await.unwrap();

        let client_id = std::env::var("TEST_GOOGLE_OAUTH_CLIENT_ID").unwrap();
        // Test authentication
        let jwt_authentication_config = IdpAuthConfig {
            jwt_auth_provider: Some(vec![format!(
                "{},{},{}",
                JWT_ISSUER_URI, JWKS_URI, client_id
            )]),
        };
        let idp_configs = jwt_authentication_config
            .extract_idp_configs()
            .unwrap()
            .unwrap();
        let jwt_authentication_config = JwtConfig {
            jwt_issuer_uri: idp_configs[0].jwt_issuer_uri.clone(),
            jwks: jwks_manager.clone(),
            jwt_audience: idp_configs[0].jwt_audience.clone(),
        };

        let authentication_token = jwt_authentication_config
            .validate_authentication_token(&wrap_request.authentication, true)
            .unwrap();
        info!("AUTHENTICATION token: {:?}", authentication_token);
        assert_eq!(
            authentication_token.iss,
            Some("https://accounts.google.com".to_owned())
        );
        assert_eq!(
            authentication_token.email,
            Some("blue@cosmian.com".to_owned())
        );
        assert_eq!(
            authentication_token.aud,
            Some(vec![
                "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"
                    .to_owned()
            ])
        );

        // Test authorization
        // we fake the URLs and use authentication tokens,
        // because we don't know the URL of the Google Drive authorization token API.
        unsafe {
            std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWKS_URI", JWKS_URI);
            std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWT_ISSUER", JWT_ISSUER_URI);
            // the token has been issued by Google Accounts (post request)
        };
        let jwt_authorization_config = jwt_authorization_config(&jwks_manager);
        trace!("{jwt_authorization_config:#?}");

        let (authorization_token, jwt_headers) = decode_jwt_authorization_token(
            &jwt_authorization_config["drive"],
            &wrap_request.authorization,
        )
        .unwrap();
        info!("AUTHORIZATION token: {:?}", authorization_token);
        info!("AUTHORIZATION token headers: {:?}", jwt_headers);

        assert_eq!(
            authorization_token.email,
            Some("blue@cosmian.com".to_owned())
        );
        // prev: Some("cse-authorization".to_owned())
        assert_eq!(
            authorization_token.aud,
            Some(vec![
                "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"
                    .to_owned()
            ])
        );
    }
}
