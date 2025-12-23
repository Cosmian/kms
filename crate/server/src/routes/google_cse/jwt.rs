use std::{collections::HashMap, sync::Arc};

use alcoholic_jwt::token_kid;
use cosmian_logger::{debug, trace};

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
            jwt_audience: None, // audience will be validated post-decode against configured lists
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

    let jwt_audience = Some(
        std::env::var("KMS_GOOGLE_CSE_AUDIENCE").unwrap_or_else(|_| "cse-authorization".to_owned()),
    );

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

    let validations = vec![
        #[cfg(all(not(test), not(feature = "insecure")))]
        alcoholic_jwt::Validation::Audience(
            jwt_config
                .jwt_audience
                .as_ref()
                .ok_or_else(|| {
                    KmsError::ServerError(
                        "JWT audience should be configured with Google Workspace client-side \
                         encryption"
                            .to_owned(),
                    )
                })?
                .to_owned(),
        ),
        alcoholic_jwt::Validation::Issuer(jwt_config.jwt_issuer_uri.clone()),
    ];

    // If a JWKS contains multiple keys, the correct KID first
    // needs to be fetched from the token headers.
    let kid = token_kid(token)
        .map_err(|e| {
            KmsError::Unauthorized(format!("Failed to decode token headers. Error: {e:?}"))
        })?
        .ok_or_else(|| KmsError::Unauthorized("No 'kid' claim present in token".to_owned()))?;

    let issuer_uri = jwt_config.jwt_issuer_uri.clone();

    trace!("Try to validate token:\n{token:?} \n {issuer_uri:?}");

    let jwk = &jwt_config.jwks.find(&kid)?.ok_or_else(|| {
        // Only log JWKS on error
        KmsError::Unauthorized(format!(
            "[Google CSE auth] Specified key not found in set. Looking for kid `{kid}` in \
             JWKS:\n{:?}",
            jwt_config.jwks
        ))
    })?;
    trace!("JWK has been found:\n{jwk:?}");

    let valid_jwt = alcoholic_jwt::validate(token, jwk, validations)
        .map_err(|err| KmsError::Unauthorized(format!("Cannot validate token: {err:?}")))?;

    trace!("valid_jwt user claims: {:?}", valid_jwt.claims);
    trace!("valid_jwt headers: {:?}", valid_jwt.headers);

    let user_claims = serde_json::from_value(valid_jwt.claims)
        .map_err(|err| KmsError::Unauthorized(format!("JWT claims are malformed: {err:?}")))?;

    let jwt_headers = serde_json::from_value(valid_jwt.headers)
        .map_err(|err| KmsError::Unauthorized(format!("JWT headers is malformed: {err:?}")))?;

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
                if let Some(allowed_audience) = &cfg.jwt_audience {
                    let token_audiences = authentication_token.aud.clone().unwrap_or_default();
                    let matches_any = token_audiences.iter().any(|aud| aud == allowed_audience);
                    let err_msg = if token_audiences.is_empty() {
                        format!(
                            "Authentication token audience not allowed. expected: {allowed_audience}, got: <empty>"
                        )
                    } else {
                        format!(
                            "Authentication token audience not allowed. expected: {allowed_audience}, got: {token_audiences:?}"
                        )
                    };
                    kms_ensure!(matches_any, KmsError::Unauthorized(err_msg));
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

    let (authorization_token, jwt_headers) = decoded_token.ok_or_else(|| {
        KmsError::Unauthorized(
            "Failed to decode authorization token with any configured JWT authorization config"
                .to_owned(),
        )
    })?;

    trace!("authorization token: {authorization_token:?}");
    trace!("authorization token headers: {jwt_headers:?}");

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
    use std::sync::Arc;

    use cosmian_logger::{debug, info, log_init, trace};

    use crate::{
        config::{IdpAuthConfig, JwtAuthConfig},
        middlewares::{JwksManager, JwtConfig},
        routes::google_cse::{
            self,
            jwt::{
                JWKS_URI, JWT_ISSUER_URI, decode_jwt_authorization_token, jwt_authorization_config,
            },
            operations::WrapRequest,
        },
        tests::google_cse::utils::generate_google_jwt,
    };

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
            uris.push(JwtAuthConfig::uri(JWT_ISSUER_URI, Some(JWKS_URI)));
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
            jwt_audience: idp_configs[0]
                .jwt_audience
                .as_ref()
                .and_then(|v| v.first().cloned()),
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
