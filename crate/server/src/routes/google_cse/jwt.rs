use std::{collections::HashMap, sync::Arc};

use alcoholic_jwt::token_kid;

use crate::{
    error::KmsError,
    kms_ensure,
    middlewares::{JwksManager, JwtConfig, JwtTokenHeaders, UserClaim},
    result::KResult,
};

// Default JWT issuer URI
#[cfg(test)]
const JWT_ISSUER_URI: &str = "https://accounts.google.com";

// Default JWT Set URI
#[cfg(test)]
const JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";

static APPLICATIONS: &[&str; 3] = &["meet", "drive", "gmail"];

fn get_jwks_uri(application: &str) -> String {
    std::env::var(format!("KMS_GOOGLE_CSE_{}_JWKS_URI", application.to_uppercase()))
    .unwrap_or(format!("https://www.googleapis.com/service_accounts/v1/jwk/gsuitecse-tokenissuer-{application}@system.gserviceaccount.com"))
}

/// List the possible JWKS URI for all the supported application
#[must_use]
pub fn list_jwks_uri() -> Vec<String> {
    APPLICATIONS
        .iter()
        .map(|app| get_jwks_uri(app))
        .collect::<Vec<_>>()
}

/// Fetch the JWT authorization configuration for Google CSE 'drive' or 'meet'
fn jwt_authorization_config_application(
    application: &str,
    jwks_manager: Arc<JwksManager>,
) -> Arc<JwtConfig> {
    let jwt_issuer_uri = std::env::var(format!(
        "KMS_GOOGLE_CSE_{}_JWT_ISSUER",
        application.to_uppercase()
    ))
    .unwrap_or(format!(
        "gsuitecse-tokenissuer-{application}@system.gserviceaccount.com"
    ));

    let jwt_audience = Some(
        std::env::var("KMS_GOOGLE_CSE_AUDIENCE")
            .unwrap_or_else(|_| "cse-authorization".to_string()),
    );

    Arc::new(JwtConfig {
        jwt_issuer_uri,
        jwks: jwks_manager,
        jwt_audience,
    })
}

/// Fetch the JWT authorization configuration for Google CSE 'drive' and 'meet'
pub fn jwt_authorization_config(jwks_manager: Arc<JwksManager>) -> HashMap<String, Arc<JwtConfig>> {
    APPLICATIONS
        .iter()
        .map(|app| {
            (
                (*app).to_string(),
                jwt_authorization_config_application(app, jwks_manager.clone()),
            )
        })
        .collect::<HashMap<_, _>>()
}

/// Decode a json web token (JWT) used for Google CSE
pub(crate) fn decode_jwt_authorization_token(
    jwt_config: &Arc<JwtConfig>,
    token: &str,
) -> KResult<(UserClaim, JwtTokenHeaders)> {
    kms_ensure!(
        !token.is_empty(),
        KmsError::Unauthorized("authorization token is empty".to_owned())
    );
    tracing::trace!(
        "validating CSE authorization token, expected issuer : {}",
        &jwt_config.jwt_issuer_uri
    );

    let validations = vec![
        #[cfg(not(test))]
        alcoholic_jwt::Validation::Audience(
            jwt_config
                .jwt_audience
                .as_ref()
                .ok_or_else(|| {
                    KmsError::ServerError(
                        "JWT audience should be configured with Google Workspace client-side \
                         encryption"
                            .to_string(),
                    )
                })?
                .to_string(),
        ),
        alcoholic_jwt::Validation::Issuer(jwt_config.jwt_issuer_uri.to_string()),
    ];

    // If a JWKS contains multiple keys, the correct KID first
    // needs to be fetched from the token headers.
    let kid = token_kid(token)
        .map_err(|_| KmsError::Unauthorized("Failed to decode token headers".to_string()))?
        .ok_or_else(|| KmsError::Unauthorized("No 'kid' claim present in token".to_string()))?;

    tracing::trace!("looking for kid `{kid}` JWKS:\n{:?}", jwt_config.jwks);

    let jwk = &jwt_config.jwks.find(&kid).ok_or_else(|| {
        KmsError::Unauthorized("[Google CSE auth] Specified key not found in set".to_string())
    })?;
    tracing::trace!("JWK has been found:\n{jwk:?}");

    let valid_jwt = alcoholic_jwt::validate(token, jwk, validations)
        .map_err(|err| KmsError::Unauthorized(format!("Cannot validate token: {err:?}")))?;

    tracing::trace!("valid_jwt user claims: {:?}", valid_jwt.claims);
    tracing::trace!("valid_jwt headers: {:?}", valid_jwt.headers);

    let user_claims = serde_json::from_value(valid_jwt.claims)
        .map_err(|err| KmsError::Unauthorized(format!("JWT claims are malformed: {err:?}")))?;

    let jwt_headers = serde_json::from_value(valid_jwt.headers)
        .map_err(|err| KmsError::Unauthorized(format!("JWT headers is malformed: {err:?}")))?;

    Ok((user_claims, jwt_headers))
}

/// The configuration for Google CSE:
///  - JWT authentication and authorization configurations
///  - external KACLS URL of this server configured in Google Workspace client-side encryption something like <https://cse.mydomain.com/google_cse>
#[derive(Clone)]
pub struct GoogleCseConfig {
    pub authentication: Arc<Vec<JwtConfig>>,
    pub authorization: HashMap<String, Arc<JwtConfig>>,
    pub kacls_url: String,
}

/// Validate the authentication and the authorization tokens and return the calling user
/// See [doc](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data?hl=en)
pub(crate) async fn validate_tokens(
    authentication_token: &str,
    authorization_token: &str,
    cse_config: &Option<GoogleCseConfig>,
    application: &str,
    roles: Option<&[&str]>,
) -> KResult<String> {
    let cse_config = cse_config.as_ref().ok_or_else(|| {
        KmsError::ServerError(
            "JWT authentication and authorization configurations for Google CSE are not set"
                .to_string(),
        )
    })?;

    // validate authentication token
    let mut decoded_token = None;
    for idp_config in cse_config.authentication.iter() {
        if let Ok(token) = idp_config.decode_authentication_token(authentication_token) {
            // store the decoded claim and break the loop if decoding succeeds
            decoded_token = Some(token);
            break;
        }
    }
    let authentication_token = decoded_token.ok_or_else(|| {
        KmsError::Unauthorized(
            "Fail to decode authentication token with the given config".to_owned(),
        )
    })?;

    tracing::trace!("authentication token: {authentication_token:?}");

    let jwt_config = cse_config.authorization.get(application).ok_or_else(|| {
        KmsError::NotSupported(format!(
            "no JWT config available for application: {application} "
        ))
    })?;
    let (authorization_token, jwt_headers) =
        decode_jwt_authorization_token(jwt_config, authorization_token)?;
    tracing::trace!("authorization token: {authorization_token:?}");
    tracing::trace!("authorization token headers: {jwt_headers:?}");

    // The emails should match (case insensitive)
    let authentication_email = authentication_token.email.ok_or_else(|| {
        KmsError::Unauthorized("Authentication token should contain an email".to_string())
    })?;
    let authorization_email = authorization_token.email.ok_or_else(|| {
        KmsError::Unauthorized("Authorization token should contain an email".to_string())
    })?;
    kms_ensure!(
        authorization_email == authentication_email,
        KmsError::Unauthorized(
            "Authentication and authorization emails in tokens do not match".to_string()
        )
    );

    if let Some(roles) = roles {
        let role = authorization_token.role.ok_or_else(|| {
            KmsError::Unauthorized("Authorization token should contain a role".to_string())
        })?;
        kms_ensure!(
            roles.contains(&role.as_str()),
            KmsError::Unauthorized(
                "Authorization token should contain a role of writer or owner".to_string()
            )
        );
    }

    if let Some(kacls_url) = authorization_token.kacls_url {
        kms_ensure!(
            kacls_url == cse_config.kacls_url,
            KmsError::Unauthorized(format!(
                "KACLS Urls should match: expected: {}, got: {} ",
                cse_config.kacls_url, kacls_url
            ))
        );
    }

    tracing::debug!("Google CSE request authorized for user {authentication_email}");

    Ok(authentication_email)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tracing::info;

    use crate::{
        config::JwtAuthConfig,
        middlewares::{JwksManager, JwtConfig},
        routes::google_cse::{
            self,
            jwt::{
                decode_jwt_authorization_token, jwt_authorization_config, JWKS_URI, JWT_ISSUER_URI,
            },
            operations::WrapRequest,
        },
        tests::google_cse::utils::generate_google_jwt,
    };

    #[tokio::test]
    async fn test_wrap_auth() {
        cosmian_logger::log_utils::log_init(None);

        let jwt = generate_google_jwt().await;

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
        tracing::debug!("wrap_request: {wrap_request:?}");
        let wrap_request: WrapRequest = serde_json::from_str(&wrap_request).unwrap();

        let uris = {
            let mut uris = google_cse::list_jwks_uri();
            uris.push(JwtAuthConfig::uri(JWT_ISSUER_URI, Some(JWKS_URI)));
            uris
        };
        let jwks_manager = Arc::new(JwksManager::new(uris).await.unwrap());
        jwks_manager.refresh().await.unwrap();

        let client_id = std::env::var("TEST_GOOGLE_OAUTH_CLIENT_ID").unwrap();
        // Test authentication
        let jwt_authentication_config = JwtAuthConfig {
            jwt_issuer_uri: Some(vec![JWT_ISSUER_URI.to_string()]),
            jwks_uri: Some(vec![JWKS_URI.to_string()]),
            jwt_audience: Some(vec![client_id]),
        };
        let jwt_authentication_config = JwtConfig {
            jwt_issuer_uri: jwt_authentication_config.jwt_issuer_uri.unwrap()[0].clone(),
            jwks: jwks_manager.clone(),
            jwt_audience: Some(jwt_authentication_config.jwt_audience.unwrap()[0].clone()),
        };

        let authentication_token = jwt_authentication_config
            .decode_authentication_token(&wrap_request.authentication)
            .unwrap();
        info!("AUTHENTICATION token: {:?}", authentication_token);
        assert_eq!(
            authentication_token.iss,
            Some("https://accounts.google.com".to_string())
        );
        assert_eq!(
            authentication_token.email,
            Some("blue@cosmian.com".to_string())
        );
        assert_eq!(
            authentication_token.aud,
            Some(
                "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"
                    .to_string()
            )
        );

        // Test authorization
        // we fake the URLs and use authentication tokens,
        // because we don't know the URL of the Google Drive authorization token API.
        unsafe {
            std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWKS_URI", JWKS_URI);
            std::env::set_var("KMS_GOOGLE_CSE_DRIVE_JWT_ISSUER", JWT_ISSUER_URI); // the token has been issued by Google Accounts (post request)
        }
        let jwt_authorization_config = jwt_authorization_config(jwks_manager);
        tracing::trace!("{jwt_authorization_config:#?}");

        let (authorization_token, jwt_headers) = decode_jwt_authorization_token(
            jwt_authorization_config.get("drive").unwrap(),
            &wrap_request.authorization,
        )
        .unwrap();
        info!("AUTHORIZATION token: {:?}", authorization_token);
        info!("AUTHORIZATION token headers: {:?}", jwt_headers);

        assert_eq!(
            authorization_token.email,
            Some("blue@cosmian.com".to_string())
        );
        // prev: Some("cse-authorization".to_string())
        assert_eq!(
            authorization_token.aud,
            Some(
                "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"
                    .to_string()
            )
        );
    }
}
