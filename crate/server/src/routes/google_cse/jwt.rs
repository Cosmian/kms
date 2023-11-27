use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use actix_rt::task;
use alcoholic_jwt::token_kid;

use crate::{
    config::JwtAuthConfig,
    error::KmsError,
    kms_ensure,
    middlewares::{JwtConfig, JwtTokenHeaders, UserClaim},
    result::{KResult, KResultHelper},
};

fn get_jwks_uri(application: &str) -> String {
    std::env::var(format!("KMS_GOOGLE_CSE_{}_JWKS_URI", application.to_uppercase()))
    .unwrap_or(format!("https://www.googleapis.com/service_accounts/v1/jwk/gsuitecse-tokenissuer-{application}@system.gserviceaccount.com"))
}

/// Fetch the JWT authorization configuration for Google CSE 'drive' or 'meet'
async fn jwt_authorization_config_application(application: &str) -> KResult<Arc<JwtConfig>> {
    let jwks_uri = get_jwks_uri(application);

    let jwt_issuer_uri = std::env::var(format!(
        "KMS_GOOGLE_CSE_{}_JWT_ISSUER",
        application.to_uppercase()
    ))
    .unwrap_or(format!(
        "gsuitecse-tokenissuer-{application}@system.gserviceaccount.com"
    ));

    let jwt_audience =
        Some(std::env::var("KMS_GOOGLE_CSE_AUDIENCE").unwrap_or("cse-authorization".to_string()));

    // Fetch the JWKS for the Google CSE service account
    let jwks_uri_rq = jwks_uri.clone();
    let jwks = task::spawn_blocking(move || JwtAuthConfig::request_jwks(&jwks_uri_rq))
        .await
        .map_err(|e| KmsError::Unauthorized(format!("cannot request JWKS: {e}")))?
        .context(&format!("Failed to fetch Google CSE JWKS at: {jwks_uri}"))?;

    Ok(Arc::new(JwtConfig {
        jwt_issuer_uri,
        jwks: RwLock::new(jwks),
        jwt_audience,
    }))
}

/// Fetch the JWT authorization configuration for Google CSE 'drive' and 'meet'
pub async fn jwt_authorization_config() -> KResult<HashMap<String, Arc<JwtConfig>>> {
    Ok(HashMap::from([
        (
            "drive".to_string(),
            jwt_authorization_config_application("drive").await?,
        ),
        (
            "meet".to_string(),
            jwt_authorization_config_application("meet").await?,
        ),
    ]))
}

/// Decode a json web token (JWT) used for Google CSE
pub async fn decode_jwt_authorization_token(
    jwt_config: &Arc<JwtConfig>,
    token: &str,
    application: &str,
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

    tracing::trace!("JWKS:\n{:?}", jwt_config.jwks);

    let jwk = {
        let jwk = jwt_config
            .jwks
            .read()
            .expect("cannot lock jwks for read")
            .find(&kid)
            .cloned();
        match jwk {
            Some(jwk) => jwk,
            None => {
                tracing::trace!("refreshing jwks");
                let jwks_uri = get_jwks_uri(application);

                // refresh JWKS
                jwt_config
                    .refresh_jwk_set(&jwks_uri)
                    .await
                    .context(&format!("Failed to fetch Google CSE JWKS at: {jwks_uri}"))?;

                // retry auth
                let jwks = jwt_config.jwks.read().expect("cannot lock jwks for read");
                tracing::trace!("find '{kid:?}' in new jwks:\n{jwks:#?}");
                jwks.find(&kid).cloned().ok_or_else(|| {
                    KmsError::Unauthorized("Specified key not found in set".to_string())
                })?
            }
        }
    };

    tracing::trace!("JWK has been found:\n{jwk:?}");

    let valid_jwt = alcoholic_jwt::validate(token, &jwk, validations)
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
///  - external KACLS URL of this server configured in Google Workspace client-side encryption
/// (something like <https://cse.mydomain.com/google_cse>)
#[derive(Clone)]
pub struct GoogleCseConfig {
    pub authentication: Arc<JwtConfig>,
    pub authorization: HashMap<String, Arc<JwtConfig>>,
    pub kacls_url: String,
}

/// Validate the authentication and the authorization tokens and return the calling user
/// See [doc](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data?hl=en)
pub async fn validate_tokens(
    authentication_token: &str,
    authorization_token: &str,
    cse_config: &Option<GoogleCseConfig>,
    application: &str,
    roles: &[&str],
) -> KResult<String> {
    let cse_config = cse_config.as_ref().ok_or_else(|| {
        KmsError::ServerError(
            "JWT authentication and authorization configurations for Google CSE are not set"
                .to_string(),
        )
    })?;

    // validate authentication token
    let authentication_token = cse_config
        .authentication
        .decode_authentication_token(authentication_token)?;
    tracing::trace!("authentication token: {authentication_token:?}");

    let jwt_config = cse_config.authorization.get(application).ok_or_else(|| {
        KmsError::NotSupported(format!(
            "no JWT config available for application: {application} "
        ))
    })?;
    let (authorization_token, jwt_headers) =
        decode_jwt_authorization_token(jwt_config, authorization_token, application).await?;
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

    let role = authorization_token.role.ok_or_else(|| {
        KmsError::Unauthorized("Authorization token should contain a role".to_string())
    })?;
    kms_ensure!(
        roles.contains(&role.as_str()),
        KmsError::Unauthorized(
            "Authorization token should contain a role of writer or owner".to_string()
        )
    );

    let kacls_url = authorization_token.kacls_url.ok_or_else(|| {
        KmsError::Unauthorized("Authorization token should contain a kacls_url".to_string())
    })?;
    kms_ensure!(
        kacls_url == cse_config.kacls_url,
        KmsError::Unauthorized(format!(
            "KACLS Urls should match: expected: {}, got: {} ",
            cse_config.kacls_url, kacls_url
        ))
    );

    tracing::debug!("wrap request authorized for user {authentication_email}");

    Ok(authentication_email)
}

#[cfg(test)]
mod tests {
    use std::sync::RwLock;

    use cosmian_logger::log_utils::log_init;
    use serde::Deserialize;
    use tracing::info;

    use crate::{
        config::JwtAuthConfig,
        middlewares::JwtConfig,
        routes::google_cse::{
            jwt::{decode_jwt_authorization_token, jwt_authorization_config},
            operations::WrapRequest,
        },
    };

    #[tokio::test]
    async fn test_wrap_auth() {
        log_init("cosmian_kms_server=trace");

        #[derive(Deserialize)]
        struct Token {
            pub id_token: String,
        }

        let client_id = std::env::var("TEST_GOOGLE_OAUTH_CLIENT_ID").unwrap();
        let client_secret = std::env::var("TEST_GOOGLE_OAUTH_CLIENT_SECRET").unwrap();
        let refresh_token = std::env::var("TEST_GOOGLE_OAUTH_REFRESH_TOKEN").unwrap();

        assert!(!client_id.is_empty());
        assert!(!client_secret.is_empty());
        assert!(!refresh_token.is_empty());

        let res = reqwest::Client::new()
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("client_id", client_id.as_str()),
                ("client_secret", client_secret.as_str()),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.as_str()),
            ])
            .send()
            .await
            .unwrap();

        tracing::debug!("Oauth response: {res:?}");

        let jwt = res.json::<Token>().await.unwrap().id_token;

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

        // Test authentication
        let jwt_authentication_config = JwtAuthConfig {
            jwt_issuer_uri: Some("https://accounts.google.com".to_string()),
            jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs".to_string()),
            jwt_audience: None,
        };
        let jwt_authentication_config = JwtConfig {
            jwt_issuer_uri: jwt_authentication_config.jwt_issuer_uri.clone().unwrap(),
            jwks: RwLock::new(
                jwt_authentication_config
                    .fetch_jwks()
                    .await
                    .unwrap()
                    .unwrap(),
            ),
            jwt_audience: jwt_authentication_config.jwt_audience.clone(),
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
        std::env::set_var(
            "KMS_GOOGLE_CSE_DRIVE_JWKS_URI",
            "https://www.googleapis.com/oauth2/v3/certs",
        );
        std::env::set_var(
            "KMS_GOOGLE_CSE_DRIVE_JWT_ISSUER",
            "https://accounts.google.com", // the token has been issued by Google Accounts (post request)
        );
        let jwt_authorization_config = jwt_authorization_config().await.unwrap();
        tracing::trace!("{jwt_authorization_config:#?}");

        let (authorization_token, jwt_headers) = decode_jwt_authorization_token(
            jwt_authorization_config.get("drive").unwrap(),
            &wrap_request.authorization,
            "drive",
        )
        .await
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
