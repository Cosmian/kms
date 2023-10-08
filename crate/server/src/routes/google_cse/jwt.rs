use actix_web::web::Data;
use alcoholic_jwt::{token_kid, JWKS};
use tracing::{debug, trace};

use crate::{
    error::KmsError,
    kms_ensure,
    middlewares::{decode_jwt_authentication_token, JwtConfig, JwtTokenHeaders, UserClaim},
    result::KResult,
};

/// Fetch the JWT authorization configuration for Google CSE
pub async fn jwt_authorization_config() -> KResult<JwtConfig> {
    let jwks_uri =std::env::var("KMS_GOOGLE_CSE_JWKS_URI").unwrap_or("https://www.googleapis.com/service_accounts/v1/jwk/gsuitecse-tokenissuer-drive@system.gserviceaccount.com".to_string());

    let jwks = reqwest::get(&jwks_uri)
        .await
        .map_err(|e| {
            KmsError::ServerError(format!(
                "Failed to fetch Google CSE authorization JWKS at: {}, {:?} ",
                jwks_uri, e
            ))
        })?
        .json::<JWKS>()
        .await
        .map_err(|e| {
            KmsError::ServerError(format!(
                "Failed to parse Google CSE authorization JWKS at: {}, {:?} ",
                jwks_uri, e
            ))
        })?;

    Ok(JwtConfig {
        jwt_issuer_uri: std::env::var("KMS_GOOGLE_CSE_JWT_ISSUER")
            .unwrap_or("gsuitecse-tokenissuer-drive@system.gserviceaccount.com".to_string()),
        jwks,
        jwt_audience: Some(
            std::env::var("KMS_GOOGLE_CSE_AUDIENCE").unwrap_or("cse-authorization".to_string()),
        ),
    })
}

/// Decode a json web token (JWT) used for Google CSE
pub fn decode_jwt_authorization_token(
    jwt_config: &JwtConfig,
    token: &str,
) -> KResult<(UserClaim, JwtTokenHeaders)> {
    kms_ensure!(
        !token.is_empty(),
        KmsError::Unauthorized("token is empty".to_owned())
    );
    tracing::trace!(
        "validating CSE authorization token {} with expected issuer : {}",
        &token,
        &jwt_config.jwt_issuer_uri
    );

    let validations = vec![
        alcoholic_jwt::Validation::Issuer(jwt_config.jwt_issuer_uri.to_string()),
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
    ];

    // If a JWKS contains multiple keys, the correct KID first
    // needs to be fetched from the token headers.
    let kid = token_kid(token)
        .map_err(|_| KmsError::Unauthorized("Failed to decode token headers".to_string()))?
        .ok_or_else(|| KmsError::Unauthorized("No 'kid' claim present in token".to_string()))?;

    let jwk = jwt_config
        .jwks
        .find(&kid)
        .ok_or_else(|| KmsError::Unauthorized("Specified key not found in set".to_string()))?;

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

/// The configuration for for Google CSE:
///  - JWT authentication and authorization configurations
///  - external KACLS URL of this server configured in Google Workspace client-side encryption
/// (something like https://cse.mydomain.com/google_cse)
#[derive(Clone)]
pub struct GoogleCseConfig {
    pub authentication: JwtConfig,
    pub authorization: JwtConfig,
    pub kacls_url: String,
}

/// Validate the authentication and the authorization tokens
/// See [doc](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data?hl=en)
pub fn validate_tokens(
    authentication_token: &str,
    authorization_token: &str,
    cse_config: Data<Option<GoogleCseConfig>>,
    roles: &[&str],
) -> KResult<()> {
    let cse_config_inner = cse_config.into_inner();
    let cse_config = cse_config_inner.as_ref().as_ref().ok_or_else(|| {
        KmsError::ServerError(
            "JWT authentication and authorization configurations for Google CSE are not set"
                .to_string(),
        )
    })?;

    // validate authentication token
    let authentication_token =
        decode_jwt_authentication_token(&cse_config.authentication, authentication_token)?;
    trace!("authentication token: {:?}", authentication_token);

    let (authorization_token, jwt_headers) =
        decode_jwt_authorization_token(&cse_config.authorization, authorization_token)?;
    trace!("authorization token: {:?}", authorization_token);
    trace!("authorization token headers: {:?}", jwt_headers);

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

    debug!("wrap request authorized");

    Ok(())
}
