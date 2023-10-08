use alcoholic_jwt::{token_kid, JWKS};
use serde::{Deserialize, Serialize};

use crate::{error::KmsError, kms_ensure, result::KResult};

#[derive(Clone)]
pub struct JwtConfig {
    pub jwt_issuer_uri: String,
    pub jwks: JWKS,
    pub jwt_audience: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserClaim {
    pub email: Option<String>,
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iat: Option<usize>,
    pub exp: Option<usize>,
    pub nbf: Option<usize>,
    pub jti: Option<String>,
    // Google specific (?)
    pub role: Option<String>,
    // Google specific (?)
    pub resource_name: Option<String>,
    // Google specific
    pub kacls_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct JwtTokenHeaders {
    pub typ: Option<String>,
    pub cty: Option<String>,
    pub alg: Option<String>,
    pub kid: Option<String>,
    pub x5t: Option<String>,
    pub x5u: Option<String>,
    pub x5c: Option<Vec<String>>,
    pub crit: Option<String>,
}

/// Decode a JWT bearer header
pub fn decode_jwt_bearer_header(
    jwt_config: &JwtConfig,
    authorization_content: &str,
) -> KResult<UserClaim> {
    let bearer: Vec<&str> = authorization_content.splitn(2, ' ').collect();
    kms_ensure!(
        bearer.len() == 2 && bearer[0] == "Bearer",
        KmsError::Unauthorized("Bad authorization header content (bad bearer)".to_owned())
    );

    let token: &str = bearer[1];
    decode_jwt_authentication_token(jwt_config, token)
}

/// Decode a json web token (JWT)
pub fn decode_jwt_authentication_token(jwt_config: &JwtConfig, token: &str) -> KResult<UserClaim> {
    kms_ensure!(
        !token.is_empty(),
        KmsError::Unauthorized("token is empty".to_owned())
    );
    tracing::trace!("token {}", &token);
    tracing::trace!(
        "expected JWT issuer {}",
        &jwt_config.jwt_issuer_uri.to_string()
    );

    let mut validations = vec![
        alcoholic_jwt::Validation::Issuer(jwt_config.jwt_issuer_uri.to_string()),
        alcoholic_jwt::Validation::SubjectPresent,
        #[cfg(not(feature = "insecure"))]
        alcoholic_jwt::Validation::NotExpired,
    ];
    if let Some(jwt_audience) = &jwt_config.jwt_audience {
        validations.push(alcoholic_jwt::Validation::Audience(
            jwt_audience.to_string(),
        ));
    }

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

    let payload = serde_json::from_value(valid_jwt.claims)
        .map_err(|err| KmsError::Unauthorized(format!("JWT claims is malformed: {err:?}")))?;

    Ok(payload)
}
