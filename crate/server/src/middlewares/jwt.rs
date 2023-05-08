use alcoholic_jwt::token_kid;
use serde::{Deserialize, Serialize};

use crate::{
    config::SharedConfig,
    error::KmsError,
    kms_ensure,
    result::{KResult, KResultHelper},
};

#[derive(Debug, Deserialize, Serialize)]
pub struct UserClaim {
    pub email: Option<String>,
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: usize,
    pub exp: usize,
}

/// Decode a json web token (JWT)
pub fn decode_jwt_new(authorization_content: &str) -> KResult<UserClaim> {
    let bearer: Vec<&str> = authorization_content.splitn(2, ' ').collect();
    kms_ensure!(
        bearer.len() == 2 && bearer[0] == "Bearer",
        KmsError::Unauthorized("Bad authorization header content (bad bearer)".to_owned())
    );

    let token: &str = bearer[1];

    kms_ensure!(
        !token.is_empty(),
        KmsError::Unauthorized("token is empty".to_owned())
    );
    tracing::trace!("token {}", &token);

    let jwt_issuer_uri = SharedConfig::jwt_issuer_uri()
        .context("decode JWT token requested but JWT Auth is not enabled")?;
    let jwks =
        SharedConfig::jwks().context("decode JWT token requested but JWT Auth is not enabled")?;
    let jwt_audience = SharedConfig::jwt_audience();

    let mut validations = vec![
        alcoholic_jwt::Validation::Issuer(jwt_issuer_uri),
        alcoholic_jwt::Validation::SubjectPresent,
        #[cfg(not(feature = "insecure"))]
        alcoholic_jwt::Validation::NotExpired,
    ];
    if let Some(jwt_audience) = jwt_audience {
        validations.push(alcoholic_jwt::Validation::Audience(jwt_audience));
    }

    // If a JWKS contains multiple keys, the correct KID first
    // needs to be fetched from the token headers.
    let kid = token_kid(token)
        .map_err(|_| KmsError::Unauthorized("Failed to decode token headers".to_string()))?
        .ok_or_else(|| KmsError::Unauthorized("No 'kid' claim present in token".to_string()))?;

    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| KmsError::Unauthorized("Specified key not found in set".to_string()))?;

    let valid_jwt = alcoholic_jwt::validate(token, jwk, validations)
        .map_err(|err| KmsError::Unauthorized(format!("Cannot validate token: {err:?}")))?;

    let payload = serde_json::from_value(valid_jwt.claims)
        .map_err(|err| KmsError::Unauthorized(format!("JWT claims is malformed: {err:?}")))?;

    Ok(payload)
}
