use alcoholic_jwt::JWKS;
use clap::Args;

use crate::{
    kms_error,
    result::{KResult, KResultHelper},
};

// Support for JWT token inspired by the doc at : https://cloud.google.com/api-gateway/docs/authenticating-users-jwt
// and following pages

#[derive(Debug, Args, Default)]
pub struct JwtAuthConfig {
    /// The issuer URI of the JWT token
    ///
    /// For Auth0, this is the delegated authority domain configured on Auth0, for instance
    /// `https://<your-tenant>.<region>.auth0.com/`
    ///
    /// For Google, this would be `https://accounts.google.com`
    #[clap(long, env = "KMS_JWT_ISSUER_URI")]
    pub jwt_issuer_uri: Option<String>,

    /// The JWKS (Json Web Key Set) URI of the JWT token
    ///
    /// For Auth0, this would be `https://<your-tenant>.<region>.auth0.com/.well-known/jwks.json`
    ///
    /// For Google, this would be `https://www.googleapis.com/oauth2/v3/certs`
    ///
    /// Defaults to `<jwt-issuer-uri>/.well-known/jwks.json` is not set
    #[clap(long, env = "KMS_JWKS_URI")]
    pub jwks_uri: Option<String>,

    /// The audience of the JWT token
    ///
    /// Optional: the server will validate the JWT `aud` claim against this value if set
    #[clap(long, env = "KMS_JST_AUDIENCE")]
    pub jwt_audience: Option<String>,
}

impl JwtAuthConfig {
    pub async fn fetch_jwks(&self) -> KResult<Option<JWKS>> {
        match &self.jwt_issuer_uri {
            None => Ok(None),
            Some(jwt_issuer_uri) => {
                let jwt_issuer_uri = jwt_issuer_uri.trim_end_matches('/');
                let jwks_uri = match &self.jwks_uri {
                    None => format!("{jwt_issuer_uri}/.well-known/jwks.json"),
                    Some(jwks_uri) => jwks_uri.to_string(),
                };
                reqwest::get(jwks_uri)
                    .await
                    .context("Unable to connect to retrieve JWKS")?
                    .json::<JWKS>()
                    .await
                    .map_err(|e| kms_error!(format!("Unable to get JWKS as a JSON: {e}")))
                    .map(Option::Some)
            }
        }
    }
}
