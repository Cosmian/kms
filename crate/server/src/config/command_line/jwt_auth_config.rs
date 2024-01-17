use actix_rt::task;
use alcoholic_jwt::JWKS;
use clap::Args;
use serde::{Deserialize, Serialize};

use crate::{
    error::KmsError,
    kms_error,
    result::{KResult, KResultHelper},
};

// Support for JWT token inspired by the doc at : https://cloud.google.com/api-gateway/docs/authenticating-users-jwt
// and following pages

#[derive(Debug, Default, Args, Deserialize, Serialize)]
#[serde(default)]
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
    /// Defaults to `<jwt-issuer-uri>/.well-known/jwks.json` if not set
    #[clap(long, env = "KMS_JWKS_URI")]
    pub jwks_uri: Option<String>,

    /// The audience of the JWT token
    ///
    /// Optional: the server will validate the JWT `aud` claim against this value if set
    #[clap(long, env = "KMS_JST_AUDIENCE")]
    pub jwt_audience: Option<String>,
}

impl JwtAuthConfig {
    /// Request JWKS using the `jwks_uri`
    ///
    /// Implementation details:
    ///
    /// this request is blocking because it may be called from
    /// within an Actix service, which is not async.
    /// Managing `Box::pin` around doesn't help much as it needs
    /// the service's `call` method to have an extended
    /// lifetime (on `self`), which is not very easy to handle.
    pub fn request_jwks(jwks_uri: &str) -> KResult<JWKS> {
        reqwest::blocking::get(jwks_uri)
            .context("Unable to connect to retrieve JWKS")?
            .json::<JWKS>()
            .map_err(|e| kms_error!(format!("Unable to get JWKS as a JSON: {e}")))
    }

    pub async fn fetch_jwks(&self) -> KResult<Option<JWKS>> {
        match &self.jwt_issuer_uri {
            None => Ok(None),
            Some(jwt_issuer_uri) => {
                let jwt_issuer_uri = jwt_issuer_uri.trim_end_matches('/');
                let jwks_uri = self.jwks_uri.as_ref().map_or(
                    format!("{jwt_issuer_uri}/.well-known/jwks.json"),
                    std::string::ToString::to_string,
                );
                task::spawn_blocking(move || {
                    JwtAuthConfig::request_jwks(&jwks_uri).map(Option::Some)
                })
                .await
                .map_err(|e| KmsError::Unauthorized(format!("cannot request JWKS: {e}")))?
            }
        }
    }
}
