use clap::Args;
use serde::{Deserialize, Serialize};

use crate::{config::IdpConfig, error::KmsError, kms_ensure};

// Support for JWT token inspired by the doc at : https://cloud.google.com/api-gateway/docs/authenticating-users-jwt
// and following pages

#[derive(Debug, Default, Args, Deserialize, Serialize)]
#[serde(default)]
pub struct JwtAuthConfig {
    /// The issuer URI of the JWT token
    ///
    /// To handle multiple identity managers, add different parameters under each argument
    /// (jwt-issuer-uri, jwks-uri and optionally jwt-audience), keeping them in
    /// the same order :
    ///
    /// --jwt-issuer-uri <`JWT_ISSUER_URI_1`> <`JWT_ISSUER_URI_2`>
    /// --jwks-uri <`JWKS_URI_1`> <`JWKS_URI_2`>
    /// --jwt-audience <`JWT_AUDIENCE_1`> <`JWT_AUDIENCE_2`>
    ///
    /// For Auth0, this is the delegated authority domain configured on Auth0, for instance
    /// `https://<your-tenant>.<region>.auth0.com/`
    ///
    /// For Google, this would be `https://accounts.google.com`
    #[clap(long, env = "KMS_JWT_ISSUER_URI", num_args = 1..)]
    pub jwt_issuer_uri: Option<Vec<String>>,

    /// The JWKS (Json Web Key Set) URI of the JWT token
    ///
    /// To handle multiple identity managers, add different parameters under each argument
    /// (jwt-issuer-uri, jwks-uri and optionally jwt-audience), keeping them in
    /// the same order
    ///
    /// For Auth0, this would be `https://<your-tenant>.<region>.auth0.com/.well-known/jwks.json`
    ///
    /// For Google, this would be `https://www.googleapis.com/oauth2/v3/certs`
    ///
    /// Defaults to `<jwt-issuer-uri>/.well-known/jwks.json` if not set
    #[clap(long, env = "KMS_JWKS_URI", num_args = 1..)]
    pub jwks_uri: Option<Vec<String>>,

    /// The audience of the JWT token
    ///
    /// Optional: the server will validate the JWT `aud` claim against this value if set
    #[clap(long, env = "KMS_JST_AUDIENCE", num_args = 1..)]
    pub jwt_audience: Option<Vec<String>>,
}

impl JwtAuthConfig {
    /// Build a JWKS URI using `jwt_issuer_uri` and an optional `jwks_uri`.
    pub(crate) fn uri(jwt_issuer_uri: &str, jwks_uri: Option<&str>) -> String {
        jwks_uri.as_ref().map_or(
            format!(
                "{}/.well-known/jwks.json",
                jwt_issuer_uri.trim_end_matches('/')
            ),
            std::string::ToString::to_string,
        )
    }

    /// Parse this configuration into one identity provider configuration per JWT issuer URI.
    ///
    /// Assert that when provided, JWKS URI and JWT audience are provided once per JWT issuer URI;
    pub(crate) fn extract_idp_configs(self) -> Result<Option<Vec<IdpConfig>>, KmsError> {
        self.jwt_issuer_uri
            .map(|issuer_uris| {
                let option_vec_to_vec_option = |option_vec: Option<Vec<_>>| {
                    option_vec.map_or_else(
                        || vec![None; issuer_uris.len()],
                        |vec| vec.into_iter().map(Some).collect(),
                    )
                };

                let jwks_uris = option_vec_to_vec_option(self.jwks_uri);
                let audiences = option_vec_to_vec_option(self.jwt_audience);

                kms_ensure!(
                    jwks_uris.len() == issuer_uris.len(),
                    "If jwks_uri are provided, they should match each provided jwt_issuer_uri."
                );
                kms_ensure!(
                    audiences.len() == issuer_uris.len(),
                    "If jwt_audience are provided, they should match each provided jwt_issuer_uri."
                );

                Ok(issuer_uris
                    .into_iter()
                    .zip(jwks_uris)
                    .zip(audiences)
                    .map(|((jwt_issuer_uri, jwks_uri), jwt_audience)| IdpConfig {
                        jwt_issuer_uri,
                        jwks_uri,
                        jwt_audience,
                    })
                    .collect())
            })
            .transpose()
    }
}
