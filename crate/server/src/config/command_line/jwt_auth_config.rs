use clap::Args;
use serde::{Deserialize, Serialize};

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
    #[clap(long, env = "KMS_JWT_ISSUER_URI", num_args = 1..)]
    pub jwt_issuer_uri: Option<Vec<String>>,

    /// The JWKS (Json Web Key Set) URI of the JWT token
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
    pub fn uri(jwt_issuer_uri: &str, jwks_uri: Option<&str>) -> String {
        jwks_uri.as_ref().map_or(
            format!(
                "{}/.well-known/jwks.json",
                jwt_issuer_uri.trim_end_matches('/')
            ),
            std::string::ToString::to_string,
        )
    }
}
