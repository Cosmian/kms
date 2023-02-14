use alcoholic_jwt::JWKS;
use clap::Args;
use eyre::Context;

#[derive(Debug, Args, Default)]
pub struct Auth0Config {
    /// Enable the use of Auth0 by specifying the delegated authority domain configured on Auth0
    #[clap(long, env = "KMS_AUTH0_AUTHORITY_DOMAIN")]
    pub auth0_authority_domain: Option<String>,
}

impl Auth0Config {
    pub async fn init(&self) -> eyre::Result<Option<JWKS>> {
        match &self.auth0_authority_domain {
            None => Ok(None),
            Some(delegated_authority_domain) => {
                let delegated_authority_domain = delegated_authority_domain.trim_end_matches('/');
                let jwks_uri =
                    format!("https://{delegated_authority_domain}/.well-known/jwks.json");
                reqwest::get(jwks_uri)
                    .await
                    .with_context(|| "Unable to connect to retrieve JWKS")?
                    .json::<JWKS>()
                    .await
                    .map_err(|e| eyre::eyre!(format!("Unable to get JWKS as a JSON: {}", e)))
                    .map(Option::Some)
            }
        }
    }
}
