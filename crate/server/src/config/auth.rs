use alcoholic_jwt::JWKS;
use clap::Args;
use eyre::Context;

#[derive(Debug, Args)]
pub struct AuthConfig {
    /// Delegated authority domain coming from auth0
    #[clap(long, env = "KMS_DELEGATED_AUTHORITY_DOMAIN")]
    pub delegated_authority_domain: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            delegated_authority_domain: "".to_string(),
        }
    }
}

impl AuthConfig {
    pub async fn init(&self) -> eyre::Result<JWKS> {
        let delegated_authority_domain: String = self
            .delegated_authority_domain
            .trim_end_matches('/')
            .to_string();

        let jwks_uri = format!("https://{delegated_authority_domain}/.well-known/jwks.json");

        reqwest::get(jwks_uri)
            .await
            .with_context(|| "Unable to connect to retrieve JWKS")?
            .json::<JWKS>()
            .await
            .with_context(|| "Unable to get JWKS as a JSON")
    }
}
