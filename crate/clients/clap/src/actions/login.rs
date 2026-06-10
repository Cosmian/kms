use clap::Parser;
use cosmian_kms_client::{
    KmsClientConfig,
    reexport::cosmian_http_client::{CosmianLoginConfig, LoginState, cosmian_login},
};

use crate::error::{KmsCliError, result::KmsCliResult};

/// Login to the KMS server identity provider.
///
/// Two subcommands are available:
///
/// **oauth** — `OAuth2` / OIDC authorization-code flow (opens a browser window).
/// Requires an `oauth2_conf` section in the configuration file with fields:
/// - `client_id`, `client_secret`, `authorize_url`, `token_url`, `scopes`.
///   The callback URL must be whitelisted with value `http://localhost:17899/token`.
///
/// **cosmian** — Cosmian authentication server (HTTP Basic credentials).
/// Requires a `cosmian_conf` section in the configuration file with fields:
/// - `server_url`: base URL of the Cosmian authentication server.
/// - `realm`: realm to authenticate against (e.g. `"kms"`).
///   The endpoint called is `POST {server_url}/login?realm={realm}` with an
///   `Authorization: Basic <base64(username:password)>` header.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct LoginAction {
    #[command(subcommand)]
    pub subcommand: LoginSubcommand,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum LoginSubcommand {
    /// Login using the `OAuth2` authorization code flow.
    Oauth,
    /// Login using Cosmian authentication server (HTTP Basic credentials).
    ///
    /// The configuration file must contain a `cosmian_conf` section with
    /// `server_url` and `realm`.  Credentials are transmitted via an
    /// `Authorization: Basic` header to `POST {server_url}/login?realm={realm}`.
    Cosmian {
        /// Username for HTTP Basic authentication.
        #[clap(long, short = 'u')]
        username: String,
        /// Password for HTTP Basic authentication.
        #[clap(long, short = 'p')]
        password: String,
    },
}

impl LoginAction {
    /// Process the login action
    ///
    /// # Errors
    /// - If the required configuration section is missing or invalid
    /// - If the authentication request fails
    #[expect(clippy::print_stdout)]
    pub async fn process(&self, config: KmsClientConfig) -> KmsCliResult<String> {
        match &self.subcommand {
            LoginSubcommand::Oauth => {
                let login_config = config.http_config.oauth2_conf.as_ref().ok_or_else(|| {
                    KmsCliError::Default(format!(
                        "The `login oauth` command (only used for JWT authentication) requires an Identity \
                         Provider (IdP) that MUST be configured in the oauth2_conf object in {config:?}",
                    ))
                })?;

                let state = LoginState::try_from(login_config.clone())?;
                println!("Browse to: {}", state.auth_url);
                let access_token = state.finalize().await?;

                println!("\nSuccess! The access token was saved in the KMS configuration (in memory)");

                Ok(access_token)
            }
            LoginSubcommand::Cosmian { username, password } => {
                let cosmian_conf: &CosmianLoginConfig =
                    config.http_config.cosmian_conf.as_ref().ok_or_else(|| {
                        KmsCliError::Default(
                            "The `login cosmian` command requires a `cosmian_conf` section in the \
                             KMS client configuration file with `server_url` and `realm` fields."
                                .to_owned(),
                        )
                    })?;

                let access_token = cosmian_login(cosmian_conf, username, password).await?;

                println!("\nSuccess! The access token was saved in the KMS configuration (in memory)");

                Ok(access_token)
            }
        }
    }
}
