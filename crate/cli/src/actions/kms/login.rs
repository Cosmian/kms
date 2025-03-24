use clap::Parser;
use cosmian_kms_client::{KmsClientConfig, reexport::cosmian_http_client::LoginState};

use crate::error::{CosmianError, result::CosmianResult};

/// Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.
///
/// This command will open a browser window and ask you to login to the Identity Provider.
/// Once you have logged in, the access token will be saved in the cosmian configuration file.
///
/// The configuration file must contain an `oauth2_conf` object with the following fields:
/// - `client_id`: The client ID of your application. This is provided by the Identity Provider.
/// - `client_secret`: The client secret of your application. This is provided by the Identity Provider.
/// - `authorize_url`: The authorization URL of the provider. For example, for Google it is `https://accounts.google.com/o/oauth2/v2/auth`.
/// - `token_url`: The token URL of the provider. For example, for Google it is `https://oauth2.googleapis.com/token`.
/// - `scopes`: The scopes to request. For example, for Google it is `["openid", "email"]`.
///
/// The callback url must be authorized on the Identity Provider with value `http://localhost:17899/token`.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct LoginAction;

impl LoginAction {
    /// Process the login action
    ///
    /// # Errors
    /// - If the `OAuth2` configuration invalid
    #[allow(clippy::print_stdout)]
    pub async fn process(&self, config: &mut KmsClientConfig) -> CosmianResult<()> {
        let login_config = config.http_config.oauth2_conf.as_ref().ok_or_else(|| {
            CosmianError::Default(format!(
                "The `login` command (only used for JWT authentication) requires an Identity \
                 Provider (IdP) that MUST be configured in the oauth2_conf object in {config:?}",
            ))
        })?;

        let state = LoginState::try_from(login_config.clone())?;
        println!("Browse to: {}", state.auth_url);
        let access_token = state.finalize().await?;

        config.http_config.access_token = Some(access_token);
        println!("\nSuccess! The access token was saved in the KMS configuration");

        Ok(())
    }
}
