use clap::Parser;
use cosmian_config_utils::ConfigUtils;
use cosmian_kms_client::{reexport::cosmian_http_client::LoginState, KmsClientConfig};

use crate::error::{result::CliResult, CliError};

/// Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.
///
/// This command will open a browser window and ask you to login to the Identity Provider.
/// Once you have logged in, the access token will be saved in the ckms configuration file.
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
    /// This function processes the login action.
    /// It loads the client configuration from the specified path, retrieves the `OAuth2` configuration,
    /// initializes the login state, prompts the user to browse to the authorization URL,
    /// finalizes the login process by receiving the authorization code and exchanging it for an access token,
    /// updates the configuration with the access token, and saves the configuration to the specified path.
    ///
    /// # Arguments
    ///
    /// * `conf_path` - The path to the client configuration file.
    ///
    /// # Errors
    ///
    /// This function can return a `CliError` in the following cases:
    ///
    /// * The `login` command requires an Identity Provider (`IdP`) that must be configured in the `oauth2_conf` object in the client configuration file.
    /// * The client configuration file cannot be loaded.
    /// * The `OAuth2` configuration is missing or invalid in the client configuration file.
    /// * The authorization URL cannot be parsed.
    /// * The authorization code is not received or does not match the CSRF token.
    /// * The access token cannot be requested from the Identity Provider.
    /// * The token exchange request fails.
    /// * The token exchange response cannot be parsed.
    /// * The client configuration cannot be updated or saved.
    #[allow(clippy::print_stdout)]
    pub async fn process(&self, config: &KmsClientConfig) -> CliResult<()> {
        let mut config = config.clone();
        let login_config = config.http_config.oauth2_conf.as_ref().ok_or_else(|| {
            CliError::Default(format!(
                "The `login` command (only used for JWT authentication) requires an Identity \
                 Provider (IdP) that MUST be configured in the oauth2_conf object in {:?}",
                config.conf_path
            ))
        })?;

        let state = LoginState::try_from(login_config.clone())?;
        println!("Browse to: {}", state.auth_url);
        let access_token = state.finalize().await?;

        // update the configuration and save it
        config.http_config.access_token = Some(access_token);
        let conf_path = config.conf_path.clone().ok_or_else(|| {
            CliError::Default("Configuration path `conf_path` must be filled".to_owned())
        })?;
        config.to_toml(&conf_path)?;

        println!(
            "\nSuccess! The access token was saved in the KMS configuration file: {:?}",
            config.conf_path
        );

        Ok(())
    }
}
