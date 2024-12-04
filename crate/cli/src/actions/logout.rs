use clap::Parser;
use cosmian_config_utils::ConfigUtils;
use cosmian_kms_client::KmsClientConfig;

use crate::error::{result::CliResult, CliError};

/// Logout from the Identity Provider.
///
/// The access token will be removed from the ckms configuration file.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct LogoutAction;

impl LogoutAction {
    /// Process the logout action.
    ///
    /// # Arguments
    ///
    /// * `conf_path` - The path to the ckms configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error if there is an issue loading or saving the configuration file.
    ///
    #[allow(clippy::print_stdout)]
    pub fn process(&self, config: &KmsClientConfig) -> CliResult<()> {
        let mut config = config.clone();
        config.http_config.access_token = None;
        let conf_path = config.conf_path.clone().ok_or_else(|| {
            CliError::Default("Configuration path `conf_path` must be filled".to_owned())
        })?;
        config.to_toml(&conf_path)?;

        println!(
            "\nThe access token was removed from the KMS configuration file: {:?}",
            config.conf_path
        );

        Ok(())
    }
}
