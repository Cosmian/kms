use clap::Parser;
use cosmian_kms_client::KmsClientConfig;

use crate::error::result::CliResult;

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
    pub fn process(&self, config: &mut KmsClientConfig) -> CliResult<()> {
        config.http_config.access_token = None;
        println!("\nThe access token was removed from the KMS configuration file",);

        Ok(())
    }
}
