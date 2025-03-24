use clap::Parser;
use cosmian_findex_client::RestClientConfig;
use tracing::info;

use crate::error::result::CosmianResult;

/// Logout from the Identity Provider.
///
/// The access token will be removed from the findex configuration file.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct LogoutAction;

impl LogoutAction {
    /// Process the logout action.
    ///
    /// # Errors
    ///
    /// Returns an error if there is an issue loading or saving the
    /// configuration file.
    pub fn run(&self, mut config: RestClientConfig) -> CosmianResult<RestClientConfig> {
        config.http_config.access_token = None;
        info!("Deleting access token from the configuration...",);
        Ok(config)
    }
}
