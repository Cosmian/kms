use clap::Parser;
use cosmian_kms_client::KmsClient;

use self::{identities::IdentitiesCommands, keypairs::KeyPairsCommands};
use crate::error::result::KmsCliResult;

mod gmail_client;
mod identities;
mod keypairs;
pub use gmail_client::GoogleApiError;

/// Manage google elements. Handle key pairs and identities from Gmail API.
#[derive(Parser)]
pub enum GoogleCommands {
    #[command(subcommand)]
    KeyPairs(KeyPairsCommands),
    #[command(subcommand)]
    Identities(IdentitiesCommands),
}

impl GoogleCommands {
    /// Process the Google command by delegating the execution to the appropriate subcommand.
    ///
    /// # Arguments
    ///
    /// * `conf_path` - The path to the configuration file.
    ///
    /// # Errors
    ///
    /// Returns a `KmsCliResult` indicating the success or failure of the command.
    ///
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::KeyPairs(command) => command.process(kms_rest_client).await?,
            Self::Identities(command) => command.process(kms_rest_client.config).await?,
        }
        Ok(())
    }
}
