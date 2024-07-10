use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::KmsClient;

use self::{identities::IdentitiesCommands, keypairs::KeypairsCommands};
use crate::error::result::CliResult;

mod gmail_client;
mod identities;
mod keypairs;
pub(crate) use gmail_client::GoogleApiError;

/// Manage google elements. Handle keypairs and identities from Gmail API.
#[derive(Parser)]
pub enum GoogleCommands {
    #[command(subcommand)]
    Keypairs(KeypairsCommands),
    #[command(subcommand)]
    Identities(IdentitiesCommands),
}

impl GoogleCommands {
    pub async fn process(&self, conf_path: &PathBuf, kms_rest_client: &KmsClient) -> CliResult<()> {
        match self {
            Self::Keypairs(command) => command.process(conf_path, kms_rest_client).await?,
            Self::Identities(command) => command.process(conf_path).await?,
        };
        Ok(())
    }
}
