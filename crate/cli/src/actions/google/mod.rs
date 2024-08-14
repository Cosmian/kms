use std::path::PathBuf;

use clap::Parser;

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
    pub async fn process(&self, conf_path: &PathBuf) -> CliResult<()> {
        match self {
            Self::Keypairs(command) => command.process(conf_path).await?,
            Self::Identities(command) => command.process(conf_path).await?,
        };
        Ok(())
    }
}
