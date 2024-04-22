use std::path::PathBuf;

use clap::Parser;
// use cosmian_kms_client::KmsClient;

use self::{keypairs::KeypairsCommands};
use crate::error::CliError;

mod keypairs;

/// Manage google elements. Handle keypairs and identities from Gmail API.
#[derive(Parser)]
pub enum GoogleCommands {
    #[command(subcommand)]
    Keypairs(KeypairsCommands),
}

impl GoogleCommands {
    pub async fn process(&self, conf_path: &PathBuf) -> Result<(), CliError> {
        match self {
            Self::Keypairs(command) => command.process(conf_path).await?,
        };
        Ok(())
    }
}
