mod byok;

use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{actions::kms::azure::byok::ByokCommands, error::result::KmsCliResult};

/// Manage Azure specific elements.
#[derive(Parser)]
pub enum AzureCommands {
    #[command(subcommand)]
    Byok(ByokCommands),
}

impl AzureCommands {
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Byok(command) => command.process(kms_rest_client).await?,
        }
        Ok(())
    }
}
