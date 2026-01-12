mod byok;

use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{actions::kms::aws::byok::ByokCommands, error::result::KmsCliResult};

/// Support for AWS specific interactions.
#[derive(Parser)]
pub enum AwsCommands {
    #[command(subcommand)]
    Byok(ByokCommands),
}

impl AwsCommands {
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Byok(command) => command.process(kms_rest_client).await?,
        }
        Ok(())
    }
}
