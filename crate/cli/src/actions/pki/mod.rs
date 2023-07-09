mod certificates;

use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use crate::error::CliError;

/// Manage certificates.
#[derive(Parser)]
pub enum CertificatesCommands {
    #[command(subcommand)]
    Certificates(certificates::CertificatesCommands),
}

impl CertificatesCommands {
    pub async fn process(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        match self {
            Self::Certificates(command) => command.process(client_connector).await?,
        };
        Ok(())
    }
}
