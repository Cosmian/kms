use clap::Parser;
use cosmian_kms_client::KmsClient;

use super::console;
use crate::error::result::{CliResult, CliResultHelper};

/// Print the version of the server
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ServerVersionAction;

impl ServerVersionAction {
    /// Process the server version action.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - The KMS client instance used to communicate with the KMS server.
    ///
    /// # Errors
    ///
    /// Returns an error if the version query fails or if there is an issue writing to the console.
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let version = kms_rest_client
            .version()
            .await
            .with_context(|| "Can't execute the version query on the kms server")?;

        console::Stdout::new(&version).write()?;

        Ok(())
    }
}
