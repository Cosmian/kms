use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::error::{result::CliResultHelper, CliError};

/// Print the version of the server
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ServerVersionAction;

impl ServerVersionAction {
    pub async fn process(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
        let version = kms_rest_client
            .version()
            .await
            .with_context(|| "Can't execute the version query on the kms server")?;

        println!("{version}");

        Ok(())
    }
}
