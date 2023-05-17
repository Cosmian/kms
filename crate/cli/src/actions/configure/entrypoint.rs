use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use crate::error::{result::CliResultHelper, CliError};

/// Initialize a new database on the KMS [enclave mode only]
#[derive(Parser, Debug)]
pub struct NewDatabaseAction;

impl NewDatabaseAction {
    pub async fn process(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        // Query the KMS to get a new database
        let token = client_connector
            .new_database()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!(
            "A new encrypted database is configured. Use the following token (by adding it to the \
             'kms_database_secret' entry of your KMS_CLI_CONF):\n\n{token}\n\n"
        );

        println!(
            "Do not loose it: there is not other copy!\nIt is impossible to recover the database \
             without the token."
        );

        Ok(())
    }
}
