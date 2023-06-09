use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use crate::error::{result::CliResultHelper, CliError};

/// Initialize a new client-secret encrypted database and return the secret
///
/// This secret is only displayed once and is not stored anywhere on the server.
/// To use the encrypted database, the secret must be set in the `kms_database_secret`
/// property of the CLI `kms.json` configuration file.
///
/// Passing the correct secret "auto-selects" the correct encrypted database:
/// multiple encrypted databases can be used concurrently on the same KMS server.
///
/// Note: this action create a new database: it will not return the secret
/// of the last created database and will not overwrite it.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
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
