use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::error::{result::CliResultHelper, CliError};

/// Initialize a new user encrypted database and return the secret (`SQLCipher` only).
///
/// This secret is only displayed once and is not stored anywhere on the server.
/// The secret must be set in the `kms_database_secret` property
/// of the CLI `kms.json` configuration file to use the encrypted database.
///
/// Passing the correct secret "auto-selects" the correct encrypted database:
/// multiple encrypted databases can be used concurrently on the same KMS server.
///
/// Note: this action creates a new database: it will not return the secret
/// of the last created database and will not overwrite it.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct NewDatabaseAction;

impl NewDatabaseAction {
    pub async fn process(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
        // Query the KMS to get a new database
        let token = kms_rest_client
            .new_database()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!(
            "A new user encrypted database is configured. Use the following token (by adding it \
             to the 'kms_database_secret' entry of your KMS_CLI_CONF):\n\n{token}\n\n"
        );

        println!(
            "Do not loose it: there is not other copy!\nIt is impossible to recover the database \
             without the token."
        );

        Ok(())
    }
}
