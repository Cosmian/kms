use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::error::result::{CliResult, CliResultHelper};

/// Initialize a new user encrypted database and return the secret (`SQLCipher` only).
///
/// This secret is only displayed once and is not stored anywhere on the server.
/// The secret must be set in the `database_secret` property
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
    /// Process the `NewDatabaseAction` by querying the KMS to get a new database.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - The KMS client used to communicate with the KMS server.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the KMS server fails.
    ///
    #[allow(clippy::print_stdout)]
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        // Query the KMS to get a new database
        let token = kms_rest_client
            .new_database()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!(
            "A new user encrypted database is configured. Use the following token (by adding it \
             to the 'database_secret' entry of your KMS_CLI_CONF):\n\n{token}\n\n"
        );

        println!(
            "Do not loose it: there is not other copy!\nIt is impossible to recover the database \
             without the token."
        );

        Ok(())
    }
}
