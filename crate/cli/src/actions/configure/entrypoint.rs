use clap::StructOpt;
use cosmian_kms_client::KmsRestClient;
use eyre::Context;

/// Query the KMS to initialize a new database
#[derive(StructOpt, Debug)]
pub struct ConfigureAction;

impl ConfigureAction {
    pub async fn process(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
        // Query the KMS to get a new database
        let token = client_connector
            .new_database()
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        println!(
            "New database configured. Use the following token (by adding it in your KMS_CLI_CONF) \
             for further uses: {token}"
        );

        println!(
            "You need to remember it. The KMS does not! If you loose it, your KMS database can't \
             be recovered"
        );

        Ok(())
    }
}
