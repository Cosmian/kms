use cosmian_kms_client::{
    cosmian_kmip::kmip::{kmip_operations::Destroy, kmip_types::UniqueIdentifier},
    KmsClient,
};

use crate::{
    actions::console,
    cli_bail,
    error::result::{CliResult, CliResultHelper},
};

pub(crate) async fn destroy(kms_rest_client: &KmsClient, key_id: &str) -> CliResult<()> {
    // Create the kmip query
    let destroy_query = Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(key_id.to_string())),
    };

    // Query the KMS with your kmip data
    let destroy_response = kms_rest_client
        .destroy(destroy_query)
        .await
        .with_context(|| format!("destroying the key {} failed", &key_id))?;

    if key_id
        == destroy_response
            .unique_identifier
            .as_str()
            .context("The server did not return the key uid as a string")?
    {
        let mut stdout = console::Stdout::new("Successfully destroyed the key.");
        stdout.set_unique_identifier(key_id);
        stdout.write()?;

        Ok(())
    } else {
        cli_bail!("Something went wrong when destroying the key.")
    }
}
