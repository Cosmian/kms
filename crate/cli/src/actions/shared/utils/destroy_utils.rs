use cosmian_kmip::kmip::kmip_operations::Destroy;
use cosmian_kms_client::KmsRestClient;

use crate::{
    cli_bail,
    error::{result::CliResultHelper, CliError},
};

pub async fn destroy(kms_rest_client: &KmsRestClient, key_id: &str) -> Result<(), CliError> {
    // Create the kmip query
    let destroy_query = Destroy {
        unique_identifier: Some(key_id.to_string()),
    };

    // Query the KMS with your kmip data
    let destroy_response = kms_rest_client
        .destroy(destroy_query)
        .await
        .with_context(|| format!("destroying the key {} failed", &key_id))?;

    if key_id == destroy_response.unique_identifier {
        println!("Successfully destroyed the key: {}.", &key_id);
        Ok(())
    } else {
        cli_bail!("Something went wrong when destroying the key.")
    }
}
