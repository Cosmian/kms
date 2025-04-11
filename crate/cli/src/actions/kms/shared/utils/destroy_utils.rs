use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::{kmip_operations::Destroy, kmip_types::UniqueIdentifier},
};

use crate::{
    actions::console,
    cli_bail,
    error::result::{CosmianResult, CosmianResultHelper},
};

/// Destroy a cryptographic object on the KMS
/// # Arguments
/// * `kms_rest_client` - The KMS client
/// * `uid` - The object id
/// * `remove` - If the object should be removed from the database
/// # Returns
/// * `CosmianResult<()>` - The result of the operation
pub(crate) async fn destroy(
    kms_rest_client: &KmsClient,
    uid: &str,
    remove: bool,
) -> CosmianResult<()> {
    // Create the kmip query
    let destroy_query = Destroy {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_string())),
        remove,
    };

    // Query the KMS with your kmip data
    let destroy_response = kms_rest_client
        .destroy(destroy_query)
        .await
        .with_context(|| format!("destroying the object {} failed", &uid))?;

    if uid
        == destroy_response
            .unique_identifier
            .as_str()
            .context("The server did not return the object uid as a string")?
    {
        let verb = if remove { "removed" } else { "destroyed" };
        let mut stdout = console::Stdout::new(format!("Successfully {verb} the object.").as_str());
        stdout.set_unique_identifier(uid);
        stdout.write()?;
        Ok(())
    } else {
        cli_bail!("Something went wrong when destroying the object.")
    }
}
