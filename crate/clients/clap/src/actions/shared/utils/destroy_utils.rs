use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::{
        kmip_objects::ObjectType, kmip_operations::Destroy, kmip_types::UniqueIdentifier,
    },
};

use crate::{
    actions::console,
    cli_bail,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Destroy a cryptographic object on the KMS
/// # Arguments
/// * `kms_rest_client` - The KMS client
/// * `uid` - The object id
/// * `remove` - If the object should be removed from the database
/// * `expected_object_type` - For HSM keys, the expected key type to guard against
///   accidental cross-type destroys (issue #763). Passed straight through to the
///   server which verifies via a PKCS#11 `get_key_type` roundtrip.
/// # Returns
/// * `KmsCliResult<()>` - The result of the operation
pub(crate) async fn destroy(
    kms_rest_client: KmsClient,
    uid: &str,
    remove: bool,
    expected_object_type: Option<ObjectType>,
) -> KmsCliResult<UniqueIdentifier> {
    // Create the kmip query
    let uid = UniqueIdentifier::TextString(uid.to_owned());
    let destroy_query = Destroy {
        unique_identifier: Some(uid.clone()),
        remove,
        // Cosmian extension: request cascade by default from the CLI helper so
        // destroying a public/private key cascades to its pair unless the server is
        // configured otherwise.
        cascade: true,
        expected_object_type,
    };

    // Query the KMS with your kmip data
    let destroy_response = kms_rest_client
        .destroy(destroy_query)
        .await
        .with_context(|| format!("destroying the object {} failed", &uid))?;

    if uid == destroy_response.unique_identifier {
        let verb = if remove { "removed" } else { "destroyed" };
        let mut stdout = console::Stdout::new(format!("Successfully {verb} the object.").as_str());
        stdout.set_unique_identifier(&uid);
        stdout.write()?;
        Ok(uid)
    } else {
        cli_bail!("Something went wrong when destroying the object.")
    }
}
