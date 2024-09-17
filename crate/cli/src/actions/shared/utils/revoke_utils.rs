use cosmian_kms_client::{
    cosmian_kmip::{
        crypto::generic::kmip_requests::build_revoke_key_request,
        kmip::kmip_types::RevocationReason,
    },
    KmsClient,
};

use crate::{
    actions::console,
    cli_bail,
    error::result::{CliResult, CliResultHelper},
};

pub(crate) async fn revoke(
    kms_rest_client: &KmsClient,
    key_id: &str,
    revocation_reason: &str,
) -> CliResult<()> {
    // Create the kmip query
    let revoke_query = build_revoke_key_request(
        key_id,
        RevocationReason::TextString(revocation_reason.to_string()),
    )?;

    // Query the KMS with your kmip data
    let revoke_response = kms_rest_client
        .revoke(revoke_query)
        .await
        .with_context(|| format!("revocation of key {} failed", &key_id))?;

    if key_id
        == revoke_response
            .unique_identifier
            .as_str()
            .context("the server did not return a key id as a string")?
    {
        let mut stdout = console::Stdout::new("Successfully revoked the object.");
        stdout.set_unique_identifier(key_id);
        stdout.write()?;

        Ok(())
    } else {
        cli_bail!("Something went wrong when revoking the key.")
    }
}
