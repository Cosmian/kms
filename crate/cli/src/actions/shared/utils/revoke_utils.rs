use cosmian_kmip::kmip::kmip_types::RevocationReason;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::generic::kmip_requests::build_revoke_key_request;

use crate::{
    cli_bail,
    error::{result::CliResultHelper, CliError},
};

pub async fn revoke(
    kms_rest_client: &KmsRestClient,
    key_id: &str,
    revocation_reason: &str,
) -> Result<(), CliError> {
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

    if key_id == revoke_response.unique_identifier {
        println!("Successfully revoked the key: {}.", &key_id);
        Ok(())
    } else {
        cli_bail!("Something went wrong when revoking the key.")
    }
}
