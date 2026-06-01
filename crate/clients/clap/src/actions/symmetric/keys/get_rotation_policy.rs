use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::error::result::KmsCliResult;

/// Get the automatic rotation policy for a symmetric key.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct GetRotationPolicyAction {
    /// The unique identifier of the key to get the rotation policy from.
    #[clap(long = "key-id", short = 'k')]
    key_id: String,
}

impl GetRotationPolicyAction {
    #[allow(clippy::unused_async)]
    pub async fn run(&self, _kms_rest_client: KmsClient) -> KmsCliResult<()> {
        // TODO: implement KMIP Get Attributes call to retrieve rotation policy
        Ok(())
    }
}
