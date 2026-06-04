use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::error::result::KmsCliResult;

/// Set the automatic rotation policy for a symmetric key.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SetRotationPolicyAction {
    /// The unique identifier of the key to set the rotation policy on.
    #[clap(long = "key-id", short = 'k')]
    key_id: String,

    /// Rotation interval in seconds. The key will be automatically re-keyed at this interval.
    #[clap(long = "interval", short = 'i')]
    interval_secs: i64,

    /// Offset in seconds from the initial date before the first rotation occurs.
    #[clap(long = "offset", short = 'o')]
    offset_secs: Option<i64>,
}

impl SetRotationPolicyAction {
    #[allow(clippy::unused_async)]
    pub async fn run(&self, _kms_rest_client: KmsClient) -> KmsCliResult<()> {
        // TODO: implement KMIP Modify Attribute call to set rotation policy
        Ok(())
    }
}
