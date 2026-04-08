use clap::Parser;
use cosmian_kms_client::{KmsClient, kmip_2_1::kmip_types::UniqueIdentifier};

use crate::{
    actions::{
        labels::KEY_ID,
        shared::{get_key_uid, utils::revoke},
    },
    error::result::KmsCliResult,
};

/// Revoke a PQC public or private key.
#[derive(Parser, Debug)]
pub struct RevokeKeyAction {
    /// The reason for the revocation
    #[clap(required = true)]
    revocation_reason: String,

    /// The key unique identifier of the key to revoke
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}

impl RevokeKeyAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;
        revoke(kms_rest_client, &id, &self.revocation_reason).await
    }
}
