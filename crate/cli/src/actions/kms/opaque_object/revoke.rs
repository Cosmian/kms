use clap::Parser;
use cosmian_kms_client::{KmsClient, kmip_2_1::kmip_types::UniqueIdentifier};

use crate::{
    actions::kms::{
        labels::KEY_ID,
        shared::{get_key_uid, utils::revoke},
    },
    error::result::KmsCliResult,
};

/// Revoke an `OpaqueObject`.
///
/// Once revoked, the object can typically only be exported by the owner when explicitly allowed.
#[derive(Parser, Default, Debug)]
pub struct RevokeOpaqueObjectAction {
    /// The reason for the revocation as a string
    #[clap(required = true)]
    pub(crate) revocation_reason: String,

    /// The opaque object unique identifier to revoke. If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) object_id: Option<String>,

    /// Tags to locate the object if id is not provided. Repeat to specify multiple tags.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,
}

impl RevokeOpaqueObjectAction {
    pub(crate) async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let id = get_key_uid(self.object_id.as_ref(), self.tags.as_ref(), KEY_ID)?;
        revoke(kms_rest_client, &id, &self.revocation_reason).await
    }
}
