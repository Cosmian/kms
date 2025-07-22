use clap::Parser;
use cosmian_kms_client::{KmsClient, kmip_2_1::kmip_types::UniqueIdentifier};

use crate::{
    actions::kms::{
        labels::SECRET_DATA_ID,
        shared::{get_key_uid, utils::revoke},
    },
    error::result::KmsCliResult,
};

/// Revoke a secret data.
///
/// When a secret data is revoked, it can only be exported by the owner of the secret data.
/// using the --allow-revoked flag on the export function.
#[derive(Parser, Default, Debug)]
pub struct RevokeSecretDataAction {
    /// The reason for the revocation as a string
    #[clap(required = true)]
    pub(crate) revocation_reason: String,

    /// The secret unique identifier of the secret to revoke.
    /// If not specified, tags should be specified
    #[clap(long = SECRET_DATA_ID, short = 's', group = "key-tags")]
    pub(crate) secret_id: Option<String>,

    /// Tag to use to retrieve the secret data when no secret data id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,
}

impl RevokeSecretDataAction {
    pub(crate) async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let id = get_key_uid(self.secret_id.as_ref(), self.tags.as_ref(), SECRET_DATA_ID)?;
        revoke(kms_rest_client, &id, &self.revocation_reason).await
    }
}
