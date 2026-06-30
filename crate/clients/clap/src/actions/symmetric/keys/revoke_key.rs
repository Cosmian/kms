use clap::Parser;
use cosmian_kms_client::{KmsClient, kmip_2_1::kmip_types::UniqueIdentifier};

use crate::{
    actions::{
        labels::KEY_ID,
        shared::{RevokeReasonArgs, get_key_uid, utils::revoke},
    },
    error::result::KmsCliResult,
};

/// Revoke a symmetric key.
///
/// When a key is revoked, it can only be exported by the owner of the key,
/// using the --allow-revoked flag on the export function.
#[derive(Parser, Debug)]
pub struct RevokeKeyAction {
    /// Revocation reason and code.
    #[clap(flatten)]
    pub(crate) reason: RevokeReasonArgs,

    /// The key unique identifier of the key to revoke.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,
}

impl RevokeKeyAction {
    pub(crate) async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;
        revoke(
            kms_rest_client,
            &id,
            &self.reason.revocation_reason,
            self.reason.reason_code,
        )
        .await
    }
}
