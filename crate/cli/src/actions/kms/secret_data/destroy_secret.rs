use clap::Parser;
use cosmian_kms_client::{KmsClient, kmip_2_1::kmip_types::UniqueIdentifier};

use crate::{
    actions::kms::{
        labels::KEY_ID,
        shared::{get_key_uid, utils::destroy},
    },
    error::result::KmsCliResult,
};

/// Destroy a secret data
///
/// The secret must have been revoked first.
///
/// Secrets belonging to external stores, such as HSMs,
/// are automatically removed.
///
/// When a secret is destroyed but not removed in the KMS,
/// it can only be exported by the owner,
/// and without its key material
#[derive(Parser, Debug)]
pub struct DestroySecretDataAction {
    /// The secret unique identifier.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 's', group = "key-tags")]
    pub(crate) secret_id: Option<String>,

    /// Tag to use to retrieve the secret when no secret id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// If the secret should be removed from the database
    /// If not specified, the key will be destroyed
    /// but its metadata will still be available in the database.
    /// Please note that the KMIP specification does not support the removal of objects.
    #[clap(long = "remove", default_value = "false", verbatim_doc_comment)]
    pub(crate) remove: bool,
}

impl DestroySecretDataAction {
    pub(crate) async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let id = get_key_uid(self.secret_id.as_ref(), self.tags.as_ref(), KEY_ID)?;
        destroy(kms_rest_client, &id, self.remove).await
    }
}
