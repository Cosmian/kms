use clap::Parser;
use cosmian_kms_client::{KmsClient, kmip_2_1::kmip_types::UniqueIdentifier};

use crate::{
    actions::kms::{
        labels::KEY_ID,
        shared::{get_key_uid, utils::destroy},
    },
    error::result::KmsCliResult,
};

/// Destroy an `OpaqueObject`.
///
/// The object must have been revoked first unless server policy allows otherwise.
#[derive(Parser, Debug)]
pub struct DestroyOpaqueObjectAction {
    /// The opaque object unique identifier. If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) object_id: Option<String>,

    /// Tags to locate the object if id is not provided. Repeat to specify multiple tags.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// If the object should be removed from the database. If not specified, the object will be destroyed
    /// but its metadata will still be available.
    #[clap(long = "remove", default_value = "false", verbatim_doc_comment)]
    pub(crate) remove: bool,
}

impl DestroyOpaqueObjectAction {
    pub(crate) async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let id = get_key_uid(self.object_id.as_ref(), self.tags.as_ref(), KEY_ID)?;
        destroy(kms_rest_client, &id, self.remove).await
    }
}
