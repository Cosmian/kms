use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{kmip_objects::ObjectType, kmip_types::UniqueIdentifier},
};

use crate::{
    actions::{labels::KEY_ID, shared::utils::destroy_key},
    error::result::KmsCliResult,
};

/// Destroy an `OpenPGP` key.
///
/// The key must have been revoked first.
///
/// When a key is destroyed but not removed,
/// it can only be exported by the owner of the key,
/// and without its key material.
#[derive(Parser, Debug)]
pub struct DestroyPgpKeyAction {
    /// The key unique identifier of the key to destroy
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// If the key should be removed from the database
    /// If not specified, the key will be destroyed
    /// but its metadata will still be available in the database.
    #[clap(long = "remove", default_value = "false", verbatim_doc_comment)]
    pub(crate) remove: bool,
}

impl DestroyPgpKeyAction {
    /// Run the destroy `OpenPGP` key action.
    ///
    /// # Errors
    ///
    /// Returns an error if key UID resolution or destruction fails.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        destroy_key(
            kms_rest_client,
            self.key_id.as_ref(),
            self.tags.as_ref(),
            self.remove,
            &[ObjectType::PGPKey],
            "PGPKey",
        )
        .await
    }
}
