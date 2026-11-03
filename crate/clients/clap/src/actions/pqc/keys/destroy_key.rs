use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{kmip_objects::ObjectType, kmip_types::UniqueIdentifier},
};

use crate::{
    actions::{labels::KEY_ID, shared::utils::destroy_key},
    error::result::KmsCliResult,
};

/// Destroy a PQC public or private key.
///
/// The key must have been revoked first.
#[derive(Parser, Debug)]
pub struct DestroyKeyAction {
    /// The key unique identifier of the key to destroy
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// Remove the key from the database entirely
    #[clap(long = "remove", default_value = "false")]
    pub(crate) remove: bool,
}

impl DestroyKeyAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        destroy_key(
            kms_rest_client,
            self.key_id.as_ref(),
            self.tags.as_ref(),
            self.remove,
            &[ObjectType::PrivateKey, ObjectType::PublicKey],
            "a PrivateKey or PublicKey",
        )
        .await
    }
}
