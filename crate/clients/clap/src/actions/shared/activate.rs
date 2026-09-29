use clap::Parser;
use cosmian_kms_client::{KmsClient, kmip_2_1::kmip_types::UniqueIdentifier};

use super::utils::activate;
use crate::{
    actions::{labels::KEY_ID, shared::get_key_uid},
    error::result::KmsCliResult,
};

/// Activate a cryptographic object (key, certificate, etc.).
///
/// Transitions the object from `Pre-Active` to `Active` state,
/// making it available for cryptographic operations.
#[derive(Parser, Default, Debug)]
pub struct ActivateKeyAction {
    /// The key unique identifier of the key to activate.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,
}

impl ActivateKeyAction {
    pub(crate) async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;
        activate(kms_rest_client, &id).await
    }
}
