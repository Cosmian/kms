use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_objects::ObjectType, kmip_operations::GetAttributes, kmip_types::UniqueIdentifier,
    },
};

use crate::{
    actions::{
        labels::KEY_ID,
        shared::{get_key_uid, utils::destroy},
    },
    error::{KmsCliError, result::KmsCliResult},
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
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        // Pre-flight: verify the object type matches this subcommand.
        let attr = kms_rest_client
            .get_attributes(GetAttributes {
                unique_identifier: Some(UniqueIdentifier::TextString(id.clone())),
                attribute_reference: None,
            })
            .await?;
        if !matches!(attr.attributes.object_type, Some(ObjectType::PGPKey)) {
            return Err(KmsCliError::NotSupported(format!(
                "Object '{id}' is of type {:?}, not PGPKey. \
                 Use the correct 'ckms ... keys destroy' subcommand for this key type.",
                attr.attributes.object_type
            )));
        }

        destroy(
            kms_rest_client,
            &id,
            self.remove,
            attr.attributes.object_type,
        )
        .await
    }
}
