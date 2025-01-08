use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{actions::shared::utils::destroy, cli_bail, error::result::CliResult};

/// Destroy a public or private key.
///
/// The key must have been revoked first.
///
/// Keys belonging to external stores, such as HSMs,
/// are automatically removed.
///
/// When a key is destroyed but not removed,
/// it can only be exported by the owner of the key,
/// and without its key material
///
/// Destroying a public or private key will destroy the whole key pair
/// when the two keys are stored in the KMS.
#[derive(Parser, Debug)]
pub struct DestroyKeyAction {
    /// The key unique identifier of the key to destroy
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,

    /// If the key should be removed from the database
    /// If not specified, the key will be destroyed
    /// but its metadata will still be available in the database.
    /// Please note that the KMIP specification does not support the removal of objects.
    #[clap(long = "remove", default_value = "false", verbatim_doc_comment)]
    remove: bool,
}

impl DestroyKeyAction {
    /// Run the destroy key action
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client used to perform the key destruction.
    ///
    /// # Results
    ///
    /// This function returns a `CliResult<()>` indicating the success or failure of the key destruction action.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * Neither `key_id` nor `tags` are specified.
    /// * The key destruction request fails.
    /// * The KMS server query fails.
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let id = if let Some(key_id) = &self.key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --key-id or one or more --tag must be specified")
        };

        destroy(kms_rest_client, &id, self.remove).await
    }
}
