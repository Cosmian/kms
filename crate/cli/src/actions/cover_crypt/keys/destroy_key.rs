use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{actions::shared::utils::destroy, cli_bail, error::result::CliResult};

/// Destroy a Covercrypt master or user decryption key.
///
/// The key must have been revoked first.
///
/// When a key is destroyed, it can only be exported by the owner of the key,
/// and without its key material
///
/// Destroying a master public or private key will destroy the whole key pair
/// and all the associated decryption keys present in the KMS.
///
/// When using tags to revoke the key, rather than the key id,
/// an error is returned if multiple keys matching the tags are found.
#[derive(Parser, Debug)]
pub struct DestroyKeyAction {
    /// The key unique identifier.
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}

impl DestroyKeyAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let id = if let Some(key_id) = &self.key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --key-id or one or more --tag must be specified")
        };

        destroy(kms_rest_client, &id).await
    }
}
