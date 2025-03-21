use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::{
        labels::KEY_ID,
        shared::{get_key_uid, utils::revoke},
    },
    error::result::CliResult,
};

/// Revoke a public or private key.
///
/// Once a key is revoked, it can only be exported by the owner of the key,
/// using the --allow-revoked flag on the export function.
///
/// Revoking a public or private key will revoke the whole key pair
/// (the two keys need to be stored in the KMS).
#[derive(Parser, Debug)]
pub struct RevokeKeyAction {
    /// The reason for the revocation as a string
    #[clap(required = true)]
    pub(crate) revocation_reason: String,

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
    /// Runs the key revocation process.
    ///
    /// This function performs the following steps:
    /// 1. Recovers the unique identifier or set of tags for the key.
    /// 2. Calls the `revoke` utility function to revoke the key.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client.
    ///
    /// # Returns
    ///
    /// * `CliResult<()>` - The result of the revocation process.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * Neither `--key-id` nor `--tag` is specified.
    /// * The revocation request fails.
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;
        revoke(kms_rest_client, &id, &self.revocation_reason).await
    }
}
