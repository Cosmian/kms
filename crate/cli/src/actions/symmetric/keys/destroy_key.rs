use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use crate::{actions::shared::utils::destroy, error::CliError};

/// Destroy a symmetric key.
///
/// The key must have been revoked first.
///
/// When a key is destroyed, it can only be exported by the owner of the key,
/// and without its key material
#[derive(Parser, Debug)]
pub struct DestroyKeyAction {
    /// The unique identifier of the key to destroy
    #[clap(required = true)]
    key_id: String,
}

impl DestroyKeyAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        destroy(client_connector, &self.key_id).await
    }
}
