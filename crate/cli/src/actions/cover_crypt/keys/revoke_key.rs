use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use crate::{actions::shared::utils::revoke, error::CliError};

/// Revoke a Covercrypt master or user decryption key.
///
/// Once a key is revoked, it can only be exported by the owner of the key,
/// using the --allow-revoked flag on the export function.
///
/// Revoking a master public or private key will revoke the whole key pair
/// and all the associated user decryption keys present in the KMS.
///
/// Once a user decryption key is revoked, it will no longer be rekeyed
/// when attributes are rotated on the master key.
///
#[derive(Parser, Debug)]
pub struct RevokeKeyAction {
    /// The unique identifier of the key to revoke
    #[clap(required = true)]
    key_id: String,

    /// The reason for the revocation as a string
    #[clap(required = true)]
    revocation_reason: String,
}

impl RevokeKeyAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        revoke(client_connector, &self.key_id, &self.revocation_reason).await
    }
}
