use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{create_key::CreatePgpKeyAction, destroy_key::DestroyPgpKeyAction};
use crate::{
    actions::shared::{RevokeKeyAction, dispatch_run},
    error::result::KmsCliResult,
};

pub mod create_key;
pub mod destroy_key;

/// Create, revoke, and destroy `OpenPGP` keys.
#[derive(Subcommand)]
pub enum KeysCommands {
    Create(CreatePgpKeyAction),
    /// Revoke an `OpenPGP` key.
    ///
    /// Once a key is revoked, it can only be exported by the owner of the key,
    /// using the --allow-revoked flag on the export function.
    Revoke(RevokeKeyAction),
    Destroy(DestroyPgpKeyAction),
}

impl KeysCommands {
    /// Process the `OpenPGP` key command.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client.
    ///
    /// # Errors
    ///
    /// Returns an error if the specific key action fails.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        dispatch_run!(self, kms_rest_client, [Create, Revoke, Destroy]);
        Ok(())
    }
}
