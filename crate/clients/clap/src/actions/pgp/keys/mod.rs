use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_key::CreatePgpKeyAction, destroy_key::DestroyPgpKeyAction,
    revoke_key::RevokePgpKeyAction,
};
use crate::error::result::KmsCliResult;

pub mod create_key;
pub mod destroy_key;
pub mod revoke_key;

/// Create, revoke, and destroy `OpenPGP` keys.
#[derive(Subcommand)]
pub enum KeysCommands {
    Create(CreatePgpKeyAction),
    Revoke(RevokePgpKeyAction),
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
        match self {
            Self::Create(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Revoke(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Destroy(action) => {
                action.run(kms_rest_client).await?;
            }
        }
        Ok(())
    }
}
