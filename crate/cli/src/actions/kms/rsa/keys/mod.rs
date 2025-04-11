use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_key_pair::CreateKeyPairAction, destroy_key::DestroyKeyAction,
    revoke_key::RevokeKeyAction,
};
use crate::{
    actions::kms::shared::{ExportKeyAction, ImportKeyAction, UnwrapKeyAction, WrapKeyAction},
    error::result::CosmianResult,
};

pub mod create_key_pair;
pub mod destroy_key;
pub mod revoke_key;

/// Create, destroy, import, and export RSA key pairs
#[derive(Subcommand)]
pub enum KeysCommands {
    Create(CreateKeyPairAction),
    Export(ExportKeyAction),
    Import(ImportKeyAction),
    Wrap(WrapKeyAction),
    Unwrap(UnwrapKeyAction),
    Revoke(RevokeKeyAction),
    Destroy(DestroyKeyAction),
}

impl KeysCommands {
    /// Process the key command
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client used to perform the key operations.
    ///
    /// # Results
    ///
    /// This function returns a `CosmianResult<()>` indicating the success or failure of the key command processing.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The specific key action fails.
    /// * The KMS server query fails.
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CosmianResult<()> {
        match self {
            Self::Create(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Export(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Import(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Wrap(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Unwrap(action) => {
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
