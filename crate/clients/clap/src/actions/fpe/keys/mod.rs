use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_key::CreateKeyAction, destroy_key::DestroyKeyAction, revoke_key::RevokeKeyAction,
};
use crate::{
    actions::shared::{
        ExportSecretDataOrKeyAction, ImportSecretDataOrKeyAction, UnwrapSecretDataOrKeyAction,
        WrapSecretDataOrKeyAction,
    },
    error::result::KmsCliResult,
};

pub mod create_key;
pub mod destroy_key;
pub mod revoke_key;

/// Create, destroy, import, and export FPE keys
#[derive(Subcommand)]
pub enum KeysCommands {
    Create(CreateKeyAction),
    Export(ExportSecretDataOrKeyAction),
    Import(ImportSecretDataOrKeyAction),
    Wrap(WrapSecretDataOrKeyAction),
    Unwrap(UnwrapSecretDataOrKeyAction),
    Revoke(RevokeKeyAction),
    Destroy(DestroyKeyAction),
}

impl KeysCommands {
    pub(crate) async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
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
                Box::pin(action.run(kms_rest_client)).await?;
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
