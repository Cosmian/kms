use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_secret::CreateKeyAction, destroy_secret::DestroyKeyAction,
    revoke_secret::RevokeKeyAction,
};
use crate::{
    actions::kms::shared::{ExportKeyAction, ImportKeyAction, UnwrapKeyAction, WrapKeyAction},
    error::result::KmsCliResult,
};

pub mod create_secret;
pub mod destroy_secret;
pub mod revoke_secret;

/// Create, destroy, import, and export symmetric keys
#[derive(Subcommand)]
pub enum SecretDataCommands {
    Create(CreateKeyAction),
    Export(ExportKeyAction),
    Import(ImportKeyAction),
    Wrap(WrapKeyAction),
    Unwrap(UnwrapKeyAction),
    Revoke(RevokeKeyAction),
    Destroy(DestroyKeyAction),
}

impl SecretDataCommands {
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
