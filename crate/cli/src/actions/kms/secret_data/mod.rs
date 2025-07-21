use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_secret::CreateSecretDataAction, destroy_secret::DestroySecretDataAction,
    revoke_secret::RevokeSecretDataAction,
};
use crate::{
    actions::kms::shared::{
        ExportSecretDataOrKeyAction, ImportSecretDataOrKeyAction, UnwrapSecretDataOrKeyAction,
        WrapSecretDataOrKeyAction,
    },
    error::result::KmsCliResult,
};

pub mod create_secret;
pub mod destroy_secret;
pub mod revoke_secret;

/// Create, import, export and destroy secret data
#[derive(Subcommand)]
pub enum SecretDataCommands {
    Create(CreateSecretDataAction),
    Export(ExportSecretDataOrKeyAction),
    Import(ImportSecretDataOrKeyAction),
    Wrap(WrapSecretDataOrKeyAction),
    Unwrap(UnwrapSecretDataOrKeyAction),
    Revoke(RevokeSecretDataAction),
    Destroy(DestroySecretDataAction),
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
