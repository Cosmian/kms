use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create::CreateOpaqueObjectAction, destroy::DestroyOpaqueObjectAction,
    revoke::RevokeOpaqueObjectAction,
};
use crate::{
    actions::kms::shared::{ExportSecretDataOrKeyAction, ImportSecretDataOrKeyAction},
    error::result::KmsCliResult,
};

pub mod create;
pub mod destroy;
pub mod revoke;

/// Create, import, export, revoke and destroy Opaque Objects
#[derive(Subcommand)]
pub enum OpaqueObjectCommands {
    Create(CreateOpaqueObjectAction),
    Export(ExportSecretDataOrKeyAction),
    Import(ImportSecretDataOrKeyAction),
    Revoke(RevokeOpaqueObjectAction),
    Destroy(DestroyOpaqueObjectAction),
}

impl OpaqueObjectCommands {
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
