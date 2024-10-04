use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_key::CreateKeyAction, destroy_key::DestroyKeyAction, rekey::ReKeyAction,
    revoke_key::RevokeKeyAction,
};
use crate::{
    actions::shared::{ExportKeyAction, ImportKeyAction, UnwrapKeyAction, WrapKeyAction},
    error::result::CliResult,
};

mod create_key;
mod destroy_key;
mod rekey;
mod revoke_key;

/// Create, destroy, import, and export symmetric keys
#[derive(Subcommand)]
pub enum KeysCommands {
    Create(CreateKeyAction),
    ReKey(ReKeyAction),
    Export(ExportKeyAction),
    Import(ImportKeyAction),
    Wrap(WrapKeyAction),
    Unwrap(UnwrapKeyAction),
    Revoke(RevokeKeyAction),
    Destroy(DestroyKeyAction),
}

impl KeysCommands {
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        match self {
            Self::Create(action) => action.run(kms_rest_client).await?,
            Self::ReKey(action) => action.run(kms_rest_client).await?,
            Self::Export(action) => action.run(kms_rest_client).await?,
            Self::Import(action) => action.run(kms_rest_client).await?,
            Self::Wrap(action) => action.run(kms_rest_client).await?,
            Self::Unwrap(action) => action.run(kms_rest_client).await?,
            Self::Revoke(action) => action.run(kms_rest_client).await?,
            Self::Destroy(action) => action.run(kms_rest_client).await?,
        };

        Ok(())
    }
}
