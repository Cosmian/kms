use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_key_pair::CreateKeyPairAction, destroy_key::DestroyKeyAction,
    revoke_key::RevokeKeyAction,
};
use crate::{
    actions::shared::{ExportKeyAction, ImportKeyAction, UnwrapKeyAction, WrapKeyAction},
    error::result::CliResult,
};

mod create_key_pair;
mod destroy_key;
mod revoke_key;

/// Create, destroy, import, and export elliptic curve key pairs
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
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        match self {
            Self::Create(action) => action.run(kms_rest_client).await?,
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
