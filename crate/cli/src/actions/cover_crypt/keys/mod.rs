use clap::Subcommand;
use cosmian_kms_client::KmsRestClient;

use self::{
    create_key_pair::CreateMasterKeyPairAction, create_user_key::CreateUserKeyAction,
    destroy_key::DestroyKeyAction, revoke_key::RevokeKeyAction,
};
use crate::{
    actions::shared::{ExportKeyAction, ImportKeyAction, UnwrapKeyAction, WrapKeyAction},
    error::CliError,
};

mod create_key_pair;
mod create_user_key;
mod destroy_key;
mod revoke_key;

/// Create, destroy, import, export `CoverCrypt` master and user keys
#[derive(Subcommand)]
pub enum KeysCommands {
    CreateMasterKeyPair(CreateMasterKeyPairAction),
    CreateUserKey(CreateUserKeyAction),
    Export(ExportKeyAction),
    Import(ImportKeyAction),
    Wrap(WrapKeyAction),
    Unwrap(UnwrapKeyAction),
    Revoke(RevokeKeyAction),
    Destroy(DestroyKeyAction),
}

impl KeysCommands {
    pub async fn process(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        match self {
            Self::CreateMasterKeyPair(action) => action.run(client_connector).await?,
            Self::CreateUserKey(action) => action.run(client_connector).await?,
            Self::Export(action) => action.run(client_connector).await?,
            Self::Import(action) => action.run(client_connector).await?,
            Self::Wrap(action) => action.run(client_connector).await?,
            Self::Unwrap(action) => action.run(client_connector).await?,
            Self::Revoke(action) => action.run(client_connector).await?,
            Self::Destroy(action) => action.run(client_connector).await?,
        };

        Ok(())
    }
}
