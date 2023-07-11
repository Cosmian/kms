use clap::Subcommand;
use cosmian_kms_client::KmsRestClient;

use self::{
    create_key_pair::CreateKeyPairAction, destroy_key::DestroyKeyAction,
    revoke_key::RevokeKeyAction,
};
use crate::{
    actions::shared::{
        ExportKeyAction, ImportKeyAction, LocateKeysAction, UnwrapKeyAction, WrapKeyAction,
    },
    error::CliError,
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
    Locate(LocateKeysAction),
}

impl KeysCommands {
    pub async fn process(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        match self {
            Self::Create(action) => action.run(client_connector).await?,
            Self::Export(action) => action.run(client_connector).await?,
            Self::Import(action) => action.run(client_connector).await?,
            Self::Wrap(action) => action.run(client_connector).await?,
            Self::Unwrap(action) => action.run(client_connector).await?,
            Self::Revoke(action) => action.run(client_connector).await?,
            Self::Destroy(action) => action.run(client_connector).await?,
            Self::Locate(action) => action.run(client_connector).await?,
        };

        Ok(())
    }
}
