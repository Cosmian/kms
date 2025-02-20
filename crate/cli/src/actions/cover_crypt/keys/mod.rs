use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_key_pair::CreateMasterKeyPairAction,
    create_user_key::CreateUserKeyAction,
    destroy_key::DestroyKeyAction,
    rekey::{PruneAction, RekeyAction},
    revoke_key::RevokeKeyAction,
};
use crate::{
    actions::shared::{ExportKeyAction, ImportKeyAction, UnwrapKeyAction, WrapKeyAction},
    error::result::CliResult,
};

mod create_key_pair;
mod create_user_key;
mod destroy_key;
mod rekey;
mod revoke_key;

/// Create, destroy, import, export, and rekey `Covercrypt` master and user keys
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
    Rekey(RekeyAction),
    Prune(PruneAction),
}

impl KeysCommands {
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        match self {
            Self::CreateMasterKeyPair(action) => action.run(kms_rest_client).await?,
            Self::CreateUserKey(action) => action.run(kms_rest_client).await?,
            Self::Export(action) => action.run(kms_rest_client).await?,
            Self::Import(action) => action.run(kms_rest_client).await?,
            Self::Wrap(action) => action.run(kms_rest_client).await?,
            Self::Unwrap(action) => action.run(kms_rest_client).await?,
            Self::Revoke(action) => action.run(kms_rest_client).await?,
            Self::Destroy(action) => action.run(kms_rest_client).await?,
            Self::Rekey(action) => action.run(kms_rest_client).await?,
            Self::Prune(action) => action.run(kms_rest_client).await?,
        };

        Ok(())
    }
}
