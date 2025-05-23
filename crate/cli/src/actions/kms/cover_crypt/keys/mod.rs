use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_key_pair::CreateMasterKeyPairAction,
    create_user_key::CreateUserKeyAction,
    destroy_key::DestroyKeyAction,
    rekey::{PruneAction, ReKeyAction},
    revoke_key::RevokeKeyAction,
};
use crate::{
    actions::kms::shared::{ExportKeyAction, ImportKeyAction, UnwrapKeyAction, WrapKeyAction},
    error::result::KmsCliResult,
};

pub(crate) mod create_key_pair;
pub(crate) mod create_user_key;
pub(crate) mod destroy_key;
pub(crate) mod rekey;
pub(crate) mod revoke_key;

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
    Rekey(ReKeyAction),
    Prune(PruneAction),
}

impl KeysCommands {
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::CreateMasterKeyPair(action) => {
                Box::pin(action.run(kms_rest_client)).await?;
            }
            Self::CreateUserKey(action) => {
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
            Self::Unwrap(action) => action.run(kms_rest_client).await?,
            Self::Revoke(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Destroy(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Rekey(action) => action.run(kms_rest_client).await?,
            Self::Prune(action) => action.run(kms_rest_client).await?,
        }

        Ok(())
    }
}
