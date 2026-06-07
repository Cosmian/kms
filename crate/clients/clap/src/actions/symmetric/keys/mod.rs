use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_key::CreateKeyAction, create_split_key::CreateSplitKeyAction,
    destroy_key::DestroyKeyAction, join_split_key::JoinSplitKeyAction, rekey::ReKeyAction,
    revoke_key::RevokeKeyAction,
};
use crate::{
    actions::shared::{
        ActivateKeyAction, ExportSecretDataOrKeyAction, GetRotationPolicyAction,
        ImportSecretDataOrKeyAction, SetRotationPolicyAction, UnwrapSecretDataOrKeyAction,
        WrapSecretDataOrKeyAction,
    },
    error::result::KmsCliResult,
};

pub mod create_key;
pub mod create_split_key;
pub mod destroy_key;
pub mod join_split_key;
pub mod rekey;
pub mod revoke_key;

/// Create, destroy, import, export, split and join symmetric keys
#[derive(Subcommand)]
pub enum KeysCommands {
    Activate(ActivateKeyAction),
    Create(CreateKeyAction),
    CreateSplitKey(CreateSplitKeyAction),
    JoinSplitKey(JoinSplitKeyAction),
    ReKey(ReKeyAction),
    Export(ExportSecretDataOrKeyAction),
    Import(ImportSecretDataOrKeyAction),
    Wrap(WrapSecretDataOrKeyAction),
    Unwrap(UnwrapSecretDataOrKeyAction),
    Revoke(RevokeKeyAction),
    Destroy(DestroyKeyAction),
    SetRotationPolicy(SetRotationPolicyAction),
    GetRotationPolicy(GetRotationPolicyAction),
}

impl KeysCommands {
    pub(crate) async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Activate(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Create(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::CreateSplitKey(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::JoinSplitKey(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::ReKey(action) => {
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
            Self::SetRotationPolicy(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::GetRotationPolicy(action) => {
                action.run(kms_rest_client).await?;
            }
        }

        Ok(())
    }
}
