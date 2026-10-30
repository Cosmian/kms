use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_key::CreateKeyAction, create_split_key::CreateSplitKeyAction,
    destroy_key::DestroyKeyAction, join_split_key::JoinSplitKeyAction, rekey::ReKeyAction,
};
use crate::{
    actions::shared::{
        ActivateKeyAction, ExportSecretDataOrKeyAction, GetRotationPolicyAction,
        ImportSecretDataOrKeyAction, RevokeKeyAction, SetRotationPolicyAction,
        UnwrapSecretDataOrKeyAction, WrapSecretDataOrKeyAction, dispatch_run,
    },
    error::result::KmsCliResult,
};

pub mod create_key;
pub mod create_split_key;
pub mod destroy_key;
pub mod join_split_key;
pub mod rekey;

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
    /// Revoke a symmetric key.
    ///
    /// When a key is revoked, it can only be exported by the owner of the key,
    /// using the --allow-revoked flag on the export function.
    Revoke(RevokeKeyAction),
    Destroy(DestroyKeyAction),
    SetRotationPolicy(SetRotationPolicyAction),
    GetRotationPolicy(GetRotationPolicyAction),
}

impl KeysCommands {
    pub(crate) async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        dispatch_run!(
            self,
            kms_rest_client,
            [
                Activate,
                Create,
                CreateSplitKey,
                JoinSplitKey,
                ReKey,
                Export,
                Import,
                Wrap,
                Revoke,
                Destroy,
                SetRotationPolicy,
                GetRotationPolicy
            ],
            boxed: [Unwrap]
        );
        Ok(())
    }
}
