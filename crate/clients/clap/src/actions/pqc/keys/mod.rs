use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_key_pair::CreatePqcKeyPairAction, destroy_key::DestroyKeyAction,
    revoke_key::RevokeKeyAction,
};
use crate::{
    actions::shared::{
        ActivateKeyAction, ExportSecretDataOrKeyAction, GetRotationPolicyAction,
        ImportSecretDataOrKeyAction, ReKeyKeyPairAction, SetRotationPolicyAction,
        UnwrapSecretDataOrKeyAction, WrapSecretDataOrKeyAction, dispatch_run,
    },
    error::result::KmsCliResult,
};

pub(crate) mod create_key_pair;
pub(crate) mod destroy_key;
pub(crate) mod revoke_key;

/// Manage post-quantum keys (ML-KEM, ML-DSA)
#[derive(Subcommand)]
pub enum KeysCommands {
    Activate(ActivateKeyAction),
    Create(CreatePqcKeyPairAction),
    Export(ExportSecretDataOrKeyAction),
    Import(ImportSecretDataOrKeyAction),
    Wrap(WrapSecretDataOrKeyAction),
    Unwrap(UnwrapSecretDataOrKeyAction),
    Revoke(RevokeKeyAction),
    Destroy(DestroyKeyAction),
    ReKey(ReKeyKeyPairAction),
    SetRotationPolicy(SetRotationPolicyAction),
    GetRotationPolicy(GetRotationPolicyAction),
}

impl KeysCommands {
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        dispatch_run!(
            self,
            kms_rest_client,
            [
                Activate,
                Create,
                Export,
                Import,
                Wrap,
                Revoke,
                Destroy,
                ReKey,
                SetRotationPolicy,
                GetRotationPolicy
            ],
            boxed: [Unwrap]
        );
        Ok(())
    }
}
