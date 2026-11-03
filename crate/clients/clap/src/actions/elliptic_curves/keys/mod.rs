use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{create_key_pair::CreateKeyPairAction, destroy_key::DestroyKeyAction};
use crate::{
    actions::shared::{
        ActivateKeyAction, ExportSecretDataOrKeyAction, GetRotationPolicyAction,
        ImportSecretDataOrKeyAction, ReKeyKeyPairAction, RevokeKeyAction, SetRotationPolicyAction,
        UnwrapSecretDataOrKeyAction, WrapSecretDataOrKeyAction, dispatch_run,
    },
    error::result::KmsCliResult,
};

pub(crate) mod create_key_pair;
pub(crate) mod destroy_key;

/// Create, destroy, import, and export elliptic curve key pairs
#[derive(Subcommand)]
pub enum KeysCommands {
    Activate(ActivateKeyAction),
    Create(CreateKeyPairAction),
    Export(ExportSecretDataOrKeyAction),
    Import(ImportSecretDataOrKeyAction),
    Wrap(WrapSecretDataOrKeyAction),
    Unwrap(UnwrapSecretDataOrKeyAction),
    /// Revoke a public or private key.
    ///
    /// Once a key is revoked, it can only be exported by the owner of the key,
    /// using the --allow-revoked flag on the export function.
    ///
    /// Revoking a public or private key will revoke the whole key pair
    /// (the two keys need to be stored in the KMS).
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
