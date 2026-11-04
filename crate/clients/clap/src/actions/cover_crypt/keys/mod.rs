use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    create_key_pair::CreateMasterKeyPairAction,
    create_user_key::CreateUserKeyAction,
    destroy_key::DestroyKeyAction,
    rekey::{PruneAction, ReKeyAction},
};
use crate::{
    actions::shared::{
        ActivateKeyAction, ExportSecretDataOrKeyAction, ImportSecretDataOrKeyAction,
        RevokeKeyAction, UnwrapSecretDataOrKeyAction, WrapSecretDataOrKeyAction, dispatch_run,
    },
    error::result::KmsCliResult,
};

pub(crate) mod create_key_pair;
pub(crate) mod create_user_key;
pub(crate) mod destroy_key;
pub(crate) mod rekey;

/// Create, destroy, import, export, and rekey `Covercrypt` master and user keys
#[derive(Subcommand)]
pub enum KeysCommands {
    Activate(ActivateKeyAction),
    CreateMasterKeyPair(CreateMasterKeyPairAction),
    CreateUserKey(CreateUserKeyAction),
    Export(ExportSecretDataOrKeyAction),
    Import(ImportSecretDataOrKeyAction),
    Wrap(WrapSecretDataOrKeyAction),
    Unwrap(UnwrapSecretDataOrKeyAction),
    /// Revoke a Covercrypt master or user decryption key.
    ///
    /// Once a key is revoked, it can only be exported by the owner of the key,
    /// using the --allow-revoked flag on the export function.
    ///
    /// Revoking a master public or private key will revoke the whole key pair
    /// and all the associated user decryption keys present in the KMS.
    ///
    /// Once a user decryption key is revoked, it will no longer be rekeyed
    /// when attributes are rotated on the master key.
    ///
    /// When using tags to revoke the key, rather than the key id,
    /// an error is returned if multiple keys matching the tags are found.
    Revoke(RevokeKeyAction),
    Destroy(DestroyKeyAction),
    Rekey(ReKeyAction),
    Prune(PruneAction),
}

impl KeysCommands {
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        dispatch_run!(
            self,
            kms_rest_client,
            [
                Activate,
                CreateUserKey,
                Export,
                Import,
                Wrap,
                Revoke,
                Destroy,
                Rekey,
                Prune
            ],
            boxed: [CreateMasterKeyPair, Unwrap]
        );
        Ok(())
    }
}
