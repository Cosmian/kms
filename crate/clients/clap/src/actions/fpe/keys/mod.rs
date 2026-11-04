use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{create_key::CreateKeyAction, destroy_key::DestroyKeyAction};
use crate::{
    actions::shared::{
        ExportSecretDataOrKeyAction, ImportSecretDataOrKeyAction, RevokeKeyAction,
        UnwrapSecretDataOrKeyAction, WrapSecretDataOrKeyAction, dispatch_run,
    },
    error::result::KmsCliResult,
};

pub mod create_key;
pub mod destroy_key;

/// Create, destroy, import, and export FPE keys
#[derive(Subcommand)]
pub enum KeysCommands {
    Create(CreateKeyAction),
    Export(ExportSecretDataOrKeyAction),
    Import(ImportSecretDataOrKeyAction),
    Wrap(WrapSecretDataOrKeyAction),
    Unwrap(UnwrapSecretDataOrKeyAction),
    /// Revoke an FPE key.
    ///
    /// When a key is revoked, it can only be exported by the owner of the key,
    /// using the --allow-revoked flag on the export function.
    Revoke(RevokeKeyAction),
    Destroy(DestroyKeyAction),
}

impl KeysCommands {
    pub(crate) async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        dispatch_run!(
            self,
            kms_rest_client,
            [Create, Export, Import, Wrap, Revoke, Destroy],
            boxed: [Unwrap]
        );
        Ok(())
    }
}
