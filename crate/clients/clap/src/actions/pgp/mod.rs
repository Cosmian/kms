use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    decrypt::DecryptAction, encrypt::EncryptAction, keys::KeysCommands, sign::SignAction,
    signature_verify::SignatureVerifyAction,
};
use crate::{
    actions::shared::{ExportSecretDataOrKeyAction, ImportSecretDataOrKeyAction},
    error::result::KmsCliResult,
};

pub mod decrypt;
pub mod encrypt;
pub mod keys;
pub mod sign;
pub mod signature_verify;

/// Create, import, export and use `OpenPGP` keys (non-FIPS builds only).
///
/// `OpenPGP` key import accepts `GnuPG` transferable public keys and unprotected secret keys in
/// ASCII-armored or binary form. Secret keys must be unprotected for KMS Decrypt/Sign operations.
/// The `pgp-secret` and `pgp-public` formats export ASCII-armored keys; `pgp-secret-binary` and
/// `pgp-public-binary` export binary keys. Encrypt and Sign produce binary `OpenPGP` output;
/// Decrypt and Verify accept both binary and ASCII-armored input.
/// Only detached signatures can be verified.
#[derive(Subcommand)]
pub enum PgpCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    Export(ExportSecretDataOrKeyAction),
    Import(ImportSecretDataOrKeyAction),
    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
    Sign(SignAction),
    SignVerify(SignatureVerifyAction),
}

impl PgpCommands {
    /// Process the `OpenPGP` command by executing the corresponding action.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client.
    ///
    /// # Errors
    ///
    /// Returns an error if executing the command fails.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Keys(command) => Box::pin(command.process(kms_rest_client)).await?,
            Self::Export(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Import(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Encrypt(action) => action.run(kms_rest_client).await?,
            Self::Decrypt(action) => action.run(kms_rest_client).await?,
            Self::Sign(action) => action.run(kms_rest_client).await?,
            Self::SignVerify(action) => {
                action.run(kms_rest_client).await?;
            }
        }
        Ok(())
    }
}
