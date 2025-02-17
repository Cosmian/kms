use clap::Parser;
use cosmian_kms_client::KmsClient;

use self::{decrypt::DecryptAction, encrypt::EncryptAction, keys::KeysCommands};
use crate::error::result::CliResult;

pub mod decrypt;
pub mod encrypt;
pub mod keys;

/// Manage RSA keys. Encrypt and decrypt data using RSA keys.
#[derive(Parser)]
pub enum RsaCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl RsaCommands {
    /// Process the RSA command by executing the corresponding action.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client used for communication with the KMS service.
    ///
    /// # Errors
    ///
    /// Returns an error if there is an issue executing the command.
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        match self {
            Self::Keys(command) => command.process(kms_rest_client).await?,
            Self::Encrypt(action) => action.run(kms_rest_client).await?,
            Self::Decrypt(action) => action.run(kms_rest_client).await?,
        }
        Ok(())
    }
}
