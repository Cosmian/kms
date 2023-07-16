mod decrypt;
mod encrypt;
mod keys;

use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use self::{decrypt::DecryptAction, encrypt::EncryptAction, keys::KeysCommands};
use crate::error::CliError;

/// Manage symmetric keys and salts. Encrypt and decrypt data.
#[derive(Parser)]
pub enum SymmetricCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl SymmetricCommands {
    pub async fn process(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        match self {
            SymmetricCommands::Keys(command) => command.process(client_connector).await?,
            SymmetricCommands::Encrypt(action) => action.run(client_connector).await?,
            SymmetricCommands::Decrypt(action) => action.run(client_connector).await?,
        };
        Ok(())
    }
}
