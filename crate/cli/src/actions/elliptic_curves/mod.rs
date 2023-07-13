mod decrypt;
mod encrypt;
mod keys;

use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use self::{decrypt::DecryptAction, encrypt::EncryptAction, keys::KeysCommands};
use super::shared::LocateObjectsAction;
use crate::error::CliError;

/// Manage elliptic curve keys. Encrypt and decrypt data using ECIES.
#[derive(Parser)]
pub enum EllipticCurveCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
    Locate(LocateObjectsAction),
}

impl EllipticCurveCommands {
    pub async fn process(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        match self {
            EllipticCurveCommands::Keys(command) => command.process(client_connector).await?,
            EllipticCurveCommands::Encrypt(action) => action.run(client_connector).await?,
            EllipticCurveCommands::Decrypt(action) => action.run(client_connector).await?,
            EllipticCurveCommands::Locate(action) => action.run(client_connector).await?,
        };
        Ok(())
    }
}
