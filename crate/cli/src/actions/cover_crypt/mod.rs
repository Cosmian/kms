pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod keys;
pub(crate) mod policy;
pub(crate) mod rotate_attributes;

use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use crate::{
    actions::cover_crypt::{
        decrypt::DecryptAction, encrypt::EncryptAction, keys::KeysCommands, policy::PolicyCommands,
        rotate_attributes::RotateAttributesAction,
    },
    error::CliError,
};

/// Manage CoverCrypt keys and policies. Rotate attributes. Encrypt and decrypt data.
#[derive(Parser)]
pub enum CoverCryptCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    #[command(subcommand)]
    Policy(PolicyCommands),
    Rotate(RotateAttributesAction),
    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl CoverCryptCommands {
    pub async fn process(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        match self {
            Self::Policy(command) => command.process(client_connector).await?,
            Self::Keys(command) => command.process(client_connector).await?,
            Self::Rotate(action) => action.run(client_connector).await?,
            Self::Encrypt(action) => action.run(client_connector).await?,
            Self::Decrypt(action) => action.run(client_connector).await?,
        };
        Ok(())
    }
}
