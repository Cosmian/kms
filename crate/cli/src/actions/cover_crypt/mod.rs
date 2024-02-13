pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod keys;
pub(crate) mod policy;
pub(crate) mod rekey;

use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use crate::{
    actions::cover_crypt::{
        decrypt::DecryptAction, encrypt::EncryptAction, keys::KeysCommands, policy::PolicyCommands,
        rekey::RekeyAction,
    },
    error::CliError,
};

/// Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data.
#[derive(Parser)]
pub enum CovercryptCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    #[command(subcommand)]
    Policy(PolicyCommands),
    Rekey(RekeyAction),
    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl CovercryptCommands {
    pub async fn process(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        match self {
            Self::Policy(command) => command.process(kms_rest_client).await?,
            Self::Keys(command) => command.process(kms_rest_client).await?,
            Self::Rekey(action) => action.run(kms_rest_client).await?,
            Self::Encrypt(action) => action.run(kms_rest_client).await?,
            Self::Decrypt(action) => action.run(kms_rest_client).await?,
        };
        Ok(())
    }
}
