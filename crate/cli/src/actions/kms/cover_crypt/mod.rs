use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::kms::cover_crypt::{
        access_structure::AccessStructureCommands, decrypt::DecryptAction, encrypt::EncryptAction,
        keys::KeysCommands,
    },
    error::result::CosmianResult,
};

pub(crate) mod access_structure;
pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod keys;

/// Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data.
#[derive(Parser)]
pub enum CovercryptCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    #[command(subcommand)]
    AccessStructure(AccessStructureCommands),
    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl CovercryptCommands {
    /// Process the Covercrypt command and execute the corresponding action.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - The KMS client used for communication with the KMS service.
    ///
    /// # Errors
    ///
    /// This function can return an error if any of the underlying actions encounter an error.
    ///
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CosmianResult<()> {
        match self {
            Self::AccessStructure(command) => command.process(kms_rest_client).await?,
            Self::Keys(command) => Box::pin(command.process(kms_rest_client)).await?,
            Self::Encrypt(action) => action.run(kms_rest_client).await?,
            Self::Decrypt(action) => action.run(kms_rest_client).await?,
        }
        Ok(())
    }
}
