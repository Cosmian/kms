use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::{
    actions::kms::configurable_kem::{
        decaps::DecapsAction, encaps::EncapsAction, keygen::CreateKemKeyPairAction,
    },
    error::result::KmsCliResult,
};

pub(crate) mod decaps;
pub(crate) mod encaps;
pub(crate) mod keygen;

#[derive(Parser)]
pub enum ConfigurableKemCommands {
    KeyGen(CreateKemKeyPairAction),
    Encrypt(EncapsAction),
    Decrypt(DecapsAction),
}

impl ConfigurableKemCommands {
    /// Process the configurable-KEM command and execute the corresponding
    /// action.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::KeyGen(action) => {
                drop(Box::pin(action.run(kms_rest_client)).await?);
            }
            Self::Encrypt(action) => action.run(kms_rest_client).await?,
            Self::Decrypt(action) => action.run(kms_rest_client).await?,
        }
        Ok(())
    }
}
