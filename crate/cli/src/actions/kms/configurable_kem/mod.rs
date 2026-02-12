use crate::{
    actions::kms::configurable_kem::{
        decaps::DecapsAction, encaps::EncapsAction, keygen::CreateKemKeyPairAction,
    },
    error::result::KmsCliResult,
};
use clap::Parser;
use cosmian_kms_client::KmsClient;

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
                let (dk_id, ek_id) = action.run(kms_rest_client).await?;
                println!("decapsulation key ID: {dk_id:?}");
                println!("encapsulation key ID: {ek_id:?}");
            }
            Self::Encrypt(action) => {
                let (key, encapsulation) = action.run(kms_rest_client).await?;
                println!("session key: {key:?}");
                println!("encapsulation: {encapsulation:?}");
            }
            Self::Decrypt(action) => {
                let key = action.run(kms_rest_client).await?;
                println!("session key: {key:?}");
            }
        }
        Ok(())
    }
}
