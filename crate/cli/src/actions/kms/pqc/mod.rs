use clap::Parser;
use cosmian_kms_client::KmsClient;

use crate::error::result::KmsCliResult;

pub(crate) mod decapsulate;
pub(crate) mod encapsulate;
pub(crate) mod keys;
pub(crate) mod sign;
pub(crate) mod signature_verify;

/// Manage post-quantum keys (ML-KEM, ML-DSA, Hybrid KEM, SLH-DSA). Encapsulate, decapsulate, sign, and verify.
#[derive(Parser)]
pub enum PqcCommands {
    #[command(subcommand)]
    Keys(keys::KeysCommands),
    Encrypt(encapsulate::EncapsulateAction),
    Decrypt(decapsulate::DecapsulateAction),
    Sign(sign::SignAction),
    SignVerify(signature_verify::SignatureVerifyAction),
}

impl PqcCommands {
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Keys(action) => action.process(kms_rest_client).await?,
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
