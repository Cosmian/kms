mod decrypt;
mod encrypt;
mod keys;

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::kmip::kmip_types::{CryptographicAlgorithm, HashingAlgorithm},
    KmsRestClient,
};

use self::{decrypt::DecryptAction, encrypt::EncryptAction, keys::KeysCommands};
use crate::error::CliError;

/// Manage RSA keys.
#[derive(Parser)]
pub enum RsaCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl RsaCommands {
    pub async fn process(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        match self {
            Self::Keys(command) => command.process(kms_rest_client).await?,
            Self::Encrypt(action) => action.run(kms_rest_client).await?,
            Self::Decrypt(action) => action.run(kms_rest_client).await?,
        };
        Ok(())
    }
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum EncryptionAlgorithm {
    CkmRsaPkcsOaep,
    RsaOaepAes128Gcm,
}

impl From<EncryptionAlgorithm> for CryptographicAlgorithm {
    fn from(value: EncryptionAlgorithm) -> Self {
        match value {
            EncryptionAlgorithm::CkmRsaPkcsOaep => CryptographicAlgorithm::RSA,
            EncryptionAlgorithm::RsaOaepAes128Gcm => CryptographicAlgorithm::AES,
        }
    }
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum HashFn {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl From<HashFn> for HashingAlgorithm {
    fn from(value: HashFn) -> Self {
        match value {
            HashFn::Sha1 => HashingAlgorithm::SHA1,
            HashFn::Sha224 => HashingAlgorithm::SHA224,
            HashFn::Sha256 => HashingAlgorithm::SHA256,
            HashFn::Sha384 => HashingAlgorithm::SHA384,
            HashFn::Sha512 => HashingAlgorithm::SHA512,
            HashFn::Sha3_224 => HashingAlgorithm::SHA3224,
            HashFn::Sha3_256 => HashingAlgorithm::SHA3256,
            HashFn::Sha3_384 => HashingAlgorithm::SHA3384,
            HashFn::Sha3_512 => HashingAlgorithm::SHA3512,
        }
    }
}
