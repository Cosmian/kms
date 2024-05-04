use std::fmt::Display;

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::kmip::kmip_types::{CryptographicAlgorithm, HashingAlgorithm},
    kmip::kmip_types::{CryptographicParameters, PaddingMethod},
    KmsClient,
};

use self::{decrypt::DecryptAction, encrypt::EncryptAction, keys::KeysCommands};
use crate::error::CliError;

mod decrypt;
mod encrypt;
mod keys;

/// Manage RSA keys.
#[derive(Parser)]
pub enum RsaCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl RsaCommands {
    pub async fn process(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
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
    #[cfg(not(feature = "fips"))]
    // a.k.a PKCS#1 v1.5 RSA
    CkmRsaPkcs,
    // a.k.a PKCS#1 RSA OAEP
    CkmRsaPkcsOaep,
    // CKM_RSA_AES_KEY_WRAP
    CkmRsaAesKeyWrap,
}

impl Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionAlgorithm::CkmRsaPkcsOaep => write!(f, "ckm-rsa-pkcs-oaep"),
            EncryptionAlgorithm::CkmRsaAesKeyWrap => write!(f, "ckm-rsa-aes-key-wrap"),
            #[cfg(not(feature = "fips"))]
            EncryptionAlgorithm::CkmRsaPkcs => write!(f, "ckm-rsa-pkcs"),
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

impl Display for HashFn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashFn::Sha1 => write!(f, "sha1"),
            HashFn::Sha224 => write!(f, "sha224"),
            HashFn::Sha256 => write!(f, "sha256"),
            HashFn::Sha384 => write!(f, "sha384"),
            HashFn::Sha512 => write!(f, "sha512"),
            HashFn::Sha3_224 => write!(f, "sha3-224"),
            HashFn::Sha3_256 => write!(f, "sha3-256"),
            HashFn::Sha3_384 => write!(f, "sha3-384"),
            HashFn::Sha3_512 => write!(f, "sha3-512"),
        }
    }
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

fn to_cryptographic_parameters(
    alg: EncryptionAlgorithm,
    hash_fn: HashFn,
) -> CryptographicParameters {
    match alg {
        #[cfg(not(feature = "fips"))]
        EncryptionAlgorithm::CkmRsaPkcs => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PKCS1v15),
            hashing_algorithm: None,
            ..Default::default()
        },
        EncryptionAlgorithm::CkmRsaPkcsOaep => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(hash_fn.into()),
            ..Default::default()
        },
        EncryptionAlgorithm::CkmRsaAesKeyWrap => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(hash_fn.into()),
            ..Default::default()
        },
    }
}
