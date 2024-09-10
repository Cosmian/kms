use std::fmt::Display;

use clap::{Parser, ValueEnum};
use cosmian_kms_client::{
    cosmian_kmip::kmip::kmip_types::{CryptographicAlgorithm, HashingAlgorithm},
    kmip::kmip_types::{CryptographicParameters, PaddingMethod},
    KmsClient,
};

use self::{decrypt::DecryptAction, encrypt::EncryptAction, keys::KeysCommands};
use crate::error::result::CliResult;

mod decrypt;
mod encrypt;
mod keys;

/// Manage RSA keys. Encrypt and decrypt data using RSA keys.
#[derive(Parser)]
pub enum RsaCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl RsaCommands {
    /// Process the RSA command by executing the corresponding action.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client used for communication with the KMS service.
    ///
    /// # Errors
    ///
    /// Returns an error if there is an issue executing the command.
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        match self {
            Self::Keys(command) => command.process(kms_rest_client).await?,
            Self::Encrypt(action) => action.run(kms_rest_client).await?,
            Self::Decrypt(action) => action.run(kms_rest_client).await?,
        };
        Ok(())
    }
}

#[derive(ValueEnum, Debug, Clone, Copy)]
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
            Self::CkmRsaPkcsOaep => write!(f, "ckm-rsa-pkcs-oaep"),
            Self::CkmRsaAesKeyWrap => write!(f, "ckm-rsa-aes-key-wrap"),
            #[cfg(not(feature = "fips"))]
            Self::CkmRsaPkcs => write!(f, "ckm-rsa-pkcs"),
        }
    }
}

#[derive(ValueEnum, Debug, Clone, Copy)]
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
            Self::Sha1 => write!(f, "sha1"),
            Self::Sha224 => write!(f, "sha224"),
            Self::Sha256 => write!(f, "sha256"),
            Self::Sha384 => write!(f, "sha384"),
            Self::Sha512 => write!(f, "sha512"),
            Self::Sha3_224 => write!(f, "sha3-224"),
            Self::Sha3_256 => write!(f, "sha3-256"),
            Self::Sha3_384 => write!(f, "sha3-384"),
            Self::Sha3_512 => write!(f, "sha3-512"),
        }
    }
}

impl From<HashFn> for HashingAlgorithm {
    fn from(value: HashFn) -> Self {
        match value {
            HashFn::Sha1 => Self::SHA1,
            HashFn::Sha224 => Self::SHA224,
            HashFn::Sha256 => Self::SHA256,
            HashFn::Sha384 => Self::SHA384,
            HashFn::Sha512 => Self::SHA512,
            HashFn::Sha3_224 => Self::SHA3224,
            HashFn::Sha3_256 => Self::SHA3256,
            HashFn::Sha3_384 => Self::SHA3384,
            HashFn::Sha3_512 => Self::SHA3512,
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
