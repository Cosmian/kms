use clap::{Parser, ValueEnum};
use cosmian_kms_client::{
    kmip::kmip_types::{BlockCipherMode, CryptographicAlgorithm, CryptographicParameters},
    KmsClient,
};

use self::{decrypt::DecryptAction, encrypt::EncryptAction, keys::KeysCommands};
use crate::error::result::CliResult;

mod decrypt;
mod encrypt;
mod keys;

/// Manage symmetric keys. Encrypt and decrypt data.
#[derive(Parser)]
pub enum SymmetricCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    Encrypt(EncryptAction),
    Decrypt(DecryptAction),
}

impl SymmetricCommands {
    /// Process the symmetric command and execute the corresponding action.
    ///
    /// # Errors
    ///
    /// This function can return an error if any of the underlying actions encounter an error.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - The KMS client used for communication with the KMS service.
    ///
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
pub(crate) enum DataEncryptionAlgorithm {
    #[cfg(not(feature = "fips"))]
    Chacha20Poly1305,
    AesGcm,
    AesXts,
    #[cfg(not(feature = "fips"))]
    AesGcmSiv,
}

impl From<DataEncryptionAlgorithm> for CryptographicParameters {
    fn from(value: DataEncryptionAlgorithm) -> Self {
        match value {
            #[cfg(not(feature = "fips"))]
            DataEncryptionAlgorithm::Chacha20Poly1305 => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ChaCha20Poly1305),
                ..Self::default()
            },
            DataEncryptionAlgorithm::AesGcm => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::GCM),
                ..Self::default()
            },
            DataEncryptionAlgorithm::AesXts => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::XTS),
                ..Self::default()
            },
            #[cfg(not(feature = "fips"))]
            DataEncryptionAlgorithm::AesGcmSiv => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::GCMSIV),
                ..Self::default()
            },
        }
    }
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub(crate) enum KeyEncryptionAlgorithm {
    #[cfg(not(feature = "fips"))]
    Chacha20Poly1305,
    AesGcm,
    AesXts,
    #[cfg(not(feature = "fips"))]
    AesGcmSiv,
    RFC5649,
}

impl From<KeyEncryptionAlgorithm> for CryptographicParameters {
    fn from(value: KeyEncryptionAlgorithm) -> Self {
        match value {
            #[cfg(not(feature = "fips"))]
            KeyEncryptionAlgorithm::Chacha20Poly1305 => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ChaCha20Poly1305),
                ..Self::default()
            },
            KeyEncryptionAlgorithm::AesGcm => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::GCM),
                ..Self::default()
            },
            KeyEncryptionAlgorithm::AesXts => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::XTS),
                ..Self::default()
            },
            #[cfg(not(feature = "fips"))]
            KeyEncryptionAlgorithm::AesGcmSiv => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::GCMSIV),
                ..Self::default()
            },
            KeyEncryptionAlgorithm::RFC5649 => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::NISTKeyWrap),
                ..Self::default()
            },
        }
    }
}
