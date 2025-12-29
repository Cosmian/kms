use clap::{Parser, ValueEnum};
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_0::kmip_types::BlockCipherMode,
    kmip_2_1::kmip_types::{CryptographicAlgorithm, CryptographicParameters},
};
use strum::{Display, EnumIter};

pub use self::{decrypt::DecryptAction, encrypt::EncryptAction, keys::KeysCommands};
use crate::error::result::KmsCliResult;

pub mod decrypt;
pub mod encrypt;
pub mod keys;

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
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Keys(command) => command.process(kms_rest_client).await?,
            Self::Encrypt(action) => action.run(kms_rest_client).await?,
            Self::Decrypt(action) => action.run(kms_rest_client).await?,
        }
        Ok(())
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, EnumIter, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum KeyEncryptionAlgorithm {
    #[cfg(feature = "non-fips")]
    Chacha20Poly1305,
    AesGcm,
    AesXts,
    #[cfg(feature = "non-fips")]
    AesGcmSiv,
    RFC3394,
    RFC5649,
}

impl From<KeyEncryptionAlgorithm> for CryptographicParameters {
    fn from(value: KeyEncryptionAlgorithm) -> Self {
        match value {
            #[cfg(feature = "non-fips")]
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
            #[cfg(feature = "non-fips")]
            KeyEncryptionAlgorithm::AesGcmSiv => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::GCMSIV),
                ..Self::default()
            },
            KeyEncryptionAlgorithm::RFC5649 => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::AESKeyWrapPadding),
                ..Self::default()
            },
            KeyEncryptionAlgorithm::RFC3394 => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::NISTKeyWrap),
                ..Self::default()
            },
        }
    }
}
