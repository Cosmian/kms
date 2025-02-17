use clap::ValueEnum;
use cosmian_kmip::kmip_2_1::kmip_types::{
    BlockCipherMode, CryptographicAlgorithm, CryptographicParameters,
};
use serde::Deserialize;
use strum::{Display, EnumIter};

#[derive(ValueEnum, Debug, Clone, Copy, Default, EnumIter, PartialEq, Eq, Display, Deserialize)]
pub enum DataEncryptionAlgorithm {
    #[cfg(not(feature = "fips"))]
    #[value(name = "Chacha20Poly1305")]
    Chacha20Poly1305,
    #[default]
    #[value(name = "AesGcm")]
    AesGcm,
    #[value(name = "AesXts")]
    AesXts,
    #[cfg(not(feature = "fips"))]
    #[value(name = "AesGcmSiv")]
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
