use clap::ValueEnum;
use cosmian_kmip::kmip_2_1::kmip_types::{
    BlockCipherMode, CryptographicAlgorithm, CryptographicParameters,
};
use serde::Deserialize;
use strum::{Display, EnumIter};

use crate::error::UtilsError;

// Symmetric encryption utils
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

/// AES 128 GCM key length in bytes.
pub const AES_128_GCM_KEY_LENGTH: usize = 16;
/// AES 128 GCM nonce length in bytes.
pub const AES_128_GCM_IV_LENGTH: usize = 12;
/// AES 128 GCM tag/mac length in bytes.
pub const AES_128_GCM_MAC_LENGTH: usize = 16;

/// AES 256 GCM key length in bytes.
pub const AES_256_GCM_KEY_LENGTH: usize = 32;
/// AES 256 GCM nonce length in bytes.
pub const AES_256_GCM_IV_LENGTH: usize = 12;
/// AES 256 GCM tag/mac length in bytes.
pub const AES_256_GCM_MAC_LENGTH: usize = 16;

/// AES 128 XTS key length in bytes.
pub const AES_128_XTS_KEY_LENGTH: usize = 32;
/// AES 128 XTS nonce, actually called a tweak, length in bytes.
pub const AES_128_XTS_TWEAK_LENGTH: usize = 16;
/// AES 128 XTS has no authentication.
pub const AES_128_XTS_MAC_LENGTH: usize = 0;
/// AES 256 XTS key length in bytes.
pub const AES_256_XTS_KEY_LENGTH: usize = 64;
/// AES 256 XTS nonce actually called a tweak,length in bytes.
pub const AES_256_XTS_TWEAK_LENGTH: usize = 16;
/// AES 256 XTS has no authentication.
pub const AES_256_XTS_MAC_LENGTH: usize = 0;
/// AES 128 `GCM_SIV` key length in bytes.
#[cfg(not(feature = "fips"))]
pub const AES_128_GCM_SIV_KEY_LENGTH: usize = 16;
/// AES 128 `GCM_SIV` nonce length in bytes.
#[cfg(not(feature = "fips"))]
pub const AES_128_GCM_SIV_IV_LENGTH: usize = 12;
/// AES 128 `GCM_SIV` mac length in bytes.
#[cfg(not(feature = "fips"))]
pub const AES_128_GCM_SIV_MAC_LENGTH: usize = 16;
/// AES 256 `GCM_SIV` key length in bytes.
#[cfg(not(feature = "fips"))]
pub const AES_256_GCM_SIV_KEY_LENGTH: usize = 32;
/// AES 256 `GCM_SIV` nonce length in bytes.
#[cfg(not(feature = "fips"))]
pub const AES_256_GCM_SIV_IV_LENGTH: usize = 12;
/// AES 256 `GCM_SIV` mac length in bytes.
#[cfg(not(feature = "fips"))]
pub const AES_256_GCM_SIV_MAC_LENGTH: usize = 16;

/// RFC 5649 with a 16-byte KEK.
pub const RFC5649_16_KEY_LENGTH: usize = 16;
// RFC 5649 IV is actually a fixed overhead
pub const RFC5649_16_IV_LENGTH: usize = 0;
/// RFC5649 has no authentication.
pub const RFC5649_16_MAC_LENGTH: usize = 0;
/// RFC 5649 with a 32-byte KEK.
pub const RFC5649_32_KEY_LENGTH: usize = 32;
// RFC 5649 IV is actually a fixed overhead
pub const RFC5649_32_IV_LENGTH: usize = 0;
/// RFC5649 has no authentication.
pub const RFC5649_32_MAC_LENGTH: usize = 0;

#[cfg(not(feature = "fips"))]
/// Chacha20-Poly1305 key length in bytes.
pub const CHACHA20_POLY1305_KEY_LENGTH: usize = 32;
#[cfg(not(feature = "fips"))]
/// Chacha20-Poly1305 iv length in bytes.
pub const CHACHA20_POLY1305_IV_LENGTH: usize = 12;
#[cfg(not(feature = "fips"))]
/// Chacha20-Poly1305 tag/mac length in bytes.
pub const CHACHA20_POLY1305_MAC_LENGTH: usize = 16;

type ParsedSymEncrypted = (Vec<u8>, Vec<u8>, Vec<u8>);

pub fn parse_decrypt_elements(
    cryptographic_parameters: &CryptographicParameters,
    mut ciphertext: Vec<u8>,
) -> Result<ParsedSymEncrypted, UtilsError> {
    let (nonce_size, tag_size) = match &cryptographic_parameters
        .cryptographic_algorithm
        .unwrap_or(CryptographicAlgorithm::AES)
    {
        CryptographicAlgorithm::AES => match cryptographic_parameters
            .block_cipher_mode
            .unwrap_or(BlockCipherMode::GCM)
        {
            BlockCipherMode::GCM | BlockCipherMode::GCMSIV => {
                (AES_128_GCM_IV_LENGTH, AES_128_GCM_MAC_LENGTH)
            }
            BlockCipherMode::XTS => (AES_128_XTS_TWEAK_LENGTH, AES_128_XTS_MAC_LENGTH),
            BlockCipherMode::NISTKeyWrap => (RFC5649_16_IV_LENGTH, RFC5649_16_MAC_LENGTH),
            _ => {
                return Err(UtilsError::Default(
                    "Unsupported block cipher mode".to_owned(),
                ))
            }
        },
        #[cfg(not(feature = "fips"))]
        CryptographicAlgorithm::ChaCha20Poly1305 | CryptographicAlgorithm::ChaCha20 => {
            (CHACHA20_POLY1305_IV_LENGTH, CHACHA20_POLY1305_MAC_LENGTH)
        }
        _ => {
            return Err(UtilsError::Default(
                "Unsupported cryptographic algorithm".to_owned(),
            ))
        }
    };
    let nonce = ciphertext.drain(..nonce_size).collect::<Vec<_>>();
    let tag = ciphertext
        .drain(ciphertext.len() - tag_size..)
        .collect::<Vec<_>>();
    Ok((ciphertext, nonce, tag))
}
