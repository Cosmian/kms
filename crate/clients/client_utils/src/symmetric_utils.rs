use clap::ValueEnum;
use cosmian_kmip::{
    kmip_0::kmip_types::BlockCipherMode,
    kmip_2_1::kmip_types::{CryptographicAlgorithm, CryptographicParameters},
};
use serde::Deserialize;
use strum::{Display, EnumIter};

use crate::error::UtilsError;

// Symmetric encryption utils
#[derive(ValueEnum, Debug, Clone, Copy, Default, EnumIter, PartialEq, Eq, Display, Deserialize)]
#[strum(serialize_all = "kebab-case")]
pub enum DataEncryptionAlgorithm {
    #[cfg(feature = "non-fips")]
    Chacha20Poly1305,
    #[default]
    AesGcm,
    AesCbc,
    AesXts,
    #[cfg(feature = "non-fips")]
    AesGcmSiv,
}

impl From<DataEncryptionAlgorithm> for CryptographicParameters {
    fn from(value: DataEncryptionAlgorithm) -> Self {
        match value {
            #[cfg(feature = "non-fips")]
            DataEncryptionAlgorithm::Chacha20Poly1305 => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ChaCha20Poly1305),
                ..Self::default()
            },
            DataEncryptionAlgorithm::AesGcm => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::GCM),
                ..Self::default()
            },
            DataEncryptionAlgorithm::AesCbc => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::CBC),
                ..Self::default()
            },
            DataEncryptionAlgorithm::AesXts => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::XTS),
                ..Self::default()
            },
            #[cfg(feature = "non-fips")]
            DataEncryptionAlgorithm::AesGcmSiv => Self {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::GCMSIV),
                ..Self::default()
            },
        }
    }
}

/// AES 128 CBC key length in bytes.
pub const AES_128_CBC_KEY_LENGTH: usize = 16;
/// AES 128 CBC nonce length in bytes.
pub const AES_128_CBC_IV_LENGTH: usize = 16;
/// AES 128 CBC tag/mac length in bytes.
pub const AES_128_CBC_MAC_LENGTH: usize = 0;

/// AES 256 CBC key length in bytes.
pub const AES_256_CBC_KEY_LENGTH: usize = 32;
/// AES 256 CBC nonce length in bytes.
pub const AES_256_CBC_IV_LENGTH: usize = 16;
/// AES 256 CBC tag/mac length in bytes.
pub const AES_256_CBC_MAC_LENGTH: usize = 0;

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
#[cfg(feature = "non-fips")]
pub const AES_128_GCM_SIV_KEY_LENGTH: usize = 16;
/// AES 128 `GCM_SIV` nonce length in bytes.
#[cfg(feature = "non-fips")]
pub const AES_128_GCM_SIV_IV_LENGTH: usize = 12;
/// AES 128 `GCM_SIV` mac length in bytes.
#[cfg(feature = "non-fips")]
pub const AES_128_GCM_SIV_MAC_LENGTH: usize = 16;
/// AES 256 `GCM_SIV` key length in bytes.
#[cfg(feature = "non-fips")]
pub const AES_256_GCM_SIV_KEY_LENGTH: usize = 32;
/// AES 256 `GCM_SIV` nonce length in bytes.
#[cfg(feature = "non-fips")]
pub const AES_256_GCM_SIV_IV_LENGTH: usize = 12;
/// AES 256 `GCM_SIV` mac length in bytes.
#[cfg(feature = "non-fips")]
pub const AES_256_GCM_SIV_MAC_LENGTH: usize = 16;

// RFC 3394 IV is actually a fixed overhead
pub const RFC3394_IV_LENGTH: usize = 0;
/// RFC3394 has no authentication.
pub const RFC3394_MAC_LENGTH: usize = 0;

// RFC 5649 IV is actually a fixed overhead
pub const RFC5649_IV_LENGTH: usize = 0;
/// RFC5649 has no authentication.
pub const RFC5649_MAC_LENGTH: usize = 0;

#[cfg(feature = "non-fips")]
/// Chacha20-Poly1305 key length in bytes.
pub const CHACHA20_POLY1305_KEY_LENGTH: usize = 32;
#[cfg(feature = "non-fips")]
/// Chacha20-Poly1305 iv length in bytes.
pub const CHACHA20_POLY1305_IV_LENGTH: usize = 12;
#[cfg(feature = "non-fips")]
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
            BlockCipherMode::CBC => (AES_128_CBC_IV_LENGTH, AES_128_CBC_MAC_LENGTH),
            BlockCipherMode::XTS => (AES_128_XTS_TWEAK_LENGTH, AES_128_XTS_MAC_LENGTH),
            BlockCipherMode::AESKeyWrapPadding => (RFC5649_IV_LENGTH, RFC5649_MAC_LENGTH),
            BlockCipherMode::NISTKeyWrap => (RFC3394_IV_LENGTH, RFC3394_MAC_LENGTH),
            _ => {
                return Err(UtilsError::Default(
                    "Unsupported block cipher mode".to_owned(),
                ));
            }
        },
        #[cfg(feature = "non-fips")]
        CryptographicAlgorithm::ChaCha20Poly1305 | CryptographicAlgorithm::ChaCha20 => {
            (CHACHA20_POLY1305_IV_LENGTH, CHACHA20_POLY1305_MAC_LENGTH)
        }
        a => {
            return Err(UtilsError::Default(format!(
                "Unsupported cryptographic algorithm: {a}"
            )));
        }
    };
    if nonce_size + tag_size > ciphertext.len() {
        return Err(UtilsError::Default(
            "The ciphertext is too short to contain the nonce/tweak and the tag".to_owned(),
        ));
    }
    let nonce = ciphertext.drain(..nonce_size).collect::<Vec<_>>();
    let tag = ciphertext
        .drain(ciphertext.len() - tag_size..)
        .collect::<Vec<_>>();
    Ok((ciphertext, nonce, tag))
}
