use std::fmt::Display;

use base64::{Engine as _, engine::general_purpose};
use clap::ValueEnum;
use cosmian_kmip::kmip_2_1::kmip_types::{CryptographicAlgorithm, RecommendedCurve};
use strum::EnumString;

use crate::error::UtilsError;

#[derive(Default, Debug, Clone, Copy, EnumString, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum Curve {
    #[cfg(feature = "non-fips")]
    NistP192,
    NistP224,
    #[default]
    NistP256,
    NistP384,
    NistP521,
    #[cfg(feature = "non-fips")]
    X25519,
    #[cfg(feature = "non-fips")]
    Ed25519,
    #[cfg(feature = "non-fips")]
    X448,
    #[cfg(feature = "non-fips")]
    Ed448,
    #[cfg(feature = "non-fips")]
    Secp256k1,
    #[cfg(feature = "non-fips")]
    Secp224k1,
}

impl Display for Curve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "non-fips")]
            Self::NistP192 => write!(f, "NIST P-192"),
            Self::NistP224 => write!(f, "NIST P-224"),
            Self::NistP256 => write!(f, "NIST P-256"),
            Self::NistP384 => write!(f, "NIST P-384"),
            Self::NistP521 => write!(f, "NIST P-521"),
            #[cfg(feature = "non-fips")]
            Self::X25519 => write!(f, "X25519"),
            #[cfg(feature = "non-fips")]
            Self::Ed25519 => write!(f, "Ed25519"),
            #[cfg(feature = "non-fips")]
            Self::X448 => write!(f, "X448"),
            #[cfg(feature = "non-fips")]
            Self::Ed448 => write!(f, "Ed448"),
            #[cfg(feature = "non-fips")]
            Self::Secp256k1 => write!(f, "SECP256k1"),
            #[cfg(feature = "non-fips")]
            Self::Secp224k1 => write!(f, "SECP224k1"),
        }
    }
}

impl From<Curve> for RecommendedCurve {
    fn from(curve: Curve) -> Self {
        match curve {
            #[cfg(feature = "non-fips")]
            Curve::NistP192 => Self::P192,
            Curve::NistP224 => Self::P224,
            Curve::NistP256 => Self::P256,
            Curve::NistP384 => Self::P384,
            Curve::NistP521 => Self::P521,
            #[cfg(feature = "non-fips")]
            Curve::X25519 => Self::CURVE25519,
            #[cfg(feature = "non-fips")]
            Curve::Ed25519 => Self::CURVEED25519,
            #[cfg(feature = "non-fips")]
            Curve::X448 => Self::CURVE448,
            #[cfg(feature = "non-fips")]
            Curve::Ed448 => Self::CURVEED448,
            #[cfg(feature = "non-fips")]
            Curve::Secp256k1 => Self::SECP256K1,
            #[cfg(feature = "non-fips")]
            Curve::Secp224k1 => Self::SECP224K1,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, EnumString, ValueEnum)]
pub enum SymmetricAlgorithm {
    #[cfg(feature = "non-fips")]
    Chacha20,
    #[default]
    Aes,
    Sha3,
    Shake,
}

impl Display for SymmetricAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "non-fips")]
            Self::Chacha20 => write!(f, "Chacha20"),
            Self::Aes => write!(f, "Aes"),
            Self::Sha3 => write!(f, "Sha3"),
            Self::Shake => write!(f, "Shake"),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, EnumString, ValueEnum)]
pub enum SecretDataType {
    Password,
    #[default]
    Seed,
}

pub fn prepare_sym_key_elements(
    number_of_bits: Option<usize>,
    wrap_key_b64: &Option<String>,
    algorithm: SymmetricAlgorithm,
) -> Result<(usize, Option<Vec<u8>>, CryptographicAlgorithm), UtilsError> {
    let mut key_bytes = None;
    let number_of_bits = if let Some(key_b64) = &wrap_key_b64 {
        let bytes = general_purpose::STANDARD.decode(key_b64)?;
        let number_of_bits = bytes.len() * 8;
        key_bytes = Some(bytes);
        number_of_bits
    } else {
        number_of_bits.unwrap_or(256)
    };
    let algorithm = match algorithm {
        SymmetricAlgorithm::Aes => CryptographicAlgorithm::AES,
        #[cfg(feature = "non-fips")]
        SymmetricAlgorithm::Chacha20 => CryptographicAlgorithm::ChaCha20,
        SymmetricAlgorithm::Sha3 => match number_of_bits {
            224 => CryptographicAlgorithm::SHA3224,
            256 => CryptographicAlgorithm::SHA3256,
            384 => CryptographicAlgorithm::SHA3384,
            512 => CryptographicAlgorithm::SHA3512,
            _ => {
                return Err(UtilsError::Default(format!(
                    "invalid number of bits for sha3 {number_of_bits}"
                )));
            }
        },
        SymmetricAlgorithm::Shake => match number_of_bits {
            128 => CryptographicAlgorithm::SHAKE128,
            256 => CryptographicAlgorithm::SHAKE256,
            _ => {
                return Err(UtilsError::Default(format!(
                    "invalid number of bits for shake {number_of_bits}"
                )));
            }
        },
    };
    Ok((number_of_bits, key_bytes, algorithm))
}
