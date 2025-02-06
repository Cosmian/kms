use std::fmt::Display;
use base64::{engine::general_purpose, Engine as _};
use cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
use strum::EnumString;

use crate::error::UtilsError;

#[derive(Debug, Clone, Copy, Default, EnumString)]
pub enum SymmetricAlgorithm {
    #[cfg(not(feature = "fips"))]
    Chacha20,
    #[default]
    Aes,
    Sha3,
    Shake,
}

impl Display for SymmetricAlgorithm {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      match self {
          #[cfg(not(feature = "fips"))]
          Self::Chacha20 => write!(f, "chacha20"),
          Self::Aes => write!(f, "aes"),
          Self::Sha3 => write!(f, "sha3"),
          Self::Shake => write!(f, "shake"),
      }
  }
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
        #[cfg(not(feature = "fips"))]
        SymmetricAlgorithm::Chacha20 => CryptographicAlgorithm::ChaCha20,
        SymmetricAlgorithm::Sha3 => match number_of_bits {
            224 => CryptographicAlgorithm::SHA3224,
            256 => CryptographicAlgorithm::SHA3256,
            384 => CryptographicAlgorithm::SHA3384,
            512 => CryptographicAlgorithm::SHA3512,
            _ => Err(UtilsError::Default(format!(
                "invalid number of bits for sha3 {}",
                number_of_bits
            )))?,
        },
        SymmetricAlgorithm::Shake => match number_of_bits {
            128 => CryptographicAlgorithm::SHAKE128,
            256 => CryptographicAlgorithm::SHAKE256,
            _ => Err(UtilsError::Default(format!(
                "invalid number of bits for shake {}",
                number_of_bits
            )))?,
        },
    };
    Ok((number_of_bits, key_bytes, algorithm))
}
