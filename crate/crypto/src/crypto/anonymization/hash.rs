use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose};
use cosmian_crypto_core::reexport::tiny_keccak::{Hasher as _, Sha3};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::AnoError;

// Available hashing methods
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum HashMethod {
    /// Represents the SHA2 hash method with an optional salt.
    SHA2(Option<Vec<u8>>),
    /// Represents the SHA3 hash method with an optional salt.
    SHA3(Option<Vec<u8>>),
    /// Represents the Argon2 hash method with a mandatory salt.
    Argon2(Vec<u8>),
}

impl HashMethod {
    /// `HashMethod` constructor for interfaces
    ///
    /// * `method` - The hash method to use. This can be one of the following:
    ///   SHA2, SHA3 or Argon2
    /// * `salt` - An optional salt to use. Required with Argon2
    pub fn new(hasher_method: &str, salt: Option<Vec<u8>>) -> Result<Self, AnoError> {
        match hasher_method {
            "SHA2" => Ok(Self::SHA2(salt)),
            "SHA3" => Ok(Self::SHA3(salt)),
            "Argon2" => salt.map_or_else(
                || {
                    Err(AnoError::AnonymizationError(
                        "Argon2 requires a salt value.".to_owned(),
                    ))
                },
                |salt| Ok(Self::Argon2(salt)),
            ),
            _ => Err(AnoError::AnonymizationError(
                "Not a valid hash method specified.".to_owned(),
            )),
        }
    }
}

#[derive(ZeroizeOnDrop)]
pub struct Hasher {
    method: HashMethod, // The selected hash method
}

impl Hasher {
    /// Creates a new `Hasher` instance using the specified hash method and an
    /// optional salt.
    ///
    /// # Arguments
    ///
    /// * `method` - The hash method to use. This can be one of the following:
    ///   * `SHA2` Fast and secure, but vulnerable to brute-force attacks.
    ///   * `SHA3` Secure and resistant to brute-force attacks, but slower than
    ///     SHA-256 and not as widely supported.
    ///   * `Argon2` Highly resistant to brute-force attacks, but can be slower
    ///     than other hash functions and may require more memory.
    #[must_use]
    pub const fn new(method: HashMethod) -> Self {
        Self { method }
    }

    /// Applies the chosen hash method to the input data.
    ///
    /// # Arguments
    ///
    /// * `data` - input string to be hashed.
    ///
    /// # Returns
    ///
    /// The base64-encoded hash string.
    pub fn apply_str(&self, data: &str) -> Result<String, AnoError> {
        let bytes = data.as_bytes();
        let hashed_bytes = self.apply_bytes(bytes)?;
        Ok(general_purpose::STANDARD.encode(hashed_bytes))
    }

    /// Applies the chosen hash method to the input data.
    ///
    /// # Arguments
    ///
    /// * `data` - input data to be hashed.
    ///
    /// # Returns
    ///
    /// The hash bytes.
    pub fn apply_bytes(&self, data: &[u8]) -> Result<[u8; 32], AnoError> {
        match &self.method {
            HashMethod::SHA2(salt) => {
                let mut hasher = Sha256::new();

                if let Some(salt_val) = salt.as_deref() {
                    hasher.update(salt_val);
                }
                hasher.update(data);
                // Convert hash output to a fixed size array
                let output = hasher.finalize().into();

                Ok(output)
            }
            HashMethod::SHA3(salt) => {
                let mut hasher = Sha3::v256();

                let mut output = [0u8; 32];
                if let Some(salt_val) = salt.as_deref() {
                    hasher.update(salt_val);
                }
                hasher.update(data);
                hasher.finalize(&mut output);

                Ok(output)
            }
            HashMethod::Argon2(salt) => {
                let mut output = [0u8; 32];
                Argon2::default().hash_password_into(data, salt, &mut output)?;

                Ok(output)
            }
        }
    }
}
