use num_bigint::BigUint;
use num_traits::ToPrimitive;

use super::{FPEError, Integer};

/// Struct representing a floating point number.
pub struct Float {
    number: Integer,
}

impl Float {
    /// Instantiates a new `Float` struct.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `Float` if successful, otherwise returns an
    /// error `AnoError`.
    pub fn instantiate() -> Result<Self, FPEError> {
        Ok(Self {
            number: Integer::instantiate(16, 16)?,
        })
    }

    /// Encrypts the floating point value.
    ///
    /// # Arguments
    ///
    /// * `value` - A floating point value to be encrypted.
    /// * `key` - A 32-byte encryption key.
    /// * `tweak` - A tweak value.
    ///
    /// # Returns
    ///
    /// Returns the encrypted floating point value if successful, otherwise
    /// returns an error `AnoError`.
    pub fn encrypt(&self, key: &[u8; 32], tweak: &[u8], value: f64) -> Result<f64, FPEError> {
        // Convert the floating point value to a BigUint
        let big_uint = BigUint::from(value.to_bits());
        // Encrypt the BigUint
        let ciphertext = self.number.encrypt_big(key, tweak, &big_uint)?;
        // Convert the encrypted BigUint to u64
        let num_bits = ciphertext.to_u64().ok_or_else(|| {
            FPEError::ConversionError(format!(
                "Failed converting the ciphertext value: {ciphertext}, to a number of bits as an \
                 u64"
            ))
        })?;
        // Convert the u64 to f64
        Ok(f64::from_bits(num_bits))
    }

    /// Decrypts the floating point value.
    ///
    /// # Arguments
    ///
    /// * `value` - A floating point value to be decrypted.
    /// * `key` - A 32-byte decryption key.
    /// * `tweak` - A tweak value.
    ///
    /// # Returns
    ///
    /// Returns the decrypted floating point value if successful, otherwise
    /// returns an error `AnoError`.
    pub fn decrypt(&self, key: &[u8; 32], tweak: &[u8], value: f64) -> Result<f64, FPEError> {
        // Convert the floating point value to a BigUint
        let big_uint = BigUint::from(value.to_bits());
        // Decrypt the BigUint
        let ciphertext = self.number.decrypt_big(key, tweak, &big_uint)?;
        // Convert the decrypted BigUint to u64
        let num_bits = ciphertext.to_u64().ok_or_else(|| {
            FPEError::ConversionError(format!(
                "Failed converting the ciphertext value: {ciphertext}, to a number of bits as an \
                 u64"
            ))
        })?;
        Ok(f64::from_bits(num_bits))
    }
}
