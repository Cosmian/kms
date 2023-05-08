// This file exists to standardize key-derivation across all KMS crates
use argon2::Argon2;

use super::error::CryptoError;

/// The salt to use when deriving passwords in the KMS crate
pub const KMS_ARGON2_SALT: &[u8] = b"Default salt used in KMS crates";

/// Derive a password into a 256 bit key using Argon 2
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut output_key_material = [0u8; 32]; // Can be any desired size
    Argon2::default()
        .hash_password_into(password, salt, &mut output_key_material)
        .map_err(|e| CryptoError::Derivation(e.to_string()))?;
    Ok(output_key_material)
}
