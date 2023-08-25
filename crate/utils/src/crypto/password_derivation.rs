// This file exists to standardize key-derivation across all KMS crates
use argon2::Argon2;

use crate::error::KmipUtilsError;

/// The salt to use when deriving passwords in the KMS crate
pub const KMS_ARGON2_SALT: &[u8] = b"Default salt used in KMS crates";

/// Derive a key into a LENGTH bytes key using Argon 2
pub fn derive_key_from_password<const LENGTH: usize>(
    password: &[u8],
    salt: &[u8],
) -> Result<[u8; LENGTH], KmipUtilsError> {
    let mut output_key_material = [0u8; LENGTH]; // Can be any desired size
    Argon2::default()
        .hash_password_into(password, salt, &mut output_key_material)
        .map_err(|e| KmipUtilsError::Derivation(e.to_string()))?;
    Ok(output_key_material)
}
