// This file exists to standardize key-derivation across all KMS crates
use argon2::Argon2;
use cloudproof::reexport::crypto_core::{FixedSizeCBytes, SymmetricKey};

use crate::error::KmipUtilsError;

/// The salt to use when deriving passwords in the KMS crate
pub const KMS_ARGON2_SALT: &[u8] = b"Default salt used in KMS crates";

/// Derive a key into a LENGTH bytes key using Argon 2
pub fn derive_key_from_password<const LENGTH: usize>(
    password: &[u8],
) -> Result<SymmetricKey<LENGTH>, KmipUtilsError> {
    let mut output_key_material = [0u8; LENGTH]; // Can be any desired size
    Argon2::default()
        .hash_password_into(password, KMS_ARGON2_SALT, &mut output_key_material)
        .map_err(|e| KmipUtilsError::Derivation(e.to_string()))?;
    //TODO Waiting or fix in crypto_core were from() should be implemented
    let sk = SymmetricKey::try_from_bytes(output_key_material)?;
    Ok(sk)
}
