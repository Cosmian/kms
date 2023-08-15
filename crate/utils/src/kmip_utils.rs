use argon2::{password_hash::Salt, PasswordHasher};
use cloudproof::reexport::crypto_core::{key_unwrap, key_wrap};
use cosmian_kmip::{error::KmipError, kmip::kmip_operations::ErrorReason};

/// The vendor ID to use for Cosmian specific attributes
pub const VENDOR_ID_COSMIAN: &str = "cosmian";

const WRAPPING_SECRET_LENGTH: usize = 32;
const SALT: &str = "Y29zbWlhbl9rbXNfc2VydmVy";

/// Wrap a key using a password
pub fn wrap_key_bytes(key: &[u8], wrapping_password: &str) -> Result<Vec<u8>, KmipError> {
    let wrapping_secret = argon2_hash(wrapping_password)?;
    key_wrap(key, &wrapping_secret)
        .map_err(|e| KmipError::KmipError(ErrorReason::Invalid_Data_Type, e.to_string()))
}

/// Unwrap a key using a password
pub fn unwrap_key_bytes(key: &[u8], wrapping_password: &str) -> Result<Vec<u8>, KmipError> {
    let wrapping_secret = argon2_hash(wrapping_password)?;
    key_unwrap(key, &wrapping_secret)
        .map_err(|e| KmipError::KmipError(ErrorReason::Invalid_Data_Type, e.to_string()))
}

fn argon2_hash(password: &str) -> Result<Vec<u8>, KmipError> {
    let argon2 = argon2::Argon2::default();
    let salt = Salt::from_b64(SALT).map_err(|_| {
        KmipError::KmipError(
            ErrorReason::Invalid_Data_Type,
            "invalid salt for argon2".to_string(),
        )
    })?;
    let hash = argon2
        .hash_password(password.as_bytes(), salt)
        .map_err(|_| {
            KmipError::KmipError(
                ErrorReason::Invalid_Data_Type,
                "invalid password for argon2".to_string(),
            )
        })?;
    Ok(hash
        .hash
        .expect("hash should be present")
        .as_bytes()
        .to_vec())
}
