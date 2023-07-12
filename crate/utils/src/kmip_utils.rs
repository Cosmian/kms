use cloudproof::reexport::crypto_core::{kdf256, key_unwrap, key_wrap};
use cosmian_kmip::{error::KmipError, kmip::kmip_operations::ErrorReason};

const WRAPPING_SECRET_LENGTH: usize = 32;

/// Wrap a key using a password
pub fn wrap_key_bytes(key: &[u8], wrapping_password: &str) -> Result<Vec<u8>, KmipError> {
    let mut wrapping_secret = [0; WRAPPING_SECRET_LENGTH];
    kdf256!(&mut wrapping_secret, wrapping_password.as_bytes());
    key_wrap(key, &wrapping_secret)
        .map_err(|e| KmipError::KmipError(ErrorReason::Invalid_Data_Type, e.to_string()))
}

/// Unwrap a key using a password
pub fn unwrap_key_bytes(key: &[u8], wrapping_password: &str) -> Result<Vec<u8>, KmipError> {
    let mut wrapping_secret = [0; WRAPPING_SECRET_LENGTH];
    kdf256!(&mut wrapping_secret, wrapping_password.as_bytes());
    key_unwrap(key, &wrapping_secret)
        .map_err(|e| KmipError::KmipError(ErrorReason::Invalid_Data_Type, e.to_string()))
}
