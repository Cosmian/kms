use cloudproof::reexport::crypto_core::kdf;
use cosmian_kmip::{error::KmipError, kmip::kmip_operations::ErrorReason};

use crate::crypto::key_wrapping_rfc_5649;

const WRAPPING_SECRET_LENGTH: usize = 32;

/// Wrap a key using a password
pub fn wrap_key_bytes(key: &[u8], wrapping_password: &str) -> Result<Vec<u8>, KmipError> {
    let wrapping_secret = kdf!(WRAPPING_SECRET_LENGTH, wrapping_password.as_bytes());
    key_wrapping_rfc_5649::wrap(key, &wrapping_secret)
        .map_err(|e| KmipError::KmipError(ErrorReason::Invalid_Data_Type, e.to_string()))
}

/// Unwrap a key using a password
pub fn unwrap_key_bytes(key: &[u8], wrapping_password: &str) -> Result<Vec<u8>, KmipError> {
    let wrapping_secret = kdf!(WRAPPING_SECRET_LENGTH, wrapping_password.as_bytes());
    key_wrapping_rfc_5649::unwrap(key, &wrapping_secret)
        .map_err(|e| KmipError::KmipError(ErrorReason::Invalid_Data_Type, e.to_string()))
}
