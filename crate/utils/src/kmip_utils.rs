use crate::{
    crypto::{
        password_derivation::derive_key_from_password,
        wrap::{key_unwrap, key_wrap},
    },
    error::KmipUtilsError,
};

const WRAPPING_SECRET_LENGTH: usize = 32;

/// Wrap a key using a password
pub fn wrap_key_bytes(key: &[u8], wrapping_password: &str) -> Result<Vec<u8>, KmipUtilsError> {
    let wrapping_secret =
        derive_key_from_password::<WRAPPING_SECRET_LENGTH>(wrapping_password.as_bytes())?;
    key_wrap(key, &wrapping_secret).map_err(|e| KmipUtilsError::Default(e.to_string()))
}

/// Unwrap a key using a password
pub fn unwrap_key_bytes(key: &[u8], wrapping_password: &str) -> Result<Vec<u8>, KmipUtilsError> {
    let wrapping_secret =
        derive_key_from_password::<WRAPPING_SECRET_LENGTH>(wrapping_password.as_bytes())?;
    key_unwrap(key, &wrapping_secret).map_err(|e| KmipUtilsError::Default(e.to_string()))
}
