use zeroize::Zeroizing;

use crate::{
    crypto::{
        password_derivation::derive_key_from_password,
        symmetric::rfc5649::{rfc5649_unwrap, rfc5649_wrap},
    },
    error::KmipUtilsError,
};

const WRAPPING_SECRET_LENGTH: usize = 32;

/// Wrap a key using a password
pub fn wrap_key_bytes(key: &[u8], wrapping_password: &str) -> Result<Vec<u8>, KmipUtilsError> {
    let wrapping_secret =
        derive_key_from_password::<WRAPPING_SECRET_LENGTH>(wrapping_password.as_bytes())?;
    rfc5649_wrap(key, wrapping_secret.as_ref()).map_err(|e| KmipUtilsError::Default(e.to_string()))
}

/// Unwrap a key using a password
pub fn unwrap_key_bytes(
    key: &[u8],
    wrapping_password: &str,
) -> Result<Zeroizing<Vec<u8>>, KmipUtilsError> {
    let wrapping_secret =
        derive_key_from_password::<WRAPPING_SECRET_LENGTH>(wrapping_password.as_bytes())?;
    rfc5649_unwrap(key, wrapping_secret.as_ref()).map_err(|e| KmipUtilsError::Default(e.to_string()))
}
