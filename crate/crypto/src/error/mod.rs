use cloudproof::reexport::crypto_core::{reexport::pkcs8, CryptoCoreError};
use cosmian_kmip::{error::KmipError, kmip::kmip_operations::ErrorReason};
use cosmian_kms_utils::error::KmipUtilsError;
use thiserror::Error;

pub mod result;

#[derive(Error, Debug)]
pub enum KmsCryptoError {
    #[error("Conversion Error: {0}")]
    ConversionError(String),

    #[error("Invalid size: {0}")]
    InvalidSize(String),

    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error("Derivation error: {0}")]
    Derivation(String),

    #[error("Kmip: {0}: {1}")]
    Kmip(ErrorReason, String),

    #[error("Invalid tag: {0}")]
    InvalidTag(String),

    #[error("{0}")]
    Default(String),
}

impl From<Vec<u8>> for KmsCryptoError {
    fn from(value: Vec<u8>) -> Self {
        Self::ConversionError(format!("Failed converting Vec<u8>: {value:?}"))
    }
}
impl From<std::array::TryFromSliceError> for KmsCryptoError {
    fn from(value: std::array::TryFromSliceError) -> Self {
        Self::ConversionError(value.to_string())
    }
}

impl From<openssl::error::ErrorStack> for KmsCryptoError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::NotSupported(e.to_string())
    }
}

impl From<KmipError> for KmsCryptoError {
    fn from(value: KmipError) -> Self {
        match value {
            KmipError::InvalidKmipValue(error_reason, value) => Self::Kmip(error_reason, value),
            KmipError::InvalidKmipObject(error_reason, value) => Self::Kmip(error_reason, value),
            KmipError::KmipNotSupported(error_reason, value) => Self::Kmip(error_reason, value),
            KmipError::NotSupported(value) => Self::Kmip(ErrorReason::Feature_Not_Supported, value),
            KmipError::KmipError(error_reason, value) => Self::Kmip(error_reason, value),
            KmipError::Default(value) => Self::NotSupported(value),
            KmipError::OpenSSL(value) => Self::NotSupported(value),
        }
    }
}

impl From<KmipUtilsError> for KmsCryptoError {
    fn from(value: KmipUtilsError) -> Self {
        match value {
            KmipUtilsError::ConversionError(s) => KmsCryptoError::ConversionError(s),
            KmipUtilsError::InvalidSize(s) => KmsCryptoError::InvalidSize(s),
            KmipUtilsError::NotSupported(s) => KmsCryptoError::NotSupported(s),
            KmipUtilsError::Derivation(s) => KmsCryptoError::Derivation(s),
            KmipUtilsError::Kmip(er, s) => KmsCryptoError::Kmip(er, s),
            KmipUtilsError::InvalidTag(s) => KmsCryptoError::InvalidTag(s),
            KmipUtilsError::Default(s) => KmsCryptoError::Default(s),
        }
    }
}

impl From<CryptoCoreError> for KmsCryptoError {
    fn from(value: CryptoCoreError) -> Self {
        Self::Default(value.to_string())
    }
}

impl From<serde_json::Error> for KmsCryptoError {
    fn from(e: serde_json::Error) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<pkcs8::spki::Error> for KmsCryptoError {
    fn from(e: pkcs8::spki::Error) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<pkcs8::Error> for KmsCryptoError {
    fn from(e: pkcs8::Error) -> Self {
        Self::ConversionError(e.to_string())
    }
}

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! crypto_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::KmsCryptoError::Default($msg.to_owned()));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::KmsCryptoError::Default(format!($fmt, $($arg)*)));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! kms_crypto_error {
    ($msg:literal) => {
        $crate::error::KmsCryptoError::Default(format!($msg))
    };
    ($err:expr $(,)?) => ({
        $crate::error::KmsCryptoError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::KmsCryptoError::Default(format!($fmt, $($arg)*))
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! kms_crypto_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err( $crate::error::KmsCryptoError::Default(format!($msg)))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::error::KmsCryptoError::Default(format!($fmt, $($arg)*)))
    };
}
