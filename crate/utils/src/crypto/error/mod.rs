use cloudproof::reexport::crypto_core::CryptoCoreError;
use cosmian_kmip::{error::KmipError, kmip::kmip_operations::ErrorReason};
use thiserror::Error;

pub mod result;

#[derive(Error, Debug)]
pub enum CryptoError {
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

    #[error("{0}")]
    Default(String),
}

impl From<std::array::TryFromSliceError> for CryptoError {
    fn from(value: std::array::TryFromSliceError) -> Self {
        Self::ConversionError(value.to_string())
    }
}

impl From<KmipError> for CryptoError {
    fn from(value: KmipError) -> Self {
        match value {
            KmipError::InvalidKmipValue(error_reason, value) => {
                CryptoError::Kmip(error_reason, value)
            }
            KmipError::InvalidKmipObject(error_reason, value) => {
                CryptoError::Kmip(error_reason, value)
            }
            KmipError::KmipNotSupported(error_reason, value) => {
                CryptoError::Kmip(error_reason, value)
            }
            KmipError::NotSupported(value) => {
                CryptoError::Kmip(ErrorReason::Feature_Not_Supported, value)
            }
            KmipError::KmipError(error_reason, value) => CryptoError::Kmip(error_reason, value),
        }
    }
}

impl From<CryptoCoreError> for CryptoError {
    fn from(value: CryptoCoreError) -> Self {
        Self::Default(value.to_string())
    }
}

impl From<serde_json::Error> for CryptoError {
    fn from(e: serde_json::Error) -> Self {
        CryptoError::ConversionError(e.to_string())
    }
}

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! crypto_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::crypto::error::CryptoError::Default($msg.to_owned()));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::crypto::error::CryptoError::Default(format!($fmt, $($arg)*)));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! crypto_error {
    ($msg:literal) => {
        $crate::crypto::error::CryptoError::Default(format!($msg))
    };
    ($err:expr $(,)?) => ({
        $crate::crypto::error::CryptoError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::crypto::error::CryptoError::Default(format!($fmt, $($arg)*))
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! crypto_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err( $crate::crypto::error::CryptoError::Default(format!($msg)))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::crypto::error::CryptoError::Default(format!($fmt, $($arg)*)))
    };
}
