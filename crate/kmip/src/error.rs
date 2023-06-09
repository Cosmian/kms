use cloudproof::reexport::crypto_core::CryptoCoreError;
use thiserror::Error;

use crate::kmip::{kmip_operations::ErrorReason, ttlv::error::TtlvError};

#[derive(Error, Debug)]
pub enum KmipError {
    #[error("Invalid KMIP value: {0}: {1}")]
    InvalidKmipValue(ErrorReason, String),

    #[error("Invalid KMIP Object: {0}: {1}")]
    InvalidKmipObject(ErrorReason, String),

    #[error("Kmip Not Supported: {0}: {1}")]
    KmipNotSupported(ErrorReason, String),

    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error("{0}: {1}")]
    KmipError(ErrorReason, String),
}

impl KmipError {
    #[must_use]
    pub fn reason(&self, reason: ErrorReason) -> Self {
        match self {
            Self::KmipError(_r, e) => Self::KmipError(reason, e.clone()),
            e => Self::KmipError(reason, e.to_string()),
        }
    }
}

impl From<TtlvError> for KmipError {
    fn from(e: TtlvError) -> Self {
        Self::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}

impl From<serde_json::Error> for KmipError {
    fn from(e: serde_json::Error) -> Self {
        Self::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}

impl From<cloudproof::reexport::cover_crypt::Error> for KmipError {
    fn from(e: cloudproof::reexport::cover_crypt::Error) -> Self {
        Self::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}

impl From<CryptoCoreError> for KmipError {
    fn from(e: CryptoCoreError) -> Self {
        Self::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! kmip_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::KmipError::KmipError($crate::kmip::kmip_operations::ErrorReason::General_Failure, $msg.to_owned()));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::KmipError::KmipError($crate::kmip::kmip_operations::ErrorReason::General_Failure, format!($fmt, $($arg)*)));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! kmip_error {
    ($msg:literal $(,)?) => {
        $crate::error::KmipError::KmipError($crate::kmip::kmip_operations::ErrorReason::General_Failure, $msg.to_owned())
    };
    ($err:expr $(,)?) => ({
        $crate::error::KmipError::KmipError($crate::kmip::kmip_operations::ErrorReason::General_Failure, $err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::KmipError::KmipError($crate::kmip::kmip_operations::ErrorReason::General_Failure, format!($fmt, $($arg)*))
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! kmip_bail {
    ($msg:literal $(,)?) => {
        return ::core::result::Result::Err($crate::error::KmipError::KmipError($crate::kmip::kmip_operations::ErrorReason::General_Failure, $msg.to_owned()))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::error::KmipError::KmipError($crate::kmip::kmip_operations::ErrorReason::General_Failure, format!($fmt, $($arg)*)))
    };
}
