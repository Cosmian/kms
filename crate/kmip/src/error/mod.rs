use std::num::TryFromIntError;

use thiserror::Error;

use crate::kmip_2_1::{kmip_operations::ErrorReason, ttlv::error::TtlvError};

pub(crate) mod result;

#[derive(Error, Debug)]
pub enum KmipError {
    #[error("Conversion Error: {0}")]
    ConversionError(String),

    #[error("{0}")]
    Default(String),

    #[error("Derivation error: {0}")]
    Derivation(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Deserialization: invalid size: {1}, expected: {0}")]
    DeserializationSize(usize, usize),

    #[error("Indexing slicing Error: {0}")]
    IndexingSlicing(String),

    #[error("Invalid KMIP value: {0}: {1}")]
    InvalidKmipValue(ErrorReason, String),

    #[error("Invalid KMIP Object: {0}: {1}")]
    InvalidKmipObject(ErrorReason, String),

    #[error("Invalid size: {0}")]
    InvalidSize(String),

    #[error("Invalid tag: {0}")]
    InvalidTag(String),

    #[error("{0}: {1}")]
    Kmip(ErrorReason, String),

    #[error("Kmip Not Supported: {0}: {1}")]
    KmipNotSupported(ErrorReason, String),

    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error("Object Not Found: {0}")]
    ObjectNotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),

    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
}

impl KmipError {
    #[must_use]
    pub fn reason(&self, reason: ErrorReason) -> Self {
        match self {
            Self::Kmip(_r, e) => Self::Kmip(reason, e.clone()),
            e => Self::Kmip(reason, e.to_string()),
        }
    }
}

impl From<Vec<u8>> for KmipError {
    fn from(value: Vec<u8>) -> Self {
        Self::ConversionError(format!("Failed converting Vec<u8>: {value:?}"))
    }
}

impl From<TtlvError> for KmipError {
    fn from(e: TtlvError) -> Self {
        Self::Kmip(ErrorReason::Codec_Error, e.to_string())
    }
}

impl From<TryFromIntError> for KmipError {
    fn from(e: TryFromIntError) -> Self {
        Self::ConversionError(e.to_string())
    }
}

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! kmip_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::kmip_error!($msg));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::kmip_error!($fmt, $($arg)*));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! kmip_error {
    ($msg:literal) => {
        $crate::error::KmipError::Kmip($crate::kmip_2_1::kmip_operations::ErrorReason::General_Failure, ::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::error::KmipError::Kmip($crate::kmip_2_1::kmip_operations::ErrorReason::General_Failure, $err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::KmipError::Kmip($crate::kmip_2_1::kmip_operations::ErrorReason::General_Failure, ::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! kmip_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::kmip_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::kmip_error!($fmt, $($arg)*))
    };
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::KmipError;

    #[test]
    fn test_kmip_error_interpolation() {
        let var = 42;
        let err = kmip_error!("interpolate {var}");
        assert_eq!("General_Failure: interpolate 42", err.to_string());

        let err = bail();
        assert_eq!(
            "General_Failure: interpolate 43",
            err.unwrap_err().to_string()
        );

        let err = ensure();
        assert_eq!(
            "General_Failure: interpolate 44",
            err.unwrap_err().to_string()
        );
    }

    fn bail() -> Result<(), KmipError> {
        let var = 43;
        kmip_bail!("interpolate {var}");
    }

    fn ensure() -> Result<(), KmipError> {
        let var = 44;
        kmip_ensure!(false, "interpolate {var}");
        Ok(())
    }
}
