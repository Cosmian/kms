use std::num::TryFromIntError;

use cloudproof::reexport::crypto_core::{reexport::pkcs8, CryptoCoreError};
use thiserror::Error;

use crate::kmip::{kmip_operations::ErrorReason, ttlv::error::TtlvError};

pub(crate) mod result;

#[derive(Error, Debug)]
pub enum KmipError {
    #[error("Invalid KMIP value: {0}: {1}")]
    InvalidKmipValue(ErrorReason, String),

    #[error("Invalid KMIP Object: {0}: {1}")]
    InvalidKmipObject(ErrorReason, String),

    #[error("Invalid size: {0}")]
    InvalidSize(String),

    #[error("Invalid tag: {0}")]
    InvalidTag(String),

    #[error("Derivation error: {0}")]
    Derivation(String),

    #[error("Kmip Not Supported: {0}: {1}")]
    KmipNotSupported(ErrorReason, String),

    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error("{0}: {1}")]
    KmipError(ErrorReason, String),

    #[error("Conversion Error: {0}")]
    ConversionError(String),

    #[error("Indexing slicing Error: {0}")]
    IndexingSlicing(String),

    #[error("{0}")]
    Default(String),

    #[error("OpenSSL Error: {0}")]
    OpenSSL(String),

    #[error("Object Not Found: {0}")]
    ObjectNotFound(String),

    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
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

impl From<Vec<u8>> for KmipError {
    fn from(value: Vec<u8>) -> Self {
        Self::ConversionError(format!("Failed converting Vec<u8>: {value:?}"))
    }
}

impl From<TtlvError> for KmipError {
    fn from(e: TtlvError) -> Self {
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

#[cfg(feature = "pyo3")]
impl From<pyo3::PyErr> for KmipError {
    fn from(e: pyo3::PyErr) -> Self {
        Self::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}
#[cfg(feature = "pyo3")]
impl From<KmipError> for pyo3::PyErr {
    fn from(e: KmipError) -> Self {
        pyo3::exceptions::PyException::new_err(e.to_string())
    }
}

impl From<openssl::error::ErrorStack> for KmipError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL(format!("Error: {e}. Details: {e:?}"))
    }
}

impl From<pkcs8::spki::Error> for KmipError {
    fn from(e: pkcs8::spki::Error) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<pkcs8::Error> for KmipError {
    fn from(e: pkcs8::Error) -> Self {
        Self::ConversionError(e.to_string())
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
        $crate::error::KmipError::KmipError($crate::kmip::kmip_operations::ErrorReason::General_Failure, ::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::error::KmipError::KmipError($crate::kmip::kmip_operations::ErrorReason::General_Failure, $err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::KmipError::KmipError($crate::kmip::kmip_operations::ErrorReason::General_Failure, ::core::format_args!($fmt, $($arg)*).to_string())
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
        if true {
            kmip_bail!("interpolate {var}");
        }
        Ok(())
    }

    fn ensure() -> Result<(), KmipError> {
        let var = 44;
        kmip_ensure!(false, "interpolate {var}");
        Ok(())
    }
}
