use std::num::TryFromIntError;

use thiserror::Error;

use crate::{
    kmip_1_4::kmip_types::ResultReason, kmip_2_1::kmip_operations::ErrorReason, ttlv::TtlvError,
};

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
    InvalidKmip14Value(ResultReason, String),

    #[error("Invalid KMIP value: {0}: {1}")]
    InvalidKmip21Value(ErrorReason, String),

    #[error("Invalid KMIP 2.1 Object: {0}: {1}")]
    InvalidKmip21Object(ErrorReason, String),

    #[error("Invalid KMIP 1.4 Object: {0}: {1}")]
    InvalidKmip14Object(ResultReason, String),

    #[error("Invalid size: {0}")]
    InvalidSize(String),

    #[error("Invalid tag: {0}")]
    InvalidTag(String),

    #[error("{0}: {1}")]
    Kmip14(ResultReason, String),

    #[error("{0}: {1}")]
    Kmip21(ErrorReason, String),

    #[error("Kmip Not Supported: {0}: {1}")]
    Kmip21NotSupported(ErrorReason, String),

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
    pub fn reason_2_1(&self, reason: ErrorReason) -> Self {
        match self {
            Self::Kmip21(_r, e) => Self::Kmip21(reason, e.clone()),
            e => Self::Kmip21(reason, e.to_string()),
        }
    }

    #[must_use]
    pub fn reason_1_4(&self, reason: ResultReason) -> Self {
        match self {
            Self::Kmip21(_r, e) => Self::Kmip14(reason, e.clone()),
            e => Self::Kmip14(reason, e.to_string()),
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
        Self::Kmip21(ErrorReason::Codec_Error, e.to_string())
    }
}

#[cfg(feature = "pyo3")]
impl From<pyo3::PyErr> for KmipError {
    fn from(e: pyo3::PyErr) -> Self {
        Self::Kmip21(ErrorReason::Codec_Error, e.to_string())
    }
}
#[cfg(feature = "pyo3")]
impl From<KmipError> for pyo3::PyErr {
    fn from(e: KmipError) -> Self {
        pyo3::exceptions::PyException::new_err(e.to_string())
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
macro_rules! kmip_2_1_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::kmip_2_1_error!($msg));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::kmip_2_1_error!($fmt, $($arg)*));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! kmip_2_1_error {
    ($msg:literal) => {
        $crate::error::KmipError::Kmip21($crate::kmip_2_1::kmip_operations::ErrorReason::General_Failure, ::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::error::KmipError::Kmip21($crate::kmip_2_1::kmip_operations::ErrorReason::General_Failure, $err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::KmipError::Kmip21($crate::kmip_2_1::kmip_operations::ErrorReason::General_Failure, ::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! kmip_2_1_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::kmip_2_1_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::kmip_2_1_error!($fmt, $($arg)*))
    };
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::KmipError;

    #[test]
    fn test_kmip_error_interpolation() {
        let var = 42;
        let err = kmip_2_1_error!("interpolate {var}");
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
        kmip_2_1_bail!("interpolate {var}");
    }

    fn ensure() -> Result<(), KmipError> {
        let var = 44;
        kmip_2_1_ensure!(false, "interpolate {var}");
        Ok(())
    }
}
