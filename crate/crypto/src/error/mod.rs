use std::num::TryFromIntError;

use cloudproof::reexport::crypto_core::{reexport::pkcs8, CryptoCoreError};
use thiserror::Error;

pub(crate) mod result;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Conversion Error: {0}")]
    ConversionError(String),

    #[error("{0}")]
    Default(String),

    #[error("Derivation error: {0}")]
    Derivation(String),

    #[error("Indexing slicing Error: {0}")]
    IndexingSlicing(String),

    #[error("Invalid size: {0}")]
    InvalidSize(String),

    #[error("Invalid tag: {0}")]
    InvalidTag(String),

    #[error("KMIP Error: {0}")]
    Kmip(String),

    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error("Object Not Found: {0}")]
    ObjectNotFound(String),

    #[error("OpenSSL Error: {0}")]
    OpenSSL(String),

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),

    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
}

impl From<Vec<u8>> for CryptoError {
    fn from(value: Vec<u8>) -> Self {
        Self::ConversionError(format!("Failed converting Vec<u8>: {value:?}"))
    }
}

impl From<cloudproof::reexport::cover_crypt::Error> for CryptoError {
    fn from(e: cloudproof::reexport::cover_crypt::Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<CryptoCoreError> for CryptoError {
    fn from(e: CryptoCoreError) -> Self {
        Self::Default(e.to_string())
    }
}

#[cfg(feature = "pyo3")]
impl From<pyo3::PyErr> for CryptoError {
    fn from(e: pyo3::PyErr) -> Self {
        Self::Default(e.to_string())
    }
}
#[cfg(feature = "pyo3")]
impl From<CryptoError> for pyo3::PyErr {
    fn from(e: CryptoError) -> Self {
        pyo3::exceptions::PyException::new_err(e.to_string())
    }
}

impl From<openssl::error::ErrorStack> for CryptoError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::OpenSSL(format!("Error: {e}. Details: {e:?}"))
    }
}

impl From<pkcs8::spki::Error> for CryptoError {
    fn from(e: pkcs8::spki::Error) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<pkcs8::Error> for CryptoError {
    fn from(e: pkcs8::Error) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<TryFromIntError> for CryptoError {
    fn from(e: TryFromIntError) -> Self {
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
            return ::core::result::Result::Err($crate::crypto_error!($msg));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::crypto_error!($fmt, $($arg)*));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! crypto_error {
    ($msg:literal) => {
        $crate::error::CryptoError::Default(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::error:CryptoError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error:CryptoError::Default(::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! crypto_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::crypto_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::crypto_error!($fmt, $($arg)*))
    };
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::CryptoError;

    #[test]
    fn test_crypto_error_interpolation() {
        let var = 42;
        let err = crypto_error!("interpolate {var}");
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

    fn bail() -> Result<(), CryptoError> {
        let var = 43;
        if true {
            crypto_bail!("interpolate {var}");
        }
        Ok(())
    }

    fn ensure() -> Result<(), CryptoError> {
        let var = 44;
        crypto_ensure!(false, "interpolate {var}");
        Ok(())
    }
}
