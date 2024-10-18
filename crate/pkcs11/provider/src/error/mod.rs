use std::{array::TryFromSliceError, str::Utf8Error};

use cosmian_kmip::{kmip::kmip_operations::ErrorReason, KmipError};
use cosmian_kms_client::ClientError;
use thiserror::Error;

pub(crate) mod result;

// Each error type must have a corresponding HTTP status code (see `kmip_endpoint.rs`)
#[derive(Error, Debug)]
pub enum Pkcs11Error {
    // Conversion errors
    #[error("Conversion error: {0}")]
    Conversion(String),

    // PKCS11 Module errors
    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),

    // Any errors on KMIP format due to mistake of the user
    #[error("{0}: {1}")]
    KmipError(ErrorReason, String),

    // When the KMS client returns an error
    #[error("{0}")]
    KmsClientError(String),

    // When a user requests something not supported by the server
    #[error("Not Supported: {0}")]
    NotSupported(String),

    // Any errors related to a bad behavior of the server but not related to the user input
    #[error("Server error: {0}")]
    ServerError(String),

    // Other errors
    #[error("{0}")]
    Default(String),
}

impl Pkcs11Error {}

impl From<KmipError> for Pkcs11Error {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmipValue(r, s)
            | KmipError::InvalidKmipObject(r, s)
            | KmipError::KmipError(r, s) => Self::KmipError(r, s),
            KmipError::NotSupported(s)
            | KmipError::KmipNotSupported(_, s)
            | KmipError::Default(s)
            | KmipError::OpenSSL(s)
            | KmipError::InvalidSize(s)
            | KmipError::InvalidTag(s)
            | KmipError::Derivation(s)
            | KmipError::ConversionError(s)
            | KmipError::IndexingSlicing(s)
            | KmipError::ObjectNotFound(s) => Self::NotSupported(s),
        }
    }
}

impl From<cosmian_pkcs11_module::MError> for Pkcs11Error {
    fn from(e: cosmian_pkcs11_module::MError) -> Self {
        Self::Pkcs11(e.to_string())
    }
}

impl From<Pkcs11Error> for cosmian_pkcs11_module::MError {
    fn from(e: Pkcs11Error) -> Self {
        Self::Backend(Box::new(e))
    }
}

impl From<TryFromSliceError> for Pkcs11Error {
    fn from(e: TryFromSliceError) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<std::io::Error> for Pkcs11Error {
    fn from(e: std::io::Error) -> Self {
        Self::ServerError(e.to_string())
    }
}

impl From<serde_json::Error> for Pkcs11Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<Utf8Error> for Pkcs11Error {
    fn from(e: Utf8Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for Pkcs11Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<ClientError> for Pkcs11Error {
    fn from(e: ClientError) -> Self {
        Self::KmsClientError(e.to_string())
    }
}

impl From<std::fmt::Error> for Pkcs11Error {
    fn from(e: std::fmt::Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for Pkcs11Error {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<x509_cert::der::Error> for Pkcs11Error {
    fn from(e: x509_cert::der::Error) -> Self {
        Self::Conversion(e.to_string())
    }
}

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! pkcs11_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::pkcs11_error!($msg));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::pkcs11_error!($fmt, $($arg)*));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! pkcs11_error {
    ($msg:literal) => {
        $crate::error::Pkcs11Error::Default(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::error::Pkcs11Error::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::Pkcs11Error::Default(::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! pkcs11_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::pkcs11_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::pkcs11_error!($fmt, $($arg)*))
    };
}
