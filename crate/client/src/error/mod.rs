use std::io;

use cosmian_kmip::{
    kmip::{kmip_operations::ErrorReason, ttlv::error::TtlvError},
    KmipError,
};
use thiserror::Error;

pub(crate) mod result;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("Invalid conversion: {0}")]
    Conversion(String),

    #[error("{0}")]
    Default(String),

    #[error("Invalid KMIP Object: {0}: {1}")]
    InvalidKmipObject(ErrorReason, String),

    #[error("Invalid KMIP value: {0}: {1}")]
    InvalidKmipValue(ErrorReason, String),

    #[error("{0}: {1}")]
    KmipError(ErrorReason, String),

    #[error("Kmip Not Supported: {0}: {1}")]
    KmipNotSupported(ErrorReason, String),

    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error(transparent)]
    PemError(#[from] pem::PemError),

    #[error("Ratls Error: {0}")]
    RatlsError(String),

    #[error("REST Request Failed: {0}")]
    RequestFailed(String),

    #[error("REST Response Conversion Failed: {0}")]
    ResponseFailed(String),

    #[error("TTLV Error: {0}")]
    TtlvError(String),

    #[error("Unexpected Error: {0}")]
    UnexpectedError(String),

    #[error(transparent)]
    UrlError(#[from] url::ParseError),
}

impl From<TtlvError> for ClientError {
    fn from(e: TtlvError) -> Self {
        Self::TtlvError(e.to_string())
    }
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        Self::Default(format!("{e}: Details: {e:?}"))
    }
}

impl From<reqwest::header::InvalidHeaderValue> for ClientError {
    fn from(e: reqwest::header::InvalidHeaderValue) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<der::Error> for ClientError {
    fn from(e: der::Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<KmipError> for ClientError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmipValue(r, s) => Self::InvalidKmipValue(r, s),
            KmipError::InvalidKmipObject(r, s) => Self::InvalidKmipObject(r, s),
            KmipError::KmipNotSupported(r, s) => Self::KmipNotSupported(r, s),
            KmipError::KmipError(r, s) => Self::KmipError(r, s),
            KmipError::NotSupported(s)
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

impl From<cloudproof::reexport::crypto_core::CryptoCoreError> for ClientError {
    fn from(e: cloudproof::reexport::crypto_core::CryptoCoreError) -> Self {
        Self::UnexpectedError(e.to_string())
    }
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! client_error {
    ($msg:literal) => {
        $crate::ClientError::Default(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::ClientError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::ClientError::Default(::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! client_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::client_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::client_error!($fmt, $($arg)*))
    };
}
