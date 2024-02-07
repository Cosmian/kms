use std::io;

use cosmian_kmip::{
    error::KmipError,
    kmip::{kmip_operations::ErrorReason, ttlv::error::TtlvError},
};
use http::header::InvalidHeaderValue;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RestClientError {
    #[error("TTLV Error: {0}")]
    TtlvError(String),

    #[error("REST Request Failed: {0}")]
    RequestFailed(String),

    #[error("REST Response Conversion Failed: {0}")]
    ResponseFailed(String),

    #[error("Unexpected Error: {0}")]
    UnexpectedError(String),

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

    #[error("{0}")]
    Default(String),

    #[error("Ratls Error: {0}")]
    RatlsError(String),

    #[error(transparent)]
    UrlError(#[from] url::ParseError),

    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),
}

impl From<TtlvError> for RestClientError {
    fn from(e: TtlvError) -> Self {
        Self::TtlvError(e.to_string())
    }
}

impl From<InvalidHeaderValue> for RestClientError {
    fn from(e: InvalidHeaderValue) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<reqwest::Error> for RestClientError {
    fn from(e: reqwest::Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<io::Error> for RestClientError {
    fn from(e: io::Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<KmipError> for RestClientError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmipValue(r, s) => Self::InvalidKmipValue(r, s),
            KmipError::InvalidKmipObject(r, s) => Self::InvalidKmipObject(r, s),
            KmipError::KmipNotSupported(r, s) => Self::KmipNotSupported(r, s),
            KmipError::NotSupported(s) => Self::NotSupported(s),
            KmipError::KmipError(r, s) => Self::KmipError(r, s),
            KmipError::Default(s) => Self::NotSupported(s),
            KmipError::OpenSSL(s) => Self::NotSupported(s),
            KmipError::InvalidTag(s) => Self::NotSupported(s),
            KmipError::InvalidSize(s) => Self::NotSupported(s),
            KmipError::Derivation(s) => Self::NotSupported(s),
            KmipError::ConversionError(s) => Self::NotSupported(s),
        }
    }
}
