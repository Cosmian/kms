use std::io;

use cosmian_kmip::{
    error::KmipError,
    kmip::{kmip_operations::ErrorReason, ttlv::error::TtlvError},
};
use http::header::InvalidHeaderValue;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KmsClientError {
    #[error("TTLV Error: {0}")]
    TtlvError(String),

    #[error("REST Request Failed: {0}")]
    RequestFailed(String),

    #[error("REST Response Failed: {0}")]
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
}

impl From<TtlvError> for KmsClientError {
    fn from(e: TtlvError) -> Self {
        Self::TtlvError(e.to_string())
    }
}

impl From<InvalidHeaderValue> for KmsClientError {
    fn from(e: InvalidHeaderValue) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<reqwest::Error> for KmsClientError {
    fn from(e: reqwest::Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<io::Error> for KmsClientError {
    fn from(e: io::Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<KmipError> for KmsClientError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmipValue(r, s) => Self::InvalidKmipValue(r, s),
            KmipError::InvalidKmipObject(r, s) => Self::InvalidKmipObject(r, s),
            KmipError::KmipNotSupported(r, s) => Self::KmipNotSupported(r, s),
            KmipError::NotSupported(s) => Self::NotSupported(s),
            KmipError::KmipError(r, s) => Self::KmipError(r, s),
        }
    }
}
