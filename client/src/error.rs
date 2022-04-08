use cosmian_kmip::{
    error::KmipError,
    kmip::{kmip_operations::ErrorReason, ttlv::error::TtlvError},
};
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
}

impl From<TtlvError> for KmsClientError {
    fn from(e: TtlvError) -> Self {
        KmsClientError::TtlvError(e.to_string())
    }
}

impl From<KmipError> for KmsClientError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmipValue(r, s) => KmsClientError::InvalidKmipValue(r, s),
            KmipError::InvalidKmipObject(r, s) => KmsClientError::InvalidKmipObject(r, s),
            KmipError::KmipNotSupported(r, s) => KmsClientError::KmipNotSupported(r, s),
            KmipError::NotSupported(s) => KmsClientError::NotSupported(s),
            KmipError::KmipError(r, s) => KmsClientError::KmipError(r, s),
        }
    }
}
