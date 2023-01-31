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
            KmipError::KmipError(_r, e) => KmipError::KmipError(reason, e.clone()),
            e => KmipError::KmipError(reason, e.to_string()),
        }
    }
}

impl From<TtlvError> for KmipError {
    fn from(e: TtlvError) -> Self {
        KmipError::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}

impl From<serde_json::Error> for KmipError {
    fn from(e: serde_json::Error) -> Self {
        KmipError::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}

impl From<cosmian_cover_crypt::Error> for KmipError {
    fn from(e: cosmian_cover_crypt::Error) -> Self {
        KmipError::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}
