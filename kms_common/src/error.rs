use thiserror::Error;

use crate::kmip::{kmip_operations::ErrorReason, ttlv::error::TtlvError};

#[derive(Error, Debug)]
pub enum KmsCommonError {
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

impl KmsCommonError {
    #[must_use]
    pub fn reason(&self, reason: ErrorReason) -> Self {
        match self {
            KmsCommonError::KmipError(_r, e) => KmsCommonError::KmipError(reason, e.clone()),
            e => KmsCommonError::KmipError(reason, e.to_string()),
        }
    }
}

impl From<TtlvError> for KmsCommonError {
    fn from(e: TtlvError) -> Self {
        KmsCommonError::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}
