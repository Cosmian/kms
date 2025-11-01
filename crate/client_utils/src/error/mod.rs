use std::num::TryFromIntError;

use cosmian_kmip::{KmipError, kmip_0::kmip_types::ErrorReason, ttlv::TtlvError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UtilsError {
    #[error("{0}")]
    Default(String),

    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error(transparent)]
    PemError(#[from] pem::PemError),

    #[error("{0}: {1}")]
    KmipError(ErrorReason, String),

    #[error("TTLV Error: {0}")]
    TtlvError(String),

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
}

impl From<Vec<u8>> for UtilsError {
    fn from(value: Vec<u8>) -> Self {
        Self::Default(format!("Failed converting Vec<u8>: {value:?}"))
    }
}

impl From<base64::DecodeError> for UtilsError {
    fn from(e: base64::DecodeError) -> Self {
        Self::Default(format!("Failed converting b64: {e:?}"))
    }
}

impl From<TtlvError> for UtilsError {
    fn from(e: TtlvError) -> Self {
        Self::TtlvError(e.to_string())
    }
}

impl From<TryFromIntError> for UtilsError {
    fn from(e: TryFromIntError) -> Self {
        Self::TtlvError(e.to_string())
    }
}

impl From<KmipError> for UtilsError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmip21Value(r, s)
            | KmipError::InvalidKmip21Object(r, s)
            | KmipError::Kmip21NotSupported(r, s)
            | KmipError::Kmip21(r, s) => Self::KmipError(r, s),
            KmipError::InvalidKmip14Value(r, s)
            | KmipError::InvalidKmip14Object(r, s)
            | KmipError::Kmip14(r, s) => Self::KmipError(r.into(), s),
            KmipError::NotSupported(s)
            | KmipError::Default(s)
            | KmipError::InvalidSize(s)
            | KmipError::InvalidTag(s)
            | KmipError::Derivation(s)
            | KmipError::ConversionError(s)
            | KmipError::IndexingSlicing(s)
            | KmipError::ObjectNotFound(s) => Self::NotSupported(s),
            KmipError::TryFromSliceError(e) => Self::Default(e.to_string()),
            KmipError::SerdeJsonError(e) => Self::SerdeJsonError(e),
            KmipError::RegexError(e) => Self::Default(e.to_string()),
            KmipError::Deserialization(e) | KmipError::Serialization(e) => {
                Self::KmipError(ErrorReason::Codec_Error, e)
            }
            KmipError::DeserializationSize(expected, actual) => Self::KmipError(
                ErrorReason::Codec_Error,
                format!("Deserialization: invalid size: {actual}, expected: {expected}"),
            ),
        }
    }
}
