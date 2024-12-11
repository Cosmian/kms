use std::array::TryFromSliceError;

use cloudproof::reexport::crypto_core::CryptoCoreError;
use cloudproof_findex::implementations::redis::FindexRedisError;
use cosmian_kmip::{kmip::kmip_operations::ErrorReason, KmipError};
use cosmian_kms_interfaces::InterfaceError;
use redis::ErrorKind;
use thiserror::Error;

// Each error type must have a corresponding HTTP status code (see `kmip_endpoint.rs`)
#[derive(Error, Debug, Clone)]
pub enum DbError {
    // When a conversion from/to bytes
    #[error("Conversion Error: {0}")]
    ConversionError(String),

    // Any actions of the user that is not allowed
    #[error("REST client connection error: {0}")]
    ClientConnectionError(String),

    // A failure originating from one of the cryptographic algorithms
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),

    // Error related to X509 Certificate
    #[error("Certificate error: {0}")]
    Certificate(String),

    // Any errors related to a bad behavior of the DB but not related to the user input
    #[error("Database Error: {0}")]
    DatabaseError(String),

    // Default error
    #[error("{0}")]
    Default(String),

    #[error("Findex Error: {0}")]
    Findex(String),

    // When a user requests something, which is nonsense
    #[error("Inconsistent operation: {0}")]
    InconsistentOperation(String),

    // Missing arguments in the request
    #[error("Invalid Request: {0}")]
    InvalidRequest(String),

    // When a user requests an item which does not exist
    #[error("Item not found: {0}")]
    ItemNotFound(String),

    // Any errors on KMIP format due to mistake of the user
    #[error("{0}: {1}")]
    KmipError(ErrorReason, String),

    // When a user requests something not supported by the server
    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error("Proteccio error: {0}")]
    Proteccio(String),

    #[error("Redis Error: {0}")]
    Redis(String),

    // When a user requests an endpoint which does not exist
    #[error("Not Supported route: {0}")]
    RouteNotFound(String),

    // Any errors related to a bad behavior of the server but not related to the user input
    #[error("Unexpected server error: {0}")]
    ServerError(String),

    #[error("Ext. store error: {0}")]
    Store(String),

    // Any actions of the user which is not allowed
    #[error("Access denied: {0}")]
    Unauthorized(String),

    // When a user requests with placeholder id arg.
    #[error("This KMIP server does not yet support place holder id")]
    UnsupportedPlaceholder,

    #[error("Invalid URL: {0}")]
    UrlError(String),

    // When a user requests with protection masks arg.
    #[error("This KMIP server does not yet support protection masks")]
    UnsupportedProtectionMasks,
}

impl From<std::string::FromUtf8Error> for DbError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<std::num::TryFromIntError> for DbError {
    fn from(e: std::num::TryFromIntError) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<sqlx::Error> for DbError {
    fn from(e: sqlx::Error) -> Self {
        Self::DatabaseError(e.to_string())
    }
}

impl From<std::io::Error> for DbError {
    fn from(e: std::io::Error) -> Self {
        Self::ServerError(e.to_string())
    }
}

impl From<serde_json::Error> for DbError {
    fn from(e: serde_json::Error) -> Self {
        Self::InvalidRequest(e.to_string())
    }
}

impl From<TryFromSliceError> for DbError {
    fn from(e: TryFromSliceError) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<redis::RedisError> for DbError {
    fn from(err: redis::RedisError) -> Self {
        Self::Redis(err.to_string())
    }
}

impl From<DbError> for redis::RedisError {
    fn from(val: DbError) -> Self {
        Self::from((ErrorKind::ClientError, "KMS Error", val.to_string()))
    }
}

impl From<tracing::dispatcher::SetGlobalDefaultError> for DbError {
    fn from(e: tracing::dispatcher::SetGlobalDefaultError) -> Self {
        Self::ServerError(e.to_string())
    }
}

impl From<InterfaceError> for DbError {
    fn from(value: InterfaceError) -> Self {
        Self::Store(value.to_string())
    }
}

impl From<CryptoCoreError> for DbError {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptographicError(e.to_string())
    }
}

impl From<FindexRedisError> for DbError {
    fn from(e: FindexRedisError) -> Self {
        Self::Findex(e.to_string())
    }
}

impl From<KmipError> for DbError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmipValue(r, s)
            | KmipError::InvalidKmipObject(r, s)
            | KmipError::Kmip(r, s) => Self::KmipError(r, s),
            KmipError::KmipNotSupported(_, s)
            | KmipError::NotSupported(s)
            | KmipError::Default(s)
            | KmipError::InvalidSize(s)
            | KmipError::InvalidTag(s)
            | KmipError::Derivation(s)
            | KmipError::ConversionError(s)
            | KmipError::IndexingSlicing(s)
            | KmipError::ObjectNotFound(s) => Self::NotSupported(s),
            KmipError::TryFromSliceError(s) => Self::ConversionError(s.to_string()),
            KmipError::SerdeJsonError(s) => Self::ConversionError(s.to_string()),
            KmipError::Deserialization(e) | KmipError::Serialization(e) => {
                Self::KmipError(ErrorReason::Codec_Error, e.to_string())
            }
            KmipError::DeserializationSize(expected, actual) => Self::KmipError(
                ErrorReason::Codec_Error,
                format!("Deserialization: invalid size: {actual}, expected: {expected}"),
            ),
        }
    }
}
