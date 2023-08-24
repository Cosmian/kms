use std::{array::TryFromSliceError, sync::mpsc::SendError};

use actix_web::{dev::ServerHandle, error::QueryPayloadError};
use cloudproof::reexport::{
    crypto_core::CryptoCoreError, findex::implementations::redis::FindexRedisError,
};
use cosmian_kmip::{
    error::KmipError,
    kmip::{kmip_operations::ErrorReason, ttlv::error::TtlvError},
};
use cosmian_kms_utils::error::KmipUtilsError;
use redis::ErrorKind;
use thiserror::Error;

// Each error type must have a corresponding HTTP status code (see `kmip_endpoint.rs`)
#[derive(Error, Debug, Eq, PartialEq)]
pub enum KmsError {
    // When a conversion from/to bytes
    #[error("Conversion Error: {0}")]
    ConversionError(String),

    // When a user requests an endpoint which does not exist
    #[error("Not Supported route: {0}")]
    RouteNotFound(String),

    // When a user requests something not supported by the server
    #[error("Not Supported: {0}")]
    NotSupported(String),

    // When a user requests something which is a non-sense
    #[error("Inconsistent operation: {0}")]
    InconsistentOperation(String),

    // When a user requests with place holder id arg.
    #[error("This KMIP server does not yet support place holder id")]
    UnsupportedPlaceholder,

    // When a user requests with protection masks arg.
    #[error("This KMIP server does not yet support protection masks")]
    UnsupportedProtectionMasks,

    // When a user requests an id which does not exist
    #[error("Item not found: {0}")]
    ItemNotFound(String),

    // Missing arguments in the request
    #[error("Invalid Request: {0}")]
    InvalidRequest(String),

    // Any errors on KMIP format due to mistake of the user
    #[error("{0}: {1}")]
    KmipError(ErrorReason, String),

    // Any errors related to a bad behavior of the DB but not related to the user input
    #[error("Database Error: {0}")]
    DatabaseError(String),

    // Any errors related to a bad behavior of the server but not related to the user input
    #[error("Unexpected server error: {0}")]
    ServerError(String),

    // Any errors related to a bad behavior of the server concerning the SGX environment
    #[error("Unexpected sgx error: {0}")]
    SGXError(String),

    // Any actions of the user which is not allowed
    #[error("Access denied: {0}")]
    Unauthorized(String),

    // A failure originating from one of the cryptographic algorithms
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),

    #[error("Redis Error: {0}")]
    Redis(String),

    #[error("Findex Error: {0}")]
    Findex(String),
}

impl From<TtlvError> for KmsError {
    fn from(e: TtlvError) -> Self {
        Self::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}

impl From<CryptoCoreError> for KmsError {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptographicError(e.to_string())
    }
}

impl From<FindexRedisError> for KmsError {
    fn from(e: FindexRedisError) -> Self {
        Self::Findex(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for KmsError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<sqlx::Error> for KmsError {
    fn from(e: sqlx::Error) -> Self {
        Self::DatabaseError(e.to_string())
    }
}

impl From<std::io::Error> for KmsError {
    fn from(e: std::io::Error) -> Self {
        Self::ServerError(e.to_string())
    }
}

impl From<openssl::error::ErrorStack> for KmsError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::ServerError(e.to_string())
    }
}

impl From<acme_lib::Error> for KmsError {
    fn from(e: acme_lib::Error) -> Self {
        Self::ServerError(e.to_string())
    }
}

impl From<serde_json::Error> for KmsError {
    fn from(e: serde_json::Error) -> Self {
        Self::InvalidRequest(e.to_string())
    }
}

impl From<cloudproof::reexport::cover_crypt::Error> for KmsError {
    fn from(e: cloudproof::reexport::cover_crypt::Error) -> Self {
        Self::InvalidRequest(e.to_string())
    }
}

impl From<libsgx::error::SgxError> for KmsError {
    fn from(e: libsgx::error::SgxError) -> Self {
        Self::SGXError(e.to_string())
    }
}

impl From<QueryPayloadError> for KmsError {
    fn from(e: QueryPayloadError) -> Self {
        Self::InvalidRequest(e.to_string())
    }
}

impl From<KmipUtilsError> for KmsError {
    fn from(e: KmipUtilsError) -> Self {
        Self::CryptographicError(e.to_string())
    }
}

impl From<TryFromSliceError> for KmsError {
    fn from(e: TryFromSliceError) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<KmipError> for KmsError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmipValue(r, s) => Self::KmipError(r, s),
            KmipError::InvalidKmipObject(r, s) => Self::KmipError(r, s),
            KmipError::KmipNotSupported(_, s) => Self::NotSupported(s),
            KmipError::NotSupported(s) => Self::NotSupported(s),
            KmipError::KmipError(r, s) => Self::KmipError(r, s),
        }
    }
}

impl From<SendError<ServerHandle>> for KmsError {
    fn from(e: SendError<ServerHandle>) -> Self {
        Self::ServerError(format!("Failed to send the server handle: {e}"))
    }
}

impl From<redis::RedisError> for KmsError {
    fn from(err: redis::RedisError) -> Self {
        KmsError::Redis(err.to_string())
    }
}

impl From<KmsError> for redis::RedisError {
    fn from(val: KmsError) -> Self {
        redis::RedisError::from((ErrorKind::ClientError, "KMS Error", val.to_string()))
    }
}

impl KmsError {
    #[must_use]
    pub fn reason(&self, reason: ErrorReason) -> Self {
        match self {
            Self::KmipError(_r, e) => Self::KmipError(reason, e.clone()),
            e => Self::KmipError(reason, e.to_string()),
        }
    }
}

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! kms_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::KmsError::ServerError($msg.to_owned()));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::KmsError::ServerError(format!($fmt, $($arg)*)));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! kms_error {
    ($msg:literal) => {
        $crate::error::KmsError::ServerError(format!($msg))
    };
    ($err:expr $(,)?) => ({
        $crate::error::KmsError::ServerError($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::KmsError::ServerError(format!($fmt, $($arg)*))
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! kms_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::error::KmsError::ServerError(format!($msg)))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::error::KmsError::ServerError(format!($fmt, $($arg)*)))
    };
}

/// Return early with an Unsupported error
#[macro_export]
macro_rules! kms_not_supported {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::error::KmsError::NotSupported(format!($msg)))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::error::KmsError::NotSupported(format!($fmt, $($arg)*)))
    };
}
