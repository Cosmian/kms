use std::{array::TryFromSliceError, sync::mpsc::SendError};

use actix_web::{dev::ServerHandle, error::QueryPayloadError};
use cloudproof::reexport::crypto_core::CryptoCoreError;
use cloudproof_findex::implementations::redis::FindexRedisError;
use cosmian_kmip::{
    kmip_1_4::kmip_types::ResultReason, kmip_2_1::kmip_operations::ErrorReason,
    ttlv::error::TtlvError, KmipError,
};
use cosmian_kms_crypto::CryptoError;
use cosmian_kms_interfaces::InterfaceError;
use cosmian_kms_server_database::DbError;
use thiserror::Error;
use x509_parser::prelude::{PEMError, X509Error};

// Each error type must have a corresponding HTTP status code (see `kmip_endpoint.rs`)
#[derive(Error, Debug, Clone)]
pub enum KmsError {
    // Error related to X509 Certificate
    #[error("Certificate error: {0}")]
    Certificate(String),

    // Any actions of the user that is not allowed
    #[error("REST client connection error: {0}")]
    ClientConnectionError(String),

    // When a conversion from/to bytes
    #[error("Conversion Error: {0}")]
    ConversionError(String),

    // A failure originating from one of the cryptographic algorithms
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),

    // Any errors related to a bad behavior of the DB but not related to the user input
    #[error("Database Error: {0}")]
    Database(String),

    #[error("{0}")]
    Default(String),

    #[error("Findex Error: {0}")]
    Findex(String),

    // When a user requests something which is a non-sense
    #[error("Inconsistent operation: {0}")]
    InconsistentOperation(String),

    // Missing arguments in the request
    #[error("Invalid Request: {0}")]
    InvalidRequest(String),

    // // When a user requests an item which does not exist
    #[error("Item not found: {0}")]
    ItemNotFound(String),

    // Any errors on KMIP format due to mistake of the user
    #[error("{0}: {1}")]
    Kmip21Error(ErrorReason, String),

    // Any errors on KMIP format due to mistake of the user
    #[error("{0}: {1}")]
    Kmip14Error(ResultReason, String),

    // When a user requests something not supported by the server
    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error("Redis Error: {0}")]
    Redis(String),

    // When a user requests an endpoint which does not exist
    #[error("Not Supported route: {0}")]
    RouteNotFound(String),

    // Any errors related to a bad behavior of the server but not related to the user input
    #[error("Unexpected server error: {0}")]
    ServerError(String),

    // Any actions of the user which is not allowed
    #[error("Access denied: {0}")]
    Unauthorized(String),

    // When a user requests with place holder id arg.
    #[error("This KMIP server does not yet support place holder id")]
    UnsupportedPlaceholder,

    // When a user requests with protection masks arg.
    #[error("This KMIP server does not yet support protection masks")]
    UnsupportedProtectionMasks,

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Invalid URL: {0}")]
    UrlError(String),
}

impl KmsError {
    #[must_use]
    pub(crate) fn reason(&self, reason: ErrorReason) -> Self {
        match self {
            Self::Kmip21Error(_r, e) => Self::Kmip21Error(reason, e.clone()),
            e => Self::Kmip21Error(reason, e.to_string()),
        }
    }
}

impl From<TtlvError> for KmsError {
    fn from(e: TtlvError) -> Self {
        Self::Kmip21Error(ErrorReason::Codec_Error, e.to_string())
    }
}

impl From<x509_parser::nom::Err<X509Error>> for KmsError {
    fn from(e: x509_parser::nom::Err<X509Error>) -> Self {
        Self::Certificate(e.to_string())
    }
}

impl From<X509Error> for KmsError {
    fn from(e: X509Error) -> Self {
        Self::Certificate(e.to_string())
    }
}

impl From<&X509Error> for KmsError {
    fn from(e: &X509Error) -> Self {
        Self::Certificate(e.to_string())
    }
}

impl From<x509_parser::nom::Err<PEMError>> for KmsError {
    fn from(e: x509_parser::nom::Err<PEMError>) -> Self {
        Self::Certificate(e.to_string())
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

impl From<std::num::TryFromIntError> for KmsError {
    fn from(e: std::num::TryFromIntError) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<std::io::Error> for KmsError {
    fn from(e: std::io::Error) -> Self {
        Self::ServerError(e.to_string())
    }
}

impl From<openssl::error::ErrorStack> for KmsError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::ServerError(format!("{e}. Details: {e:?}"))
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

impl From<QueryPayloadError> for KmsError {
    fn from(e: QueryPayloadError) -> Self {
        Self::InvalidRequest(e.to_string())
    }
}

impl From<TryFromSliceError> for KmsError {
    fn from(e: TryFromSliceError) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<reqwest::Error> for KmsError {
    fn from(e: reqwest::Error) -> Self {
        Self::ClientConnectionError(format!("{e}: details: {e:?}"))
    }
}

impl From<KmipError> for KmsError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmip21Value(r, s)
            | KmipError::InvalidKmip21Object(r, s)
            | KmipError::Kmip21(r, s) => Self::Kmip21Error(r, s),
            KmipError::Kmip21NotSupported(_, s)
            | KmipError::NotSupported(s)
            | KmipError::Default(s)
            | KmipError::InvalidSize(s)
            | KmipError::InvalidTag(s)
            | KmipError::Derivation(s)
            | KmipError::ConversionError(s)
            | KmipError::IndexingSlicing(s)
            | KmipError::ObjectNotFound(s) => Self::NotSupported(s),
            KmipError::TryFromSliceError(t) => Self::NotSupported(t.to_string()),
            KmipError::SerdeJsonError(e) => Self::NotSupported(e.to_string()),
            KmipError::Deserialization(e) | KmipError::Serialization(e) => {
                Self::Kmip21Error(ErrorReason::Codec_Error, e)
            }
            KmipError::DeserializationSize(expected, actual) => Self::Kmip21Error(
                ErrorReason::Codec_Error,
                format!("Deserialization: invalid size: {actual}, expected: {expected}"),
            ),
            KmipError::InvalidKmip14Value(result_reason, e)
            | KmipError::InvalidKmip14Object(result_reason, e)
            | KmipError::Kmip14(result_reason, e) => Self::Kmip14Error(result_reason, e),
        }
    }
}

impl From<SendError<ServerHandle>> for KmsError {
    fn from(e: SendError<ServerHandle>) -> Self {
        Self::ServerError(format!("Failed to send the server handle: {e}"))
    }
}

impl From<url::ParseError> for KmsError {
    fn from(e: url::ParseError) -> Self {
        Self::UrlError(e.to_string())
    }
}

impl From<base64::DecodeError> for KmsError {
    fn from(e: base64::DecodeError) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<tracing::dispatcher::SetGlobalDefaultError> for KmsError {
    fn from(e: tracing::dispatcher::SetGlobalDefaultError) -> Self {
        Self::ServerError(e.to_string())
    }
}

impl From<DbError> for KmsError {
    fn from(value: DbError) -> Self {
        Self::Default(value.to_string())
    }
}

impl From<KmsError> for DbError {
    fn from(value: KmsError) -> Self {
        Self::Default(value.to_string())
    }
}

impl From<InterfaceError> for KmsError {
    fn from(value: InterfaceError) -> Self {
        Self::Default(value.to_string())
    }
}

impl From<CryptoError> for KmsError {
    fn from(value: CryptoError) -> Self {
        Self::CryptographicError(value.to_string())
    }
}

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! kms_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::kms_error!($msg));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::kms_error!($fmt, $($arg)*));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! kms_error {
    ($msg:literal) => {
        $crate::error::KmsError::ServerError(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::error::KmsError::ServerError($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::KmsError::ServerError(::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! kms_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::kms_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::kms_error!($fmt, $($arg)*))
    };
}

#[allow(clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::KmsError;

    #[test]
    fn test_kms_error_interpolation() {
        let var = 42;
        let err = kms_error!("interpolate {var}");
        assert_eq!("Unexpected server error: interpolate 42", err.to_string());

        let err = bail();
        err.expect_err("Unexpected server error: interpolate 43");

        let err = ensure();
        err.expect_err("Unexpected server error: interpolate 44");
    }

    fn bail() -> Result<(), KmsError> {
        let var = 43;
        {
            kms_bail!("interpolate {var}");
        }
    }

    fn ensure() -> Result<(), KmsError> {
        let var = 44;
        kms_ensure!(false, "interpolate {var}");
        Ok(())
    }
}
