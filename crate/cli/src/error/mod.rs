use std::str::Utf8Error;

use cosmian_kmip::{
    error::KmipError,
    kmip::{kmip_operations::ErrorReason, ttlv::error::TtlvError},
};
use cosmian_kms_client::error::KmsClientError;
use cosmian_kms_utils::crypto::error::CryptoError;
use thiserror::Error;
pub mod result;

#[cfg(test)]
use assert_cmd::cargo::CargoError;

// Each error type must have a corresponding HTTP status code (see `kmip_endpoint.rs`)
#[derive(Error, Debug, Eq, PartialEq)]
pub enum CliError {
    // When a user requests an endpoint which does not exist
    #[error("Not Supported route: {0}")]
    RouteNotFound(String),

    // When a user requests something not supported by the server
    #[error("Not Supported: {0}")]
    NotSupported(String),

    // When a user requests something which is a non-sense
    #[error("Inconsistent operation: {0}")]
    InconsistentOperation(String),

    // When a user requests an id which does not exist
    #[error("Item not found: {0}")]
    ItemNotFound(String),

    // Missing arguments in the request
    #[error("Invalid Request: {0}")]
    InvalidRequest(String),

    // Any errors on KMIP format due to mistake of the user
    #[error("{0}: {1}")]
    KmipError(ErrorReason, String),

    // Any errors related to a bad behavior of the server but not related to the user input
    #[error("Server error: {0}")]
    ServerError(String),

    // Any errors related to a bad behavior of the server concerning the SGX environment
    #[error("Unexpected sgx error: {0}")]
    SGXError(String),

    // Any actions of the user which is not allowed
    #[error("Access denied: {0}")]
    Unauthorized(String),

    // A cryptographic error
    #[error("Cryptographic error: {0}")]
    Cryptographic(String),

    // When the KMS client returns an error
    #[error("{0}")]
    KmsClientError(String),

    // Other errors
    #[error("{0}")]
    Default(String),
}

impl From<CryptoError> for CliError {
    fn from(e: CryptoError) -> Self {
        CliError::Cryptographic(e.to_string())
    }
}

impl From<TtlvError> for CliError {
    fn from(e: TtlvError) -> Self {
        CliError::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::ServerError(e.to_string())
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError::InvalidRequest(e.to_string())
    }
}

impl From<cloudproof::reexport::cover_crypt::Error> for CliError {
    fn from(e: cloudproof::reexport::cover_crypt::Error) -> Self {
        CliError::InvalidRequest(e.to_string())
    }
}

impl From<libsgx::error::SgxError> for CliError {
    fn from(e: libsgx::error::SgxError) -> Self {
        CliError::SGXError(e.to_string())
    }
}

impl From<Utf8Error> for CliError {
    fn from(e: Utf8Error) -> Self {
        CliError::Default(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for CliError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        CliError::Default(e.to_string())
    }
}

#[cfg(test)]
impl From<reqwest::Error> for CliError {
    fn from(e: reqwest::Error) -> Self {
        CliError::Default(e.to_string())
    }
}

#[cfg(test)]
impl From<CargoError> for CliError {
    fn from(e: CargoError) -> Self {
        CliError::Default(e.to_string())
    }
}

impl From<KmipError> for CliError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmipValue(r, s) => CliError::KmipError(r, s),
            KmipError::InvalidKmipObject(r, s) => CliError::KmipError(r, s),
            KmipError::KmipNotSupported(_, s) => CliError::NotSupported(s),
            KmipError::NotSupported(s) => CliError::NotSupported(s),
            KmipError::KmipError(r, s) => CliError::KmipError(r, s),
        }
    }
}

impl From<base64::DecodeError> for CliError {
    fn from(e: base64::DecodeError) -> Self {
        CliError::Default(e.to_string())
    }
}

impl From<KmsClientError> for CliError {
    fn from(e: KmsClientError) -> Self {
        CliError::KmsClientError(e.to_string())
    }
}

impl CliError {
    #[must_use]
    pub fn reason(&self, reason: ErrorReason) -> Self {
        match self {
            CliError::KmipError(_r, e) => CliError::KmipError(reason, e.clone()),
            e => CliError::KmipError(reason, e.to_string()),
        }
    }
}

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! cli_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::CliError::Default($msg.to_owned()));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::CliError::Default(format!($fmt, $($arg)*)));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! cli_error {
    ($msg:literal) => {
        $crate::error::CliError::Default(format!($msg))
    };
    ($err:expr $(,)?) => ({
        $crate::error::CliError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::CliError::Default(format!($fmt, $($arg)*))
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! cli_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err( $crate::error::CliError::Default(format!($msg)))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::error::CliError::Default(format!($fmt, $($arg)*)))
    };
}
