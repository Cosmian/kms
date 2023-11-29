use std::{array::TryFromSliceError, str::Utf8Error};

#[cfg(test)]
use assert_cmd::cargo::CargoError;
use cosmian_kmip::{
    error::KmipError,
    kmip::{kmip_operations::ErrorReason, ttlv::error::TtlvError},
};
use cosmian_kms_client::RestClientError;
use cosmian_kms_utils::error::KmipUtilsError;
use openssl::error::ErrorStack;
use pem::PemError;
use thiserror::Error;

pub mod result;

// Each error type must have a corresponding HTTP status code (see `kmip_endpoint.rs`)
#[derive(Error, Debug)]
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

    // Conversion errors
    #[error("Conversion error: {0}")]
    Conversion(String),

    // When the KMS client returns an error
    #[error("{0}")]
    KmsClientError(String),

    // Other errors
    #[error("invalid options: {0}")]
    UserError(String),

    // Other errors
    #[error("{0}")]
    Default(String),

    // TEE errors
    #[error(transparent)]
    TeeAttestationError(#[from] tee_attestation::error::Error),

    // Url parsing errors
    #[error(transparent)]
    UrlParsing(#[from] url::ParseError),
}

impl From<KmipUtilsError> for CliError {
    fn from(e: KmipUtilsError) -> Self {
        Self::Cryptographic(e.to_string())
    }
}

impl From<&KmipError> for CliError {
    fn from(e: &KmipError) -> Self {
        Self::KmipError(ErrorReason::Invalid_Attribute, e.to_string())
    }
}

impl From<TtlvError> for CliError {
    fn from(e: TtlvError) -> Self {
        Self::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}

impl From<der::Error> for CliError {
    fn from(e: der::Error) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<cloudproof::reexport::crypto_core::CryptoCoreError> for CliError {
    fn from(e: cloudproof::reexport::crypto_core::CryptoCoreError) -> Self {
        Self::Cryptographic(e.to_string())
    }
}

impl From<cloudproof::reexport::crypto_core::reexport::pkcs8::Error> for CliError {
    fn from(e: cloudproof::reexport::crypto_core::reexport::pkcs8::Error) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<ErrorStack> for CliError {
    fn from(e: ErrorStack) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<TryFromSliceError> for CliError {
    fn from(e: TryFromSliceError) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::ServerError(e.to_string())
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<cloudproof::reexport::cover_crypt::Error> for CliError {
    fn from(e: cloudproof::reexport::cover_crypt::Error) -> Self {
        Self::InvalidRequest(e.to_string())
    }
}

impl From<Utf8Error> for CliError {
    fn from(e: Utf8Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for CliError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::Default(e.to_string())
    }
}

#[cfg(test)]
impl From<reqwest::Error> for CliError {
    fn from(e: reqwest::Error) -> Self {
        Self::Default(e.to_string())
    }
}

#[cfg(test)]
impl From<CargoError> for CliError {
    fn from(e: CargoError) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<KmipError> for CliError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmipValue(r, s) => Self::KmipError(r, s),
            KmipError::InvalidKmipObject(r, s) => Self::KmipError(r, s),
            KmipError::KmipNotSupported(_, s) => Self::NotSupported(s),
            KmipError::NotSupported(s) => Self::NotSupported(s),
            KmipError::KmipError(r, s) => Self::KmipError(r, s),
            KmipError::Default(s) => Self::NotSupported(s),
            KmipError::OpenSSL(s) => Self::NotSupported(s),
        }
    }
}

impl From<base64::DecodeError> for CliError {
    fn from(e: base64::DecodeError) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<RestClientError> for CliError {
    fn from(e: RestClientError) -> Self {
        Self::KmsClientError(e.to_string())
    }
}

impl From<PemError> for CliError {
    fn from(e: PemError) -> Self {
        Self::Conversion(format!("PEM error: {}", e))
    }
}

impl From<std::fmt::Error> for CliError {
    fn from(e: std::fmt::Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl CliError {
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
