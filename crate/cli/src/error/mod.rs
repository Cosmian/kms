use std::{num::TryFromIntError, str::Utf8Error};

#[cfg(test)]
use assert_cmd::cargo::CargoError;
use cosmian_config_utils::ConfigUtilsError;
use cosmian_kms_client::{
    cosmian_kmip::{
        kmip_2_1::{kmip_operations::ErrorReason, ttlv::error::TtlvError},
        KmipError,
    },
    reexport::cosmian_http_client::HttpClientError,
    KmsClientError,
};
use cosmian_kms_crypto::CryptoError;
use hex::FromHexError;
use thiserror::Error;

use crate::actions::google::GoogleApiError;

pub mod result;

// Each error type must have a corresponding HTTP status code (see `kmip_endpoint.rs`)
#[derive(Error, Debug)]
pub enum CliError {
    // Configuration errors
    #[error(transparent)]
    ConfigUtilsError(#[from] ConfigUtilsError),

    // Conversion errors
    #[error("Conversion error: {0}")]
    Conversion(String),

    #[error(transparent)]
    CovercryptError(#[from] cloudproof::reexport::cover_crypt::Error),

    // A cryptographic error
    #[error("Cryptographic error: {0}")]
    Cryptographic(String),

    // Other errors
    #[error("{0}")]
    Default(String),

    #[error(transparent)]
    DerError(#[from] der::Error),

    #[error(transparent)]
    FromHexError(#[from] FromHexError),

    #[cfg(test)]
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),

    // When an error occurs fetching Gmail API
    #[error("Error interacting with Gmail API: {0}")]
    GmailApiError(String),

    #[error(transparent)]
    HttpClientError(#[from] HttpClientError),

    // When a user requests something, which is nonsense
    #[error("Inconsistent operation: {0}")]
    InconsistentOperation(String),

    // Missing arguments in the request
    #[error("Invalid Request: {0}")]
    InvalidRequest(String),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    // When a user requests an id which does not exist
    #[error("Item not found: {0}")]
    ItemNotFound(String),

    // Any errors on KMIP format due to mistake of the user
    #[error("{0}: {1}")]
    KmipError(ErrorReason, String),

    #[error(transparent)]
    KmsClientError(#[from] KmsClientError),

    // When a user requests something not supported by the server
    #[error("Not Supported: {0}")]
    NotSupported(String),

    // When a user requests an endpoint which does not exist
    #[error("Not Supported route: {0}")]
    RouteNotFound(String),

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),

    // Any errors related to a bad behavior of the server but not related to the user input
    #[error("Server error: {0}")]
    ServerError(String),

    #[error(transparent)]
    TryFromIntError(#[from] TryFromIntError),

    // Any actions of the user which is not allowed
    #[error("Access denied: {0}")]
    Unauthorized(String),

    // Url parsing errors
    #[error(transparent)]
    UrlParsing(#[from] url::ParseError),

    // Other errors
    #[error("invalid options: {0}")]
    UserError(String),

    #[error(transparent)]
    Utf8Error(#[from] Utf8Error),
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

impl From<TtlvError> for CliError {
    fn from(e: TtlvError) -> Self {
        Self::KmipError(ErrorReason::Codec_Error, e.to_string())
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
            KmipError::InvalidKmip21Value(r, s)
            | KmipError::InvalidKmip21Object(r, s)
            | KmipError::Kmip21(r, s) => Self::KmipError(r, s),
            KmipError::Kmip21NotSupported(_, s)
            | KmipError::NotSupported(s)
            | KmipError::Default(s)
            | KmipError::InvalidSize(s)
            | KmipError::InvalidTag(s)
            | KmipError::Derivation(s)
            | KmipError::ConversionError(s)
            | KmipError::IndexingSlicing(s)
            | KmipError::ObjectNotFound(s) => Self::NotSupported(s),
            KmipError::TryFromSliceError(t) => Self::Conversion(t.to_string()),
            KmipError::SerdeJsonError(e) => Self::Conversion(e.to_string()),
            KmipError::Deserialization(_) | KmipError::Serialization(_) => {
                Self::KmipError(ErrorReason::Codec_Error, e.to_string())
            }
            KmipError::DeserializationSize(expected, actual) => Self::KmipError(
                ErrorReason::Codec_Error,
                format!("Deserialization: invalid size: {actual}, expected: {expected}"),
            ),
        }
    }
}

impl From<CryptoError> for CliError {
    fn from(e: CryptoError) -> Self {
        Self::Cryptographic(e.to_string())
    }
}

impl From<GoogleApiError> for CliError {
    fn from(e: GoogleApiError) -> Self {
        match e {
            GoogleApiError::Jwt(e) => Self::GmailApiError(e.to_string()),
            GoogleApiError::Reqwest(e) => Self::GmailApiError(e.to_string()),
            GoogleApiError::Serde(e) => Self::GmailApiError(e.to_string()),
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
            return ::core::result::Result::Err($crate::cli_error!($msg));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::cli_error!($fmt, $($arg)*));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! cli_error {
    ($msg:literal) => {
        $crate::error::CliError::Default(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::error::CliError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::CliError::Default(::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! cli_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::cli_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::cli_error!($fmt, $($arg)*))
    };
}

#[cfg(test)]
mod tests {

    use crate::error::result::CliResult;

    #[test]
    fn test_cli_error_interpolation() {
        let var = 42;
        let err = cli_error!("interpolate {var}");
        assert_eq!("interpolate 42", err.to_string());

        let err = bail();
        assert_eq!("interpolate 43", err.unwrap_err().to_string());

        let err = ensure();
        assert_eq!("interpolate 44", err.unwrap_err().to_string());
    }

    fn bail() -> CliResult<()> {
        let var = 43;
        cli_bail!("interpolate {var}");
    }

    fn ensure() -> CliResult<()> {
        let var = 44;
        cli_ensure!(false, "interpolate {var}");
        Ok(())
    }
}
