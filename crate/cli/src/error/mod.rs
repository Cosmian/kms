use std::str::Utf8Error;

#[cfg(test)]
use assert_cmd::cargo::CargoError;
use cosmian_config_utils::ConfigUtilsError;
use cosmian_kms_client::{
    KmsClientError,
    cosmian_kmip::ttlv::TtlvError,
    reexport::{cosmian_http_client::HttpClientError, cosmian_kms_client_utils::error::UtilsError},
};
#[cfg(feature = "non-fips")]
use cosmian_kms_crypto::reexport::cosmian_cover_crypt;
use thiserror::Error;

use crate::actions::kms::google::GoogleApiError;

pub mod result;

// Each error type must have a corresponding HTTP status code (see
// `kmip_endpoint.rs`)
#[derive(Error, Debug)]
pub enum KmsCliError {
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[cfg(test)]
    #[error(transparent)]
    CargoError(#[from] CargoError),
    #[error("{0}")]
    Configuration(String),
    #[error("Conversion error: {0}")]
    Conversion(String),
    #[error(transparent)]
    ConfigUtilsError(#[from] ConfigUtilsError),
    #[cfg(feature = "non-fips")]
    #[error(transparent)]
    CovercryptError(#[from] cosmian_cover_crypt::Error),
    #[error(transparent)]
    CryptoError(#[from] cosmian_kms_crypto::CryptoError),
    #[error("{0}")]
    Default(String),
    #[error(transparent)]
    DerError(#[from] der::Error),
    #[error(transparent)]
    FmtError(#[from] std::fmt::Error),
    #[error(transparent)]
    FromHexError(#[from] hex::FromHexError),
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("Error interacting with Gmail API: {0}")]
    GmailApiError(String),
    #[error(transparent)]
    HttpClientError(#[from] HttpClientError),
    #[error("Inconsistent operation: {0}")]
    InconsistentOperation(String),
    #[error("Invalid Request: {0}")]
    InvalidRequest(String),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("Item not found: {0}")]
    ItemNotFound(String),
    #[error(transparent)]
    KmipError(#[from] cosmian_kms_client::cosmian_kmip::KmipError),
    #[error(transparent)]
    KmsClientError(#[from] KmsClientError),
    #[error("Not Supported: {0}")]
    NotSupported(String),
    #[error("Not Supported route: {0}")]
    RouteNotFound(String),
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("Server error: {0}")]
    ServerError(String),
    #[error(transparent)]
    TryFromIntError(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    TTLVError(#[from] TtlvError),
    #[error(transparent)]
    UrlParsing(#[from] url::ParseError),
    #[error("invalid options: {0}")]
    UserError(String),
    #[error(transparent)]
    Utf8Error(#[from] Utf8Error),
    #[error(transparent)]
    UuidError(#[from] uuid::Error),
    #[error("Access denied: {0}")]
    Unauthorized(String),
    #[error(transparent)]
    UtilsError(#[from] UtilsError),
    #[cfg(test)]
    #[error(transparent)]
    OpenSSL(#[from] openssl::error::ErrorStack),
}

impl From<GoogleApiError> for KmsCliError {
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
        $crate::error::KmsCliError::Default(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::error::KmsCliError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::KmsCliError::Default(::core::format_args!($fmt, $($arg)*).to_string())
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
#[allow(clippy::panic)]
mod tests {

    use crate::error::result::KmsCliResult;

    #[test]
    fn test_cli_error_interpolation() {
        let var = 42;
        let err = cli_error!("interpolate {var}");
        assert_eq!("interpolate 42", err.to_string());

        let err = bail();
        match err {
            Err(e) => assert_eq!("interpolate 43", e.to_string()),
            Ok(()) => panic!("expected error"),
        }

        let err = ensure();
        match err {
            Err(e) => assert_eq!("interpolate 44", e.to_string()),
            Ok(()) => panic!("expected error"),
        }
    }

    fn bail() -> KmsCliResult<()> {
        let var = 43;
        if true {
            cli_bail!("interpolate {var}");
        }
        Ok(())
    }

    fn ensure() -> KmsCliResult<()> {
        let var = 44;
        cli_ensure!(false, "interpolate {var}");
        Ok(())
    }
}
