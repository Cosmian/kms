use std::str::Utf8Error;

#[cfg(test)]
use assert_cmd::cargo::CargoError;
use cosmian_client::{
    reexport::{
        cosmian_findex::{self, Address, ADDRESS_LENGTH},
        cosmian_findex_structs::StructsError,
        cosmian_http_client::HttpClientError,
    },
    ClientError,
};
use cosmian_config_utils::ConfigUtilsError;
use cosmian_kms_cli::reexport::cosmian_kms_client::KmsClientError;
use thiserror::Error;

pub mod result;

// Each error type must have a corresponding HTTP status code (see
// `kmip_endpoint.rs`)
#[derive(Error, Debug)]
pub enum CosmianError {
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

    // Any errors related to a bad behavior of the server but not related to the user input
    #[error("Server error: {0}")]
    ServerError(String),

    // Any actions of the user which is not allowed
    #[error("Access denied: {0}")]
    Unauthorized(String),

    // Conversion errors
    #[error("Conversion error: {0}")]
    Conversion(String),

    // Invalid configuration file
    #[error("{0}")]
    Configuration(String),

    // Other errors
    #[error("invalid options: {0}")]
    UserError(String),

    // Other errors
    #[error("{0}")]
    Default(String),

    // Url parsing errors
    #[error(transparent)]
    UrlParsing(#[from] url::ParseError),

    // When an error occurs fetching Gmail API
    #[error("Error interacting with Gmail API: {0}")]
    GmailApiError(String),

    #[error(transparent)]
    KmsClientError(#[from] KmsClientError),

    #[error(transparent)]
    KmsCliError(#[from] cosmian_kms_cli::error::CliError),

    #[error(transparent)]
    KmipError(#[from] cosmian_kms_cli::reexport::cosmian_kms_client::cosmian_kmip::KmipError),

    #[error(transparent)]
    HttpClientError(#[from] HttpClientError),

    #[error(transparent)]
    Findex(#[from] cosmian_findex::Error<Address<ADDRESS_LENGTH>>),

    #[error(transparent)]
    FindexClientConfig(#[from] ClientError),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    CsvError(#[from] csv::Error),

    #[error(transparent)]
    Utf8Error(#[from] Utf8Error),

    #[error(transparent)]
    UuidError(#[from] uuid::Error),

    #[error(transparent)]
    StructsError(#[from] StructsError),

    #[error(transparent)]
    ConfigUtilsError(#[from] ConfigUtilsError),

    #[error(transparent)]
    FmtError(#[from] std::fmt::Error),

    #[error(transparent)]
    Base64(#[from] base64::DecodeError),

    #[cfg(test)]
    #[error(transparent)]
    CargoError(#[from] CargoError),
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
        $crate::error::CosmianError::Default(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::error::CosmianError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::CosmianError::Default(::core::format_args!($fmt, $($arg)*).to_string())
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

    use crate::error::result::CosmianResult;

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

    fn bail() -> CosmianResult<()> {
        let var = 43;
        if true {
            cli_bail!("interpolate {var}");
        }
        Ok(())
    }

    fn ensure() -> CosmianResult<()> {
        let var = 44;
        cli_ensure!(false, "interpolate {var}");
        Ok(())
    }
}
