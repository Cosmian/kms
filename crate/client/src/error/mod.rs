use std::io;

use cosmian_config_utils::ConfigUtilsError;
use cosmian_findex::{Address, ADDRESS_LENGTH};
use cosmian_findex_structs::StructsError;
use cosmian_kms_cli::reexport::cosmian_kms_client;
use thiserror::Error;

pub(crate) mod result;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Unexpected Error: {0}")]
    Default(String),
    #[error("REST Request Failed: {0}")]
    RequestFailed(String),
    #[error(transparent)]
    FindexError(#[from] cosmian_findex::Error<Address<ADDRESS_LENGTH>>),
    #[error(transparent)]
    StructsError(#[from] StructsError),
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    ConfigUtilsError(#[from] ConfigUtilsError),
    #[error(transparent)]
    KmipError(#[from] cosmian_kms_client::cosmian_kmip::KmipError),
    #[error(transparent)]
    KmsClientError(#[from] cosmian_kms_client::KmsClientError),
    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    TryFromIntError(#[from] std::num::TryFromIntError),
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! client_error {
    ($msg:literal) => {
        $crate::ClientError::Default(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::ClientError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::ClientError::Default(::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! client_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::client_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::client_error!($fmt, $($arg)*))
    };
}
