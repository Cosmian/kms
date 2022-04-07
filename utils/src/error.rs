use cosmian_kmip::{
    error::KmsCommonError,
    kmip::{kmip_operations::ErrorReason, ttlv::error::TtlvError},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LibError {
    #[error("TTLV Error: {0}")]
    TtlvError(String),

    #[error("Invalid KMIP value: {0}: {1}")]
    InvalidKmipValue(ErrorReason, String),

    #[error("Invalid KMIP Object: {0}: {1}")]
    InvalidKmipObject(ErrorReason, String),

    #[error("{0}: {1}")]
    KmipError(ErrorReason, String),

    #[error("Cryptographic Error: {0}: {1}")]
    CryptographicError(String, String),

    #[error("REST Request Failed: {0}")]
    RequestFailed(String),

    #[error("REST Response Filed: {0}")]
    ResponseFailed(String),

    #[error("Unexpected Error: {0}")]
    UnexpectedError(String),

    #[error("Invalid Request: {0}")]
    InvalidRequest(String),

    #[error("Error: {0}")]
    Error(String),
}

impl LibError {
    #[must_use]
    pub fn reason(&self, reason: ErrorReason) -> Self {
        match self {
            LibError::KmipError(_r, e) => LibError::KmipError(reason, e.clone()),
            e => LibError::KmipError(reason, e.to_string()),
        }
    }
}

impl From<std::io::Error> for LibError {
    fn from(e: std::io::Error) -> Self {
        LibError::UnexpectedError(e.to_string())
    }
}

impl From<eyre::Report> for LibError {
    fn from(e: eyre::Report) -> Self {
        LibError::Error(e.to_string())
    }
}

impl From<TtlvError> for LibError {
    fn from(e: TtlvError) -> Self {
        LibError::TtlvError(e.to_string())
    }
}

impl From<serde_json::Error> for LibError {
    fn from(e: serde_json::Error) -> Self {
        LibError::UnexpectedError(e.to_string())
    }
}

impl From<KmsCommonError> for LibError {
    fn from(e: KmsCommonError) -> Self {
        match e {
            KmsCommonError::InvalidKmipValue(r, s) => LibError::InvalidKmipValue(r, s),
            KmsCommonError::InvalidKmipObject(r, s) => LibError::InvalidKmipObject(r, s),
            KmsCommonError::KmipNotSupported(_, _) => todo!(),
            KmsCommonError::NotSupported(_) => todo!(),
            KmsCommonError::KmipError(_, _) => todo!(),
        }
    }
}

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! lib_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::LibError::Error($msg.to_owned()));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::LibError::Error($err.to_string()));
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::LibError::Error(format!($fmt, $($arg)*)));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! lib_error {
    ($msg:literal $(,)?) => {
        $crate::error::LibError::Error($msg.to_owned())
    };
    ($err:expr $(,)?) => ({
        $crate::error::LibError::Error($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::LibError::Error(format!($fmt, $($arg)*))
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! lib_bail {
    ($msg:literal $(,)?) => {
        return ::core::result::Result::Err($crate::error::LibError::Error($msg.to_owned()))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($crate::error::LibError::Error($err.to_string()))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::error::LibError::Error(format!($fmt, $($arg)*)))
    };
}
