use abe_gpsw::error::FormatErr;
use cosmian_kmip::{
    error::KmipError,
    kmip::{kmip_operations::ErrorReason, ttlv::error::TtlvError},
};
use cosmian_kms_utils::error::LibError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KmsError {
    #[error("Invalid KMIP value: {0}: {1}")]
    InvalidKmipValue(ErrorReason, String),

    #[error("Invalid KMIP Object: {0}: {1}")]
    InvalidKmipObject(ErrorReason, String),

    #[error("Kmip Not Supported: {0}: {1}")]
    KmipNotSupported(ErrorReason, String),

    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error("{0}: {1}")]
    KmipError(ErrorReason, String),

    #[error("Unexpected Error: {0}")]
    UnexpectedError(String),

    #[error("Cryptographic Error: {0}: {1}")]
    CryptographicError(String, String),

    #[error("Database Error: {0}")]
    DatabaseError(String),

    #[error("Invalid Request: {0}")]
    InvalidRequest(String),

    #[error("REST Request Failed: {0}")]
    RequestFailed(String),

    #[error("REST Response Filed: {0}")]
    ResponseFailed(String),

    #[error("Unexpected server error: {0}")]
    ServerError(String),

    #[error("Access denied: {0}")]
    Unauthorized(String),
}

impl KmsError {
    #[must_use]
    pub fn reason(&self, reason: ErrorReason) -> Self {
        match self {
            KmsError::KmipError(_r, e) => KmsError::KmipError(reason, e.clone()),
            e => KmsError::KmipError(reason, e.to_string()),
        }
    }
}

impl From<std::io::Error> for KmsError {
    fn from(e: std::io::Error) -> Self {
        KmsError::ServerError(e.to_string())
    }
}

impl From<eyre::Report> for KmsError {
    fn from(e: eyre::Report) -> Self {
        KmsError::ServerError(e.to_string())
    }
}

impl From<TtlvError> for KmsError {
    fn from(e: TtlvError) -> Self {
        KmsError::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}

impl From<serde_json::Error> for KmsError {
    fn from(e: serde_json::Error) -> Self {
        KmsError::ServerError(e.to_string())
    }
}

impl From<FormatErr> for KmsError {
    fn from(e: FormatErr) -> Self {
        KmsError::CryptographicError("ABE".to_owned(), e.to_string())
    }
}

impl From<LibError> for KmsError {
    fn from(e: LibError) -> Self {
        match e {
            LibError::TtlvError(s) => KmsError::NotSupported(s),
            LibError::RequestFailed(s) => KmsError::RequestFailed(s),
            LibError::ResponseFailed(s) => KmsError::ResponseFailed(s),
            LibError::UnexpectedError(s) => KmsError::UnexpectedError(s),
            LibError::InvalidKmipValue(_, _) => todo!(),
            LibError::InvalidKmipObject(_, _) => todo!(),
            LibError::CryptographicError(s, r) => KmsError::CryptographicError(s, r),
            LibError::InvalidRequest(_) => todo!(),
            LibError::Error(s) => KmsError::ServerError(s),
            LibError::KmipError(_, _) => todo!(),
        }
    }
}

impl From<KmipError> for KmsError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmipValue(r, s) => KmsError::InvalidKmipValue(r, s),
            KmipError::InvalidKmipObject(r, s) => KmsError::InvalidKmipObject(r, s),
            KmipError::KmipNotSupported(r, s) => KmsError::KmipNotSupported(r, s),
            KmipError::NotSupported(s) => KmsError::NotSupported(s),
            KmipError::KmipError(r, s) => KmsError::KmipError(r, s),
        }
    }
}

impl From<sqlx::Error> for KmsError {
    fn from(e: sqlx::Error) -> Self {
        KmsError::DatabaseError(e.to_string())
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
            return ::core::result::Result::Err($crate::error::KmsError::ServerError($err.to_string()));
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
    ($msg:literal $(,)?) => {
        $crate::error::KmsError::ServerError($msg.to_owned())
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
    ($msg:literal $(,)?) => {
        return ::core::result::Result::Err($crate::error::KmsError::ServerError($msg.to_owned()))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($crate::error::KmsError::ServerError($err.to_string()))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::error::KmsError::ServerError(format!($fmt, $($arg)*)))
    };
}
