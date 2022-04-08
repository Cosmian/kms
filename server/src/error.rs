use abe_gpsw::error::FormatErr;
use cosmian_kmip::{
    error::KmipError,
    kmip::{kmip_operations::ErrorReason, ttlv::error::TtlvError},
};
use cosmian_kms_utils::error::LibError;
use thiserror::Error;

// Each error type must have a corresponding HTTP status code (see `kmip_endpoint.rs`)
#[derive(Error, Debug)]
pub enum KmsError {
    // When a user requests an endpoint which does not exist
    #[error("Not Supported route: {0}")]
    RouteNotFound(String),

    // When a user requests soemthing not supported by the server
    #[error("Not Supported: {0}")]
    NotSupported(String),

    // When a user requests with place holder id arg.
    #[error("This KMIP server does not yet support place holder id")]
    NotSupportedPlaceholder(),

    // When a user requests with protection masks arg.
    #[error("This KMIP server does not yet support protection masks")]
    NotSupportedProtectionMasks(),

    // When a user requests an id which does not exist
    #[error("Item not found: {0}")]
    ItemNotFound(String),

    // Missing arguments in the request
    #[error("Invalid Request: {0}")]
    InvalidRequest(String),

    // Any errors on KMIP format due to mistake of the user
    #[error("{0}: {1}")]
    KmipError(ErrorReason, String),

    // Any errors related to a bad bahaviour of the DB but not related to the user input
    #[error("Database Error: {0}")]
    DatabaseError(String),

    // Any errors related to a bad bahaviour of the server but not related to the user input
    #[error("Unexpected server error: {0}")]
    ServerError(String),

    // Any actions of the user which is not allowed
    #[error("Access denied: {0}")]
    Unauthorized(String),
}

impl From<TtlvError> for KmsError {
    fn from(e: TtlvError) -> Self {
        KmsError::KmipError(ErrorReason::Codec_Error, e.to_string())
    }
}

impl From<sqlx::Error> for KmsError {
    fn from(e: sqlx::Error) -> Self {
        KmsError::DatabaseError(e.to_string())
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

impl From<serde_json::Error> for KmsError {
    fn from(e: serde_json::Error) -> Self {
        KmsError::InvalidRequest(e.to_string())
    }
}

impl From<FormatErr> for KmsError {
    fn from(e: FormatErr) -> Self {
        KmsError::InvalidRequest(e.to_string())
    }
}

impl From<KmipError> for KmsError {
    fn from(e: KmipError) -> Self {
        match e {
            KmipError::InvalidKmipValue(_, s) => KmsError::InvalidRequest(s),
            KmipError::InvalidKmipObject(_, s) => KmsError::InvalidRequest(s),
            KmipError::KmipNotSupported(_, s) => KmsError::InvalidRequest(s),
            KmipError::NotSupported(s) => KmsError::NotSupported(s), //TODO
            KmipError::KmipError(r, s) => KmsError::KmipError(r, s),
        }
    }
}

impl From<LibError> for KmsError {
    fn from(e: LibError) -> Self {
        // TODO: rework that after liberror been reworked
        match e {
            LibError::TtlvError(s) => KmsError::InvalidRequest(s), //TODO
            LibError::RequestFailed(_) => todo!(),
            LibError::ResponseFailed(_) => todo!(),
            LibError::UnexpectedError(_) => todo!(),
            LibError::InvalidKmipValue(_, _) => todo!(),
            LibError::InvalidKmipObject(_, _) => todo!(),
            LibError::CryptographicError(_, _) => todo!(),
            LibError::InvalidRequest(_) => todo!(),
            LibError::Error(s) => KmsError::NotSupported(s),
            LibError::KmipError(_, _) => todo!(),
        }
    }
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
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::error::KmsError::ServerError(format!($fmt, $($arg)*)))
    };
}
