//! Copyright 2024 Cosmian Tech SAS

use thiserror::Error;

pub type InterfaceResult<T> = Result<T, InterfaceError>;

#[derive(Error, Debug)]
pub enum InterfaceError {
    #[error("{0}")]
    Default(String),

    /// Wraps a `std::io::Error` with context, keeping `.kind()` inspectable — unlike
    /// `Default`, which only keeps the rendered message.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Invalid Request: {0}")]
    InvalidRequest(String),

    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("HSM Error: {0}")]
    Hsm(String),

    #[error("Database Error: {0}")]
    Db(String),
}
