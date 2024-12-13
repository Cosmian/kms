//! Copyright 2024 Cosmian Tech SAS

use thiserror::Error;

pub type InterfaceResult<T> = Result<T, InterfaceError>;

#[derive(Error, Debug)]
pub enum InterfaceError {
    #[error("{0}")]
    Default(String),

    #[error("Invalid Request: {0}")]
    InvalidRequest(String),

    #[error("HSM Error: {0}")]
    Hsm(String),

    #[error("Database Error: {0}")]
    Db(String),
}
