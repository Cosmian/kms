//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_interfaces::InterfaceError;
use thiserror::Error;

pub type PResult<T> = Result<T, PError>;

#[derive(Error, Debug)]
pub enum PError {
    #[error("{0}")]
    Default(String),

    #[error("Error loading the library: {0}")]
    LibLoading(#[from] libloading::Error),

    #[error("PKCS#11 Error: {0}")]
    Pkcs11(String),

    #[error("HSM Error: {0}")]
    Hsm(String),

    #[error(transparent)]
    TryFromIntError(#[from] std::num::TryFromIntError),
}

impl From<InterfaceError> for PError {
    fn from(e: InterfaceError) -> Self {
        PError::Hsm(e.to_string())
    }
}

impl From<PError> for InterfaceError {
    fn from(e: PError) -> Self {
        InterfaceError::Default(e.to_string())
    }
}
