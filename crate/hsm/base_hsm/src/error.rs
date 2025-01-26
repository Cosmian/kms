//! Copyright 2024 Cosmian Tech SAS

use cosmian_kms_interfaces::InterfaceError;
use thiserror::Error;

pub type HResult<T> = Result<T, HError>;

#[derive(Error, Debug)]
pub enum HError {
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

impl From<InterfaceError> for HError {
    fn from(e: InterfaceError) -> Self {
        HError::Hsm(e.to_string())
    }
}

impl From<HError> for InterfaceError {
    fn from(e: HError) -> Self {
        InterfaceError::Default(e.to_string())
    }
}
