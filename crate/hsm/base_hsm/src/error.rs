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
        Self::Hsm(e.to_string())
    }
}

impl From<HError> for InterfaceError {
    fn from(e: HError) -> Self {
        Self::Default(e.to_string())
    }
}

pub(crate) trait HResultHelper<T> {
    fn context(self, context: &str) -> HResult<T>;
}

impl<T, E> HResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> HResult<T> {
        self.map_err(|e| HError::Default(format!("{context}: {e}")))
    }
}

impl<T> HResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> HResult<T> {
        self.ok_or_else(|| HError::Default(context.to_owned()))
    }
}
