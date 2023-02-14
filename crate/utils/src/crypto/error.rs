use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Conversion Error: {0}")]
    ConversionError(String),

    #[error("Invalid size: {0}")]
    InvalidSize(String),

    #[error("Not Supported: {0}")]
    NotSupported(String),
}

impl From<std::array::TryFromSliceError> for CryptoError {
    fn from(value: std::array::TryFromSliceError) -> Self {
        Self::ConversionError(value.to_string())
    }
}
