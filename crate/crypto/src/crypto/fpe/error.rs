use thiserror::Error;

#[derive(Debug, Error)]
pub enum FPEError {
    /// The alphabet or radix configuration is invalid.
    #[error("Alphabet error: {0}")]
    AlphabetError(String),
    /// An FF1 operation (init, encrypt, decrypt) or value parsing failed.
    #[error("FPE operation failed: {0}")]
    OperationFailed(String),
    /// A value, index, or length is outside the permitted range.
    #[error("Out of bounds: {0}")]
    OutOfBounds(String),
    /// The key length does not match the required length.
    #[error("Invalid key size {0}, expected: {1}")]
    KeySize(usize, usize),
    /// A numeric type conversion failed.
    #[error("Conversion error: {0}")]
    ConversionError(String),
}

impl From<std::num::TryFromIntError> for FPEError {
    fn from(value: std::num::TryFromIntError) -> Self {
        Self::ConversionError(value.to_string())
    }
}
