use core::fmt::Display;

#[derive(Debug)]
pub enum FPEError {
    Generic(String),
    FPE(String),
    KeySize(usize, usize),
    ConversionError(String),
}

impl From<std::num::TryFromIntError> for FPEError {
    fn from(value: std::num::TryFromIntError) -> Self {
        Self::ConversionError(value.to_string())
    }
}

impl Display for FPEError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generic(err) => write!(f, "Anonymization error: {err}"),
            Self::FPE(err) => write!(f, "FPE error: {err}"),
            Self::KeySize(given, expected) => {
                write!(f, "Invalid key size {given}, expected: {expected}")
            }
            Self::ConversionError(err) => write!(f, "Conversion error: {err}"),
        }
    }
}

impl std::error::Error for FPEError {}
