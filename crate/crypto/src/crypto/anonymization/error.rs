use core::fmt::Display;

#[derive(Debug)]
pub enum AnoError {
    AnonymizationError(String),
    ConversionError(String),
}

impl From<std::convert::Infallible> for AnoError {
    fn from(value: std::convert::Infallible) -> Self {
        Self::ConversionError(value.to_string())
    }
}
impl From<chrono::ParseError> for AnoError {
    fn from(value: chrono::ParseError) -> Self {
        Self::ConversionError(value.to_string())
    }
}
impl From<regex::Error> for AnoError {
    fn from(value: regex::Error) -> Self {
        Self::ConversionError(value.to_string())
    }
}
impl From<rand_distr::NormalError> for AnoError {
    fn from(value: rand_distr::NormalError) -> Self {
        Self::AnonymizationError(value.to_string())
    }
}
impl From<rand::Error> for AnoError {
    fn from(value: rand::Error) -> Self {
        Self::AnonymizationError(value.to_string())
    }
}
impl From<argon2::Error> for AnoError {
    fn from(value: argon2::Error) -> Self {
        Self::AnonymizationError(value.to_string())
    }
}

impl Display for AnoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AnonymizationError(err) => write!(f, "Anonymization error: {err}"),
            Self::ConversionError(err) => write!(f, "Conversion error: {err}"),
        }
    }
}

/// Construct a generic error from a string.
#[macro_export]
macro_rules! ano_error {
    ($fmt:expr $(,)?) => ({
        AnoError::AnonymizationError(format!($fmt))
    });
    ($fmt:expr, $($arg:tt)*) => {
        AnoError::AnonymizationError(format!($fmt, $($arg)*))
    };
}
