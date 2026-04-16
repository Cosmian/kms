use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnoError {
    /// A generic anonymization logic error.
    #[error("Anonymization error: {0}")]
    AnonymizationError(String),
    /// A date/time parsing failure.
    #[error(transparent)]
    ChronoParse(#[from] chrono::ParseError),
    /// A regex compilation failure.
    #[error(transparent)]
    Regex(#[from] regex::Error),
    /// An Argon2 hashing failure.
    #[error("Argon2 error: {0}")]
    Argon2(String),
    /// A random number generator failure.
    #[error(transparent)]
    Rand(#[from] rand::Error),
    /// A normal distribution parameter error.
    #[error(transparent)]
    NormalDistribution(#[from] rand_distr::NormalError),
}
