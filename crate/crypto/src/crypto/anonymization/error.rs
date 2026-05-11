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
    /// A normal distribution parameter error.
    #[error(transparent)]
    NormalDistribution(#[from] rand_distr::NormalError),
    /// A uniform distribution parameter error.
    #[error(transparent)]
    UniformDistribution(#[from] rand_distr::uniform::Error),
}
