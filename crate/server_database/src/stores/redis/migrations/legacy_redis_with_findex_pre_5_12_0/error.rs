// represents any error originating from deprecated functions that are used only for migration purposes.
use cloudproof_findex::implementations::redis::FindexRedisError;
use cosmian_kms_interfaces::InterfaceError;
use thiserror::Error;

pub(crate) type LegacyDbResult<R> = Result<R, LegacyDbError>;

#[derive(Error, Debug)]
pub enum LegacyDbError {
    #[error("Redis (legacy) v2.3.0 error: {0}")]
    Redis(#[from] redis_for_migrations::RedisError),

    // When the Redis-Findex's algorithm returns a non-memory related error
    #[error("Cloudproof Findex internal error: {0}")]
    Findex(#[from] FindexRedisError),

    #[error("Conversion Error: {0}")]
    ConversionError(String),

    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Interface error: {0}")]
    Interface(#[from] InterfaceError),

    // Default error
    #[error("{0}")]
    Other(String),
}

impl From<std::string::FromUtf8Error> for LegacyDbError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::ConversionError(e.to_string())
    }
}
