use std::array::TryFromSliceError;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum FindexError {
    #[error("Redis Error: {0}")]
    Redis(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Conversion error: {0}")]
    Conversion(String),

    #[error("The server is compacting the indexes. Please retry later.")]
    Compacting,

    #[allow(dead_code)]
    #[error("{0}")]
    Default(String),
}

impl From<redis::RedisError> for FindexError {
    fn from(err: redis::RedisError) -> Self {
        FindexError::Redis(err.to_string())
    }
}

impl From<cosmian_findex::Error<FindexError>> for FindexError {
    fn from(err: cosmian_findex::Error<FindexError>) -> Self {
        match err {
            cosmian_findex::Error::CryptoError(e) => FindexError::Crypto(e),
            cosmian_findex::Error::CryptoCoreError(e) => FindexError::Crypto(e.to_string()),
            cosmian_findex::Error::ConversionError(e) => FindexError::Conversion(e),
            cosmian_findex::Error::Callback(e) => e,
        }
    }
}

impl From<TryFromSliceError> for FindexError {
    fn from(err: TryFromSliceError) -> Self {
        FindexError::Conversion(err.to_string())
    }
}

impl cosmian_findex::CallbackError for FindexError {}

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! findex_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::FindexError::Default($msg.to_owned()));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::error::FindexError::Default(format!($fmt, $($arg)*)));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! findex_error {
    ($msg:literal $(,)?) => {
        $crate::error::FindexError::Default($msg.to_owned())
    };
    ($err:expr $(,)?) => ({
        $crate::error::FindexError::Default($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::FindexError::Default(format!($fmt, $($arg)*))
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! findex_bail {
    ($msg:literal $(,)?) => {
        return ::core::result::Result::Err($crate::error::FindexError::Default($msg.to_owned()))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::error::FindexError::Default(format!($fmt, $($arg)*)))
    };
}
