use thiserror::Error;

#[derive(Error, Debug)]
pub enum FindexError {
    #[error("Redis Error: {0}")]
    Redis(String),

    #[error("{0}")]
    Default(String),
}

impl From<redis::RedisError> for FindexError {
    fn from(err: redis::RedisError) -> Self {
        FindexError::Redis(err.to_string())
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
