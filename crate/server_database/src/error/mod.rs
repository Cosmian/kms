mod db_error;
mod result;

pub use db_error::DbError;
pub use result::{DbResult, DbResultHelper};

/// Return early with an error if a condition is not satisfied.
///
/// This macro is equivalent to `if !$cond { return Err(From::from($err)); }`.
#[macro_export]
macro_rules! db_ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($crate::db_error!($msg));
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            return ::core::result::Result::Err($err);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return ::core::result::Result::Err($crate::db_error!($fmt, $($arg)*));
        }
    };
}

/// Construct a server error from a string.
#[macro_export]
macro_rules! db_error {
    ($msg:literal) => {
        $crate::error::DbError::DatabaseError(::core::format_args!($msg).to_string())
    };
    ($err:expr $(,)?) => ({
        $crate::error::DbError::DatabaseError($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::DbError::DatabaseError(::core::format_args!($fmt, $($arg)*).to_string())
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! db_bail {
    ($msg:literal) => {
        return ::core::result::Result::Err($crate::db_error!($msg))
    };
    ($err:expr $(,)?) => {
        return ::core::result::Result::Err($err)
    };
    ($fmt:expr, $($arg:tt)*) => {
        return ::core::result::Result::Err($crate::db_error!($fmt, $($arg)*))
    };
}
