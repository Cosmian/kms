use std::fmt::Display;

use super::KmsCliError;

pub type KmsCliResult<R> = Result<R, KmsCliError>;

/// Trait for providing helper methods for `KmsCliResult`.
pub trait KmsCliResultHelper<T> {
    /// Sets the context for the error.
    ///
    /// # Errors
    ///
    /// Returns a `KmsCliResult` with the specified context.
    fn context(self, context: &str) -> KmsCliResult<T>;

    /// Sets the context for the error using a closure.
    ///
    /// # Errors
    ///
    /// Returns a `KmsCliResult` with the context returned by the closure.
    fn with_context<D, O>(self, op: O) -> KmsCliResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> KmsCliResultHelper<T> for std::result::Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> KmsCliResult<T> {
        self.map_err(|e| KmsCliError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> KmsCliResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| KmsCliError::Default(format!("{}: {e}", op())))
    }
}

impl<T> KmsCliResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> KmsCliResult<T> {
        self.ok_or_else(|| KmsCliError::Default(context.to_owned()))
    }

    fn with_context<D, O>(self, op: O) -> KmsCliResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| KmsCliError::Default(format!("{}", op())))
    }
}
