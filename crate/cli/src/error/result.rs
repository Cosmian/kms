use std::fmt::Display;

use super::CosmianError;

pub type CosmianResult<R> = Result<R, CosmianError>;

/// Trait for providing helper methods for `CliResult`.
pub trait CosmianResultHelper<T> {
    /// Sets the context for the error.
    ///
    /// # Errors
    ///
    /// Returns a `CliResult` with the specified context.
    fn context(self, context: &str) -> CosmianResult<T>;

    /// Sets the context for the error using a closure.
    ///
    /// # Errors
    ///
    /// Returns a `CliResult` with the context returned by the closure.
    fn with_context<D, O>(self, op: O) -> CosmianResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> CosmianResultHelper<T> for std::result::Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> CosmianResult<T> {
        self.map_err(|e| CosmianError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> CosmianResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| CosmianError::Default(format!("{}: {e}", op())))
    }
}

impl<T> CosmianResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> CosmianResult<T> {
        self.ok_or_else(|| CosmianError::Default(context.to_string()))
    }

    fn with_context<D, O>(self, op: O) -> CosmianResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| CosmianError::Default(format!("{}", op())))
    }
}
