use crate::error::DbError;

pub type DbResult<R> = Result<R, DbError>;

/// A helper trait for `DbResult` that provides additional methods for error handling.
pub trait DbResultHelper<T> {
    /// Sets the context for the error.
    ///
    /// # Errors
    ///
    /// Returns a `DbResult` with the specified context if the original result is an error.
    fn context(self, context: &str) -> DbResult<T>;

    #[allow(dead_code)]
    /// Sets the context for the error using a closure.
    ///
    /// # Errors
    ///
    /// Returns a `DbResult` with the context returned by the closure if the original result is an error.
    fn with_context<O>(self, op: O) -> DbResult<T>
    where
        O: FnOnce() -> String;
}

impl<T, E> DbResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> DbResult<T> {
        self.map_err(|e| DbError::ServerError(format!("{context}: {e}")))
    }

    fn with_context<O>(self, op: O) -> DbResult<T>
    where
        O: FnOnce() -> String,
    {
        self.map_err(|e| DbError::ServerError(format!("{}: {e}", op())))
    }
}

impl<T> DbResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> DbResult<T> {
        self.ok_or_else(|| DbError::ServerError(context.to_owned()))
    }

    fn with_context<O>(self, op: O) -> DbResult<T>
    where
        O: FnOnce() -> String,
    {
        self.ok_or_else(|| DbError::ServerError(op()))
    }
}
