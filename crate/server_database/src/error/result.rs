use crate::error::DbError;

pub(crate) type DbResult<R> = Result<R, DbError>;

/// A helper trait for `DbResult` that provides additional methods for error handling.
pub(crate) trait DbResultHelper<T> {
    /// Sets the context for the error.
    ///
    /// # Errors
    ///
    /// Returns a `DbResult` with the specified context if the original result is an error.
    fn context(self, context: &str) -> DbResult<T>;
}

impl<T, E> DbResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> DbResult<T> {
        self.map_err(|e| DbError::ServerError(format!("{context}: {e}")))
    }
}

impl<T> DbResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> DbResult<T> {
        self.ok_or_else(|| DbError::ServerError(context.to_owned()))
    }
}
