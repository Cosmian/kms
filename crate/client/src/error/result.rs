use std::fmt::Display;

use super::ClientError;

pub type ClientResult<R> = Result<R, ClientError>;

pub trait RestClientResultHelper<T> {
    fn context(self, context: &str) -> ClientResult<T>;
    fn with_context<D, O>(self, op: O) -> ClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> RestClientResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> ClientResult<T> {
        self.map_err(|e| ClientError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> ClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| ClientError::Default(format!("{}: {e}", op())))
    }
}

impl<T> RestClientResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> ClientResult<T> {
        self.ok_or_else(|| ClientError::Default(context.to_string()))
    }

    fn with_context<D, O>(self, op: O) -> ClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| ClientError::Default(format!("{}", op())))
    }
}
