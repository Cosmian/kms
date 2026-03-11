use std::fmt::Display;

use super::HttpClientError;

pub(crate) type HttpClientResult<R> = Result<R, HttpClientError>;

#[allow(dead_code)]
pub(crate) trait HttpClientResultHelper<T> {
    fn context(self, context: &str) -> HttpClientResult<T>;
    fn with_context<D, O>(self, op: O) -> HttpClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> HttpClientResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> HttpClientResult<T> {
        self.map_err(|e| HttpClientError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> HttpClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| HttpClientError::Default(format!("{}: {e}", op())))
    }
}

impl<T> HttpClientResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> HttpClientResult<T> {
        self.ok_or_else(|| HttpClientError::Default(context.to_owned()))
    }

    fn with_context<D, O>(self, op: O) -> HttpClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| HttpClientError::Default(format!("{}", op())))
    }
}
