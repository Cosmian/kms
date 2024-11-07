use std::fmt::Display;

use super::KmsClientError;

pub type KmsClientResult<R> = Result<R, KmsClientError>;

#[allow(dead_code)]
pub(crate) trait KmsClientResultHelper<T> {
    fn context(self, context: &str) -> KmsClientResult<T>;
    fn with_context<D, O>(self, op: O) -> KmsClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> KmsClientResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> KmsClientResult<T> {
        self.map_err(|e| KmsClientError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> KmsClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| KmsClientError::Default(format!("{}: {e}", op())))
    }
}

impl<T> KmsClientResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> KmsClientResult<T> {
        self.ok_or_else(|| KmsClientError::Default(context.to_string()))
    }

    fn with_context<D, O>(self, op: O) -> KmsClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| KmsClientError::Default(format!("{}", op())))
    }
}
