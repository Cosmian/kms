use std::fmt::Display;

use crate::error::CryptoError;

pub(crate) type CryptoResult<R> = Result<R, CryptoError>;

pub trait CryptoResultHelper<T> {
    fn context(self, context: &str) -> CryptoResult<T>;
    fn with_context<D, O>(self, op: O) -> CryptoResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> CryptoResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> CryptoResult<T> {
        self.map_err(|e| CryptoError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> CryptoResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| CryptoError::Default(format!("{}: {e}", op())))
    }
}

impl<T> CryptoResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> CryptoResult<T> {
        self.ok_or_else(|| CryptoError::Default(context.to_owned()))
    }

    fn with_context<D, O>(self, op: O) -> CryptoResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| CryptoError::Default(format!("{}", op())))
    }
}
