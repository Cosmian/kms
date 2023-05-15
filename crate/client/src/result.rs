use std::fmt::Display;

use cosmian_kmip::kmip::kmip_operations::ErrorReason;

use super::KmsClientError;

pub type ClientResult<R> = Result<R, KmsClientError>;

pub trait ClientResultHelper<T> {
    fn reason(self, reason: ErrorReason) -> ClientResult<T>;
    fn context(self, context: &str) -> ClientResult<T>;
    fn with_context<D, O>(self, op: O) -> ClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> ClientResultHelper<T> for std::result::Result<T, E>
where
    E: std::error::Error,
{
    fn reason(self, reason: ErrorReason) -> ClientResult<T> {
        self.map_err(|e| KmsClientError::KmipError(reason, e.to_string()))
    }

    fn context(self, context: &str) -> ClientResult<T> {
        self.map_err(|e| KmsClientError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> ClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| KmsClientError::Default(format!("{}: {e}", op())))
    }
}

impl<T> ClientResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> ClientResult<T> {
        self.ok_or_else(|| KmsClientError::Default(context.to_string()))
    }

    fn with_context<D, O>(self, op: O) -> ClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| KmsClientError::Default(format!("{}", op())))
    }

    fn reason(self, reason: ErrorReason) -> ClientResult<T> {
        self.ok_or_else(|| KmsClientError::Default(reason.to_string()))
    }
}
