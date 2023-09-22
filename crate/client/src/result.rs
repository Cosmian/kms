use std::fmt::Display;

use cosmian_kmip::kmip::kmip_operations::ErrorReason;

use crate::error::RestClientError;

pub type RestClientResult<R> = Result<R, RestClientError>;

pub trait RestClientResultHelper<T> {
    fn reason(self, reason: ErrorReason) -> RestClientResult<T>;
    fn context(self, context: &str) -> RestClientResult<T>;
    fn with_context<D, O>(self, op: O) -> RestClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> RestClientResultHelper<T> for std::result::Result<T, E>
where
    E: std::error::Error,
{
    fn reason(self, reason: ErrorReason) -> RestClientResult<T> {
        self.map_err(|e| RestClientError::KmipError(reason, e.to_string()))
    }

    fn context(self, context: &str) -> RestClientResult<T> {
        self.map_err(|e| RestClientError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> RestClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| RestClientError::Default(format!("{}: {e}", op())))
    }
}

impl<T> RestClientResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> RestClientResult<T> {
        self.ok_or_else(|| RestClientError::Default(context.to_string()))
    }

    fn with_context<D, O>(self, op: O) -> RestClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| RestClientError::Default(format!("{}", op())))
    }

    fn reason(self, reason: ErrorReason) -> RestClientResult<T> {
        self.ok_or_else(|| RestClientError::Default(reason.to_string()))
    }
}
