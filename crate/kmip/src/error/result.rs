use std::fmt::Display;

use crate::{error::KmipError, kmip::kmip_operations::ErrorReason};

pub(crate) type KmipResult<R> = Result<R, KmipError>;

pub trait KmipResultHelper<T> {
    fn reason(self, reason: ErrorReason) -> KmipResult<T>;
    fn context(self, context: &str) -> KmipResult<T>;
    fn with_context<D, O>(self, op: O) -> KmipResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> KmipResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn reason(self, reason: ErrorReason) -> KmipResult<T> {
        self.map_err(|e| KmipError::Default(e.to_string()).reason(reason))
    }

    fn context(self, context: &str) -> KmipResult<T> {
        self.map_err(|e| KmipError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> KmipResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| KmipError::Default(format!("{}: {e}", op())))
    }
}

impl<T> KmipResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> KmipResult<T> {
        self.ok_or_else(|| KmipError::Default(context.to_owned()))
    }

    fn with_context<D, O>(self, op: O) -> KmipResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| KmipError::Default(format!("{}", op())))
    }

    fn reason(self, reason: ErrorReason) -> KmipResult<T> {
        self.ok_or_else(|| KmipError::Default(reason.to_string()))
    }
}
