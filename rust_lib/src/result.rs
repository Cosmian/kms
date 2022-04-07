use cosmian_kms_common::kmip::kmip_operations::ErrorReason;

use crate::error::LibError;

pub type LibResult<R> = Result<R, LibError>;

pub trait LibResultHelper<T> {
    fn reason(self, reason: ErrorReason) -> LibResult<T>;
    fn context(self, context: &str) -> LibResult<T>;
    fn with_context<O>(self, op: O) -> LibResult<T>
    where
        O: FnOnce() -> String;
}

impl<T, E> LibResultHelper<T> for std::result::Result<T, E>
where
    E: std::error::Error,
{
    fn reason(self, reason: ErrorReason) -> LibResult<T> {
        self.map_err(|e| LibError::Error(e.to_string()).reason(reason))
    }

    fn context(self, context: &str) -> LibResult<T> {
        self.map_err(|e| LibError::Error(format!("{}: {}", context, e)))
    }

    fn with_context<O>(self, op: O) -> LibResult<T>
    where
        O: FnOnce() -> String,
    {
        self.map_err(|e| LibError::Error(format!("{}: {}", op(), e)))
    }
}

impl<T> LibResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> LibResult<T> {
        self.ok_or_else(|| LibError::Error(context.to_string()))
    }

    fn with_context<O>(self, op: O) -> LibResult<T>
    where
        O: FnOnce() -> String,
    {
        self.ok_or_else(|| LibError::Error(op()))
    }

    fn reason(self, reason: ErrorReason) -> LibResult<T> {
        self.ok_or_else(|| LibError::Error(reason.to_string()))
    }
}
