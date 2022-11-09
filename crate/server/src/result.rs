use cosmian_kmip::kmip::kmip_operations::ErrorReason;

use crate::error::KmsError;

pub type KResult<R> = Result<R, KmsError>;

pub trait KResultHelper<T> {
    fn reason(self, reason: ErrorReason) -> KResult<T>;
    fn context(self, context: &str) -> KResult<T>;
    fn with_context<O>(self, op: O) -> KResult<T>
    where
        O: FnOnce() -> String;
}

impl<T, E> KResultHelper<T> for std::result::Result<T, E>
where
    E: std::error::Error,
{
    fn reason(self, reason: ErrorReason) -> KResult<T> {
        self.map_err(|e| KmsError::ServerError(e.to_string()).reason(reason))
    }

    fn context(self, context: &str) -> KResult<T> {
        self.map_err(|e| KmsError::ServerError(format!("{context}: {e}")))
    }

    fn with_context<O>(self, op: O) -> KResult<T>
    where
        O: FnOnce() -> String,
    {
        self.map_err(|e| KmsError::ServerError(format!("{}: {e}", op())))
    }
}

impl<T> KResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> KResult<T> {
        self.ok_or_else(|| KmsError::ServerError(context.to_string()))
    }

    fn with_context<O>(self, op: O) -> KResult<T>
    where
        O: FnOnce() -> String,
    {
        self.ok_or_else(|| KmsError::ServerError(op()))
    }

    fn reason(self, reason: ErrorReason) -> KResult<T> {
        self.ok_or_else(|| KmsError::ServerError(reason.to_string()))
    }
}
