use std::fmt::Display;

use cosmian_kms_client::cosmian_kmip::kmip::kmip_operations::ErrorReason;

use super::CliError;

pub type CliResult<R> = Result<R, CliError>;

pub trait CliResultHelper<T> {
    fn reason(self, reason: ErrorReason) -> CliResult<T>;
    fn context(self, context: &str) -> CliResult<T>;
    fn with_context<D, O>(self, op: O) -> CliResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> CliResultHelper<T> for std::result::Result<T, E>
where
    E: std::error::Error,
{
    fn reason(self, reason: ErrorReason) -> CliResult<T> {
        self.map_err(|e| CliError::Default(e.to_string()).reason(reason))
    }

    fn context(self, context: &str) -> CliResult<T> {
        self.map_err(|e| CliError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> CliResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| CliError::Default(format!("{}: {e}", op())))
    }
}

impl<T> CliResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> CliResult<T> {
        self.ok_or_else(|| CliError::Default(context.to_string()))
    }

    fn with_context<D, O>(self, op: O) -> CliResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| CliError::Default(format!("{}", op())))
    }

    fn reason(self, reason: ErrorReason) -> CliResult<T> {
        self.ok_or_else(|| CliError::Default(reason.to_string()))
    }
}
