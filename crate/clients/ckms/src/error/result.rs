use std::fmt::Display;

use super::CosmianError;

pub type CosmianResult<R> = Result<R, CosmianError>;

pub trait CosmianResultHelper<T> {
    fn context(self, context: &str) -> CosmianResult<T>;
    fn with_context<D, O>(self, op: O) -> CosmianResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> CosmianResultHelper<T> for Result<T, E>
where
    E: Into<CosmianError>,
{
    fn context(self, context: &str) -> CosmianResult<T> {
        self.map_err(|e| {
            let err: CosmianError = e.into();
            CosmianError::Default(format!("{context}: {err}"))
        })
    }

    fn with_context<D, O>(self, op: O) -> CosmianResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| {
            let err: CosmianError = e.into();
            CosmianError::Default(format!("{}: {err}", op()))
        })
    }
}

impl<T> CosmianResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> CosmianResult<T> {
        self.ok_or_else(|| CosmianError::Default(context.to_owned()))
    }

    fn with_context<D, O>(self, op: O) -> CosmianResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| CosmianError::Default(format!("{}", op())))
    }
}
