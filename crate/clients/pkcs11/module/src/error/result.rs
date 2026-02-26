use std::fmt::Display;

use super::ModuleError;

pub type ModuleResult<R> = Result<R, ModuleError>;

#[expect(dead_code)]
pub(crate) trait MResultHelper<T> {
    fn context(self, context: &str) -> ModuleResult<T>;
    fn with_context<D, O>(self, op: O) -> ModuleResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> MResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> ModuleResult<T> {
        self.map_err(|e| ModuleError::Context {
            context: context.to_owned(),
            source: Box::new(ModuleError::Default(e.to_string())),
        })
    }

    fn with_context<D, O>(self, op: O) -> ModuleResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| ModuleError::Context {
            context: format!("{}", op()),
            source: Box::new(ModuleError::Default(e.to_string())),
        })
    }
}

impl<T> MResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> ModuleResult<T> {
        self.ok_or_else(|| ModuleError::Default(context.to_owned()))
    }

    fn with_context<D, O>(self, op: O) -> ModuleResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| ModuleError::Default(format!("{}", op())))
    }
}
