use std::fmt::Display;

use super::Pkcs11Error;

pub(crate) type Pkcs11Result<R> = Result<R, Pkcs11Error>;

#[allow(dead_code)]
pub(crate) trait Pkcs11ResultHelper<T> {
    fn context(self, context: &str) -> Pkcs11Result<T>;
    fn with_context<D, O>(self, op: O) -> Pkcs11Result<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> Pkcs11ResultHelper<T> for std::result::Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> Pkcs11Result<T> {
        self.map_err(|e| Pkcs11Error::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> Pkcs11Result<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| Pkcs11Error::Default(format!("{}: {e}", op())))
    }
}

impl<T> Pkcs11ResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> Pkcs11Result<T> {
        self.ok_or_else(|| Pkcs11Error::Default(context.to_string()))
    }

    fn with_context<D, O>(self, op: O) -> Pkcs11Result<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| Pkcs11Error::Default(format!("{}", op())))
    }
}
