use super::Pkcs11Error;

pub(crate) type Pkcs11Result<R> = Result<R, Pkcs11Error>;

pub(crate) trait Pkcs11ResultHelper<T> {
    /// Attach a static `context` message to the error.
    fn context(self, context: &str) -> Pkcs11Result<T>;
}

impl<T, E> Pkcs11ResultHelper<T> for Result<T, E>
where
    E: Into<Pkcs11Error>,
{
    fn context(self, context: &str) -> Pkcs11Result<T> {
        self.map_err(|e| {
            let err: Pkcs11Error = e.into();
            Pkcs11Error::Default(format!("{context}: {err}"))
        })
    }
}

impl<T> Pkcs11ResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> Pkcs11Result<T> {
        self.ok_or_else(|| Pkcs11Error::Default(context.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Pkcs11Error, Pkcs11Result, Pkcs11ResultHelper};

    #[test]
    fn result_context_prefixes_the_converted_source_error() {
        let res: Pkcs11Result<()> = Err(std::io::Error::other("boom")).context("reading key");
        assert!(matches!(
            &res,
            Err(Pkcs11Error::Default(msg)) if msg == "reading key: Server error: boom"
        ));
    }

    #[test]
    fn option_context_is_the_error_message() {
        let none: Option<u8> = None;
        assert!(matches!(
            none.context("missing"),
            Err(Pkcs11Error::Default(msg)) if msg == "missing"
        ));
        assert_eq!(Some(1_u8).context("unused").ok(), Some(1));
    }
}
