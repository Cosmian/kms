use super::ModuleError;

pub type ModuleResult<R> = Result<R, ModuleError>;

pub(crate) trait MResultHelper<T> {
    fn context(self, context: &str) -> ModuleResult<T>;
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
}

impl<T> MResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> ModuleResult<T> {
        self.ok_or_else(|| ModuleError::Default(context.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{MResultHelper, ModuleResult};
    use crate::ModuleError;

    #[test]
    fn result_context_wraps_the_source_error() {
        let res: ModuleResult<()> = Err(io::Error::other("boom")).context("C_Foo");
        assert!(matches!(
            &res,
            Err(ModuleError::Context { context, source })
                if context == "C_Foo"
                    && matches!(source.as_ref(), ModuleError::Default(msg) if msg == "boom")
        ));
        assert_eq!(
            res.err().map(|e| e.to_string()).as_deref(),
            Some("C_Foo: pkcs11 error: boom")
        );
    }

    #[test]
    fn option_context_becomes_a_default_error() {
        let none: Option<u8> = None;
        assert!(matches!(
            none.context("missing"),
            Err(ModuleError::Default(msg)) if msg == "missing"
        ));
        assert_eq!(Some(3_u8).context("unused").ok(), Some(3));
    }
}
