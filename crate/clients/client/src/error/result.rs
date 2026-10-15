use std::fmt::Display;

use super::KmsClientError;

pub type KmsClientResult<R> = Result<R, KmsClientError>;

pub(crate) trait KmsClientResultHelper<T> {
    /// Attach a static `context` message to the error.
    fn context(self, context: &str) -> KmsClientResult<T>;
    /// Attach a lazily-built context message to the error.
    fn with_context<D, O>(self, op: O) -> KmsClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D;
}

impl<T, E> KmsClientResultHelper<T> for Result<T, E>
where
    E: std::error::Error,
{
    fn context(self, context: &str) -> KmsClientResult<T> {
        self.map_err(|e| KmsClientError::Default(format!("{context}: {e}")))
    }

    fn with_context<D, O>(self, op: O) -> KmsClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.map_err(|e| KmsClientError::Default(format!("{}: {e}", op())))
    }
}

impl<T> KmsClientResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> KmsClientResult<T> {
        self.ok_or_else(|| KmsClientError::Default(context.to_owned()))
    }

    fn with_context<D, O>(self, op: O) -> KmsClientResult<T>
    where
        D: Display + Send + Sync + 'static,
        O: FnOnce() -> D,
    {
        self.ok_or_else(|| KmsClientError::Default(format!("{}", op())))
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, io};

    use super::{KmsClientResult, KmsClientResultHelper};

    fn io_failure() -> Result<(), io::Error> {
        Err(io::Error::new(io::ErrorKind::NotFound, "no such file"))
    }

    #[test]
    fn result_context_prefixes_the_source_error() {
        let res: KmsClientResult<()> = io_failure().context("could not open");
        assert_eq!(
            res.err().map(|e| e.to_string()).as_deref(),
            Some("could not open: no such file")
        );
    }

    #[test]
    fn result_with_context_builds_message_lazily_and_only_on_error() {
        let res: KmsClientResult<()> = io_failure().with_context(|| format!("step {}", 3));
        assert_eq!(
            res.err().map(|e| e.to_string()).as_deref(),
            Some("step 3: no such file")
        );

        let ok: Result<u8, io::Error> = Ok(7);
        let calls = Cell::new(0_u8);
        let res = ok.with_context(|| {
            calls.set(calls.get() + 1);
            "unused"
        });
        assert_eq!(res.ok(), Some(7));
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn option_context_uses_the_message_as_the_error() {
        let none: Option<u8> = None;
        assert_eq!(
            none.context("missing value")
                .err()
                .map(|e| e.to_string())
                .as_deref(),
            Some("missing value")
        );
        assert_eq!(
            none.with_context(|| "lazy missing value")
                .err()
                .map(|e| e.to_string())
                .as_deref(),
            Some("lazy missing value")
        );
        assert_eq!(Some(5_u8).context("unused").ok(), Some(5));
    }
}
