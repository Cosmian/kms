use std::fmt::Display;

use serde::{de, ser};

#[derive(Debug)]
pub struct TtlvError {
    pub error: String,
}

impl TtlvError {
    #[must_use]
    pub fn new(s: &str) -> TtlvError {
        TtlvError {
            error: s.to_owned(),
        }
    }
}

impl Display for TtlvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.error)
    }
}

impl std::error::Error for TtlvError {}

impl ser::Error for TtlvError {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        TtlvError {
            error: format!("{msg}"),
        }
    }
}

impl de::Error for TtlvError {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        TtlvError {
            error: format!("{msg}"),
        }
    }
}
