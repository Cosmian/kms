use std::fmt::Display;

use serde::{de, ser};

use crate::error::KmipError;

#[derive(Debug)]
pub struct TtlvError {
    pub error: String,
}

impl TtlvError {
    #[must_use]
    pub fn new(s: &str) -> Self {
        Self {
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
        Self {
            error: format!("{msg}"),
        }
    }
}

impl de::Error for TtlvError {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        Self {
            error: format!("{msg}"),
        }
    }
}

impl From<std::io::Error> for TtlvError {
    fn from(err: std::io::Error) -> Self {
        Self::new(&err.to_string())
    }
}

impl From<&str> for TtlvError {
    fn from(s: &str) -> Self {
        Self { error: s.into() }
    }
}

impl From<String> for TtlvError {
    fn from(s: String) -> Self {
        Self { error: s }
    }
}

impl From<time::Error> for TtlvError {
    fn from(err: time::error::Error) -> Self {
        Self::new(&err.to_string())
    }
}

impl From<KmipError> for TtlvError {
    fn from(err: KmipError) -> Self {
        Self::new(&err.to_string())
    }
}

impl From<strum::ParseError> for TtlvError {
    fn from(err: strum::ParseError) -> Self {
        Self::new(&err.to_string())
    }
}

impl From<time::error::ComponentRange> for TtlvError {
    fn from(err: time::error::ComponentRange) -> Self {
        Self::new(&err.to_string())
    }
}
