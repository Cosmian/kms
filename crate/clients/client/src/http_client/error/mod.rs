use std::io;

use der::Error as DerError;
use thiserror::Error;
use url::ParseError;

pub(crate) mod result;

#[derive(Error, Debug)]
pub enum HttpClientError {
    #[error("Invalid conversion: {0}")]
    Conversion(String),

    #[error("{0}")]
    Default(String),

    #[error("Not Supported: {0}")]
    NotSupported(String),

    #[error("Ratls Error: {0}")]
    RatlsError(String),

    #[error("URL Error: {0}")]
    Url(String),

    #[error("REST Request Failed: {0}")]
    RequestFailed(String),

    #[error("REST Response Conversion Failed: {0}")]
    ResponseFailed(String),

    #[error("Unexpected Error: {0}")]
    UnexpectedError(String),
}

impl From<reqwest::Error> for HttpClientError {
    fn from(e: reqwest::Error) -> Self {
        Self::Default(format!("{e}: Details: {e:?}"))
    }
}

impl From<reqwest::header::InvalidHeaderValue> for HttpClientError {
    fn from(e: reqwest::header::InvalidHeaderValue) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<io::Error> for HttpClientError {
    fn from(e: io::Error) -> Self {
        Self::Default(e.to_string())
    }
}

impl From<DerError> for HttpClientError {
    fn from(e: DerError) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl From<ParseError> for HttpClientError {
    fn from(e: ParseError) -> Self {
        Self::Url(e.to_string())
    }
}
