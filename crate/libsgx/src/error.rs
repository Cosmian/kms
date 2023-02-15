use base64;
use jsonwebtoken;
use openssl;
use reqwest::Error;
use serde_json;
use thiserror::Error;
use url::ParseError;

#[derive(Error, Debug)]
pub enum SgxError {
    #[error("{0}")]
    QuoteMalformed(String),

    #[error("{0}")]
    QuoteReportDataMalformed(String),

    #[error("{0}")]
    InvalidAPIParameter(String),

    #[error("{0}")]
    RemoteAttesterRequestFailed(String),

    #[error("{0}")]
    RemoteAttesterTokenMalformed(String),

    #[error("{0}")]
    RemoteAttesterCertsMalformed(String),

    #[error("{0}")]
    EnclaveIOError(String),
}

impl From<base64::DecodeError> for SgxError {
    fn from(e: base64::DecodeError) -> Self {
        Self::QuoteMalformed(e.to_string())
    }
}

impl From<ParseError> for SgxError {
    fn from(e: ParseError) -> Self {
        Self::QuoteMalformed(e.to_string())
    }
}

impl From<Error> for SgxError {
    fn from(e: Error) -> Self {
        Self::RemoteAttesterRequestFailed(e.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for SgxError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        Self::RemoteAttesterTokenMalformed(e.to_string())
    }
}

impl From<serde_json::Error> for SgxError {
    fn from(e: serde_json::Error) -> Self {
        Self::RemoteAttesterTokenMalformed(e.to_string())
    }
}

impl From<openssl::error::ErrorStack> for SgxError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::RemoteAttesterCertsMalformed(e.to_string())
    }
}

impl From<std::io::Error> for SgxError {
    fn from(e: std::io::Error) -> Self {
        Self::EnclaveIOError(e.to_string())
    }
}
