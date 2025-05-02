use thiserror::Error;

/// Errors that may occur during any of the operations in this lib.
#[derive(Error, Debug)]
pub enum GoogleApiError {
    /// A jwt error occurred.
    #[error("JWT error `{0}`")]
    Jwt(jwt_simple::Error),
    /// Got an error whilst processing a request.
    #[error("Reqwest error `{0}`")]
    Reqwest(reqwest::Error),
    // A serialization error occurred
    #[error("Serialization error `{0}`")]
    Serde(serde_json::Error),
}

impl From<jwt_simple::Error> for GoogleApiError {
    fn from(e: jwt_simple::Error) -> Self {
        Self::Jwt(e)
    }
}

impl From<reqwest::Error> for GoogleApiError {
    fn from(e: reqwest::Error) -> Self {
        Self::Reqwest(e)
    }
}

impl From<serde_json::Error> for GoogleApiError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e)
    }
}
