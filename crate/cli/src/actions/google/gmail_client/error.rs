/// Errors that may occur during any of the operations in this lib.
#[derive(Debug, thiserror::Error)]
pub enum GoogleApiError {
    /// A tls error occurred.
    #[error("OpenSSL error stack `{0}`")]
    OpenSSLError(#[from] openssl::error::ErrorStack),
    /// A jwt error occurred.
    #[error("JWT error `{0}`")]
    JwtError(#[from] jwt::Error),
    /// Got an error whilst processing a request.
    #[error("Reqwest error `{0}`")]
    ReqwestError(#[from] reqwest::Error),
    /// An error occurred whilst retrieving the access token.
    #[error("Token retrieval error `{0}`")]
    TokenRetrivalError(String),
    /// An IO error occurred.
    #[error("Failed to load service account file `{0}`")]
    ServiceAccountLoadFailure(std::io::Error),
    /// A serialization error occurred
    #[error("Serialization error `{0}`")]
    SerdeError(#[from] serde_json::Error),
}

// /// A `Result` alias with a `GoogleApiError` for the Err case.
// pub type Result<T> = std::result::Result<T, GoogleApiError>;
