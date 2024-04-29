/// Errors that may occur during any of the operations in this lib.
#[derive(Debug, thiserror::Error)]
pub enum GoogleApiError {
    /// A jwt error occurred.
    #[error("JWT error `{0}`")]
    JwtError(#[from] jwt_simple::Error),
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
