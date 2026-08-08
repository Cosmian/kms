use thiserror::Error;

#[derive(Debug, Error)]
pub enum OperatorError {
    #[error("KMS client error: {0}")]
    KmsClient(#[from] cosmian_kms_client::KmsClientError),

    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("KMS returned unexpected object type for uid {uid}: got {got}; cause: {cause}")]
    UnexpectedObjectType {
        uid: String,
        got: String,
        cause: String,
    },

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("TLS error: {0}")]
    Tls(String),
}
