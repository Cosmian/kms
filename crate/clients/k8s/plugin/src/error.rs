use thiserror::Error;

#[derive(Error, Debug)]
pub enum PluginError {
    #[error("KMS client error: {0}")]
    KmsClient(#[from] cosmian_kms_client::KmsClientError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Encrypt operation returned no ciphertext")]
    MissingCiphertext,

    #[error("Decrypt operation returned no plaintext")]
    MissingPlaintext,
}

impl From<PluginError> for tonic::Status {
    fn from(err: PluginError) -> Self {
        match err {
            PluginError::KmsClient(e) => Self::internal(format!("KMS client error: {e}")),
            PluginError::MissingCiphertext | PluginError::MissingPlaintext => {
                Self::internal(err.to_string())
            }
            PluginError::Config(msg) => Self::failed_precondition(msg),
            PluginError::Io(e) => Self::internal(format!("I/O error: {e}")),
        }
    }
}
