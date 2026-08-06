use thiserror::Error;

/// Errors that can occur in the CSI provider service.
#[derive(Error, Debug)]
pub enum CsiProviderError {
    /// Error originating from the KMS client.
    #[error("KMS client error: {0}")]
    KmsClient(#[from] cosmian_kms_client::KmsClientError),

    /// The attributes JSON from the `SecretProviderClass` could not be parsed.
    #[error("invalid SecretProviderClass attributes: {0}")]
    InvalidAttributes(String),

    /// No objects were declared in the `SecretProviderClass` parameters.
    #[error("no objects declared in SecretProviderClass parameters")]
    NoObjects,

    /// KMS returned an object type whose key material could not be extracted.
    #[error("cannot extract bytes from KMS object '{uid}': {cause}")]
    UnextractableObject { uid: String, cause: String },

    /// I/O error (e.g. writing to tmpfs).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),
}

impl From<CsiProviderError> for tonic::Status {
    fn from(err: CsiProviderError) -> Self {
        match &err {
            CsiProviderError::KmsClient(_)
            | CsiProviderError::UnextractableObject { .. }
            | CsiProviderError::Io(_) => Self::internal(err.to_string()),
            CsiProviderError::InvalidAttributes(_) | CsiProviderError::NoObjects => {
                Self::invalid_argument(err.to_string())
            }
            CsiProviderError::Config(_) => Self::failed_precondition(err.to_string()),
        }
    }
}
