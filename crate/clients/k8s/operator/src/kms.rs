use cosmian_kmip::kmip_2_1::{
    kmip_objects::Object, kmip_operations::Get, kmip_types::UniqueIdentifier,
};
use cosmian_kms_client::{KmsClient, KmsClientConfig};
use tracing::debug;

use crate::error::OperatorError;

/// Thin wrapper around [`KmsClient`] for operator use cases.
pub struct KmsClientWrapper {
    client: KmsClient,
}

impl KmsClientWrapper {
    /// Create a new wrapper from config.
    pub fn new(config: KmsClientConfig) -> Result<Self, OperatorError> {
        let client = KmsClient::new_with_config(config)
            .map_err(|e| OperatorError::Config(format!("failed to build KMS client: {e}")))?;
        Ok(Self { client })
    }

    /// Retrieve the raw secret bytes for a KMS object UID.
    ///
    /// Supports `SecretData`, `SymmetricKey`, and any object whose `KeyBlock`
    /// exposes `key_bytes()`.  The bytes are returned as-is — the caller is
    /// responsible for interpreting the encoding (UTF-8, binary, …).
    pub async fn get_secret_bytes(&self, uid: &str) -> Result<Vec<u8>, OperatorError> {
        debug!(uid, "fetching secret from KMS");

        let response = self
            .client
            .get(Get {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                ..Get::default()
            })
            .await?;

        extract_bytes(uid, &response.object)
    }
}

/// Extract raw bytes from any KMIP object that carries a `KeyBlock`.
fn extract_bytes(uid: &str, object: &Object) -> Result<Vec<u8>, OperatorError> {
    Ok(object
        .key_block()
        .map_err(|e| OperatorError::UnexpectedObjectType {
            uid: uid.to_owned(),
            got: format!("{:?}", object.object_type()),
            cause: e.to_string(),
        })?
        .key_bytes()
        .map_err(|e| OperatorError::Config(format!("cannot extract bytes for uid {uid}: {e}")))?
        .to_vec())
}
