use cosmian_kmip::kmip::kmip_operations::{Encrypt, EncryptResponse};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use tracing::trace;

use crate::{
    core::{operations::uids::uid_from_identifier_tags, KMS},
    error::KmsError,
    result::KResult,
};

pub async fn encrypt(
    kms: &KMS,
    request: Encrypt,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<EncryptResponse> {
    trace!("encrypt : {}", serde_json::to_string(&request)?);

    // there must be an identifier
    let identifier = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // retrieve from tags or use passed identifier
    let unique_identifier =
        uid_from_identifier_tags(kms, &identifier, user, ObjectOperationType::Encrypt, params)
            .await?
            .unwrap_or(identifier);

    kms.get_encryption_system(&unique_identifier, user, params)
        .await?
        .encrypt(&request)
        .map_err(Into::into)
}
