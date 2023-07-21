use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{Encrypt, EncryptResponse},
    kmip_types::StateEnumeration,
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use tracing::trace;

use crate::{
    core::KMS, database::object_with_metadata::ObjectWithMetadata, error::KmsError, result::KResult,
};

pub async fn encrypt(
    kms: &KMS,
    request: Encrypt,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<EncryptResponse> {
    trace!("encrypt : {}", serde_json::to_string(&request)?);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(&uid_or_tags, user, ObjectOperationType::Encrypt, params)
        .await?
        .into_iter()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            owm.state == StateEnumeration::Active
                && (object_type == ObjectType::PublicKey || object_type == ObjectType::SymmetricKey)
        })
        .collect::<Vec<ObjectWithMetadata>>();

    // there can only be one key
    let owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::ItemNotFound(uid_or_tags.to_owned()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many objects for key {uid_or_tags}",
        )))
    }

    kms.get_encryption_system(owm, params)
        .await?
        .encrypt(&request)
        .map_err(Into::into)
}
