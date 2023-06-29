use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{Decrypt, DecryptResponse},
    kmip_types::StateEnumeration,
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use tracing::trace;

use crate::{
    core::KMS, database::object_with_metadata::ObjectWithMetadata, error::KmsError, result::KResult,
};

pub async fn decrypt(
    kms: &KMS,
    request: Decrypt,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<DecryptResponse> {
    trace!("Decrypt: {:?}", &request.unique_identifier);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(&uid_or_tags, user, ObjectOperationType::Decrypt, params)
        .await?
        .into_iter()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            owm.state == StateEnumeration::Active
                && (object_type == ObjectType::PrivateKey
                    || object_type == ObjectType::SymmetricKey)
        })
        .collect::<Vec<ObjectWithMetadata>>();

    // there can only be one key
    let owm = match owm_s.len() {
        0 => return Err(KmsError::ItemNotFound(uid_or_tags)),
        1 => owm_s.pop().expect("failed extracting the key"),
        _ => {
            return Err(KmsError::InvalidRequest(format!(
                "too many items for {uid_or_tags}",
            )))
        }
    };

    // decrypt
    kms.get_decryption_system(Default::default(), owm, params)
        .await?
        .decrypt(&request)
        .map_err(Into::into)
}
