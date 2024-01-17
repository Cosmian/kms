use cloudproof::reexport::cover_crypt::Covercrypt;
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{Decrypt, DecryptResponse, ErrorReason},
    kmip_types::{KeyFormatType, StateEnumeration},
};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, ObjectOperationType},
    crypto::cover_crypt::attributes,
};
use tracing::trace;

use crate::{
    core::KMS,
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    result::{KResult, KResultHelper},
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
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Decrypt: unique_identifier must be a string")?;
    trace!("decrypt: uid_or_tags: {uid_or_tags}");

    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(uid_or_tags, user, ObjectOperationType::Decrypt, params)
        .await?
        .into_values()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            if owm.state != StateEnumeration::Active {
                return false
            }
            if object_type == ObjectType::SymmetricKey {
                return true
            }
            if object_type != ObjectType::PrivateKey {
                return false
            }
            if let Ok(attributes) = owm.object.attributes() {
                // is it a Covercrypt secret key?
                if attributes.key_format_type == Some(KeyFormatType::CoverCryptSecretKey) {
                    // does it have an access policy that allows decryption?
                    return attributes::access_policy_from_attributes(attributes).is_ok()
                }
            }
            true
        })
        .collect::<Vec<ObjectWithMetadata>>();
    trace!("decrypt: owm_s: {:?}", owm_s);

    // there can only be one key
    let owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::KmipError(ErrorReason::Item_Not_Found, uid_or_tags.to_string()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many objects for key {uid_or_tags}",
        )))
    }

    // decrypt
    kms.get_decryption_system(owm, request.cryptographic_parameters.as_ref(), params)
        .await?
        .decrypt(&request)
        .map_err(Into::into)
}
