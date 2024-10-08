use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{Create, ErrorReason, Import, ReKey, ReKeyResponse},
    kmip_types::{StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_client::access::ObjectOperationType;
use tracing::{debug, trace};

use crate::{
    core::{
        extra_database_params::ExtraDatabaseParams, operations::import::process_symmetric_key, KMS,
    },
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

pub(crate) async fn rekey(
    kms: &KMS,
    request: ReKey,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ReKeyResponse> {
    trace!("ReKey: {}", serde_json::to_string(&request)?);

    if request.protection_storage_masks.is_some() {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Rekey: the symmetric key unique identifier must be a string")?;

    // retrieve the symmetric key associated with the uid (the array MUST contain only one element)
    let mut owm_s = kms
        .db
        .retrieve(uid_or_tags, owner, ObjectOperationType::Rekey, params)
        .await?
        .into_values()
        .filter(|owm| {
            // only active objects
            if owm.state != StateEnumeration::Active {
                return false
            }
            // only symmetric keys
            if owm.object.object_type() != ObjectType::SymmetricKey {
                return false
            }
            true
        })
        .collect::<Vec<ObjectWithMetadata>>();

    // there can only be one private key
    let owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::KmipError(ErrorReason::Item_Not_Found, uid_or_tags.to_owned()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "rekey: get: too many symmetric keys for uid/tags: {uid_or_tags}",
        )))
    }

    // create a new symmetric key KMIP object (in memory)
    let create_request = Create {
        object_type: ObjectType::SymmetricKey,
        attributes: owm.attributes,
        protection_storage_masks: None,
    };
    let (_uid, new_object, _tags) = KMS::create_symmetric_key_and_tags(&create_request)?;

    // import new KMIP object into the database (but overwrite the existing one)
    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString(owm.id),
        object_type: ObjectType::SymmetricKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: new_object.attributes()?.clone(),
        object: new_object,
    };
    let (uid, operations) = process_symmetric_key(kms, import_request, owner, params).await?;

    // execute the operations
    kms.db.atomic(owner, &operations, params).await?;

    // return the uid
    debug!("Rekey symmetric key with uid: {uid}");

    Ok(ReKeyResponse {
        unique_identifier: UniqueIdentifier::TextString(uid),
    })
}
