use cosmian_kmip::kmip::{kmip_objects::Object, kmip_types::StateEnumeration};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use tracing::trace;

use crate::{
    core::KMS, database::object_with_metadata::ObjectWithMetadata, error::KmsError, kms_bail,
    result::KResult,
};

/// Retrieve a single object for a given operation type
/// or the Get operation if not found.
///
/// This function assumes that if the user can `Get` the object,
/// then it can also do any other operation with it.
pub async fn retrieve_object_for_operation(
    uid_or_tags: &str,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    //TODO: we could improve the retrieve() DB calls to support a list of Any(operation..)
    // https://github.com/Cosmian/kms/issues/93
    Ok(
        match _retrieve_object(uid_or_tags, operation_type, kms, user, params).await {
            Ok(key) => key,
            Err(_) => {
                // see if we can Get it which is also acceptable in this case
                _retrieve_object(uid_or_tags, ObjectOperationType::Get, kms, user, params).await?
            }
        },
    )
}

/// check if unwrapping key exists and retrieve it
async fn _retrieve_object(
    uid_or_tags: &str,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    trace!(
        "get_key: key_uid_or_tags: {uid_or_tags:?}, user: {user}, operation_type: \
         {operation_type:?}"
    );
    let mut objects: Vec<Object> = kms
        .db
        .retrieve(uid_or_tags, user, operation_type, params)
        .await?
        .into_iter()
        .filter(|(_uid, owm)| owm.state == StateEnumeration::Active)
        .map(|(_uid, own)| own.object)
        .collect();
    match objects.len() {
        0 => kms_bail!("unable to fetch the key with uid or tags: {uid_or_tags}. No key found"),
        1 => Ok(objects.remove(0)),
        _ => kms_bail!(
            "unable to fetch the key with uid or tags: {uid_or_tags}. Too many keys matching the \
             passed tags"
        ),
    }
}

/// Retrieve a single object from the database
///
/// The object is retrieved from the database based on the unique identifier or the tags
/// The object is returned only if it is active or if the `allow_full_export` flag is set
/// If the object is not found or if there are more than one object, an error is returned
//TODO: this should alo return attributes when https://github.com/Cosmian/kms/issues/88 is fixed
pub async fn retrieve_object_with_metadata(
    object_uid_or_tags: &str,
    kms: &KMS,
    allow_full_export: bool,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ObjectWithMetadata> {
    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(
            object_uid_or_tags,
            user,
            if allow_full_export {
                ObjectOperationType::Export
            } else {
                ObjectOperationType::Get
            },
            params,
        )
        .await?
        .into_values()
        .filter(|owm| owm.state == StateEnumeration::Active || allow_full_export)
        .collect::<Vec<ObjectWithMetadata>>();

    // there can only be one object
    let owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::ItemNotFound(object_uid_or_tags.to_string()))?;
    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many objects for {object_uid_or_tags}",
        )))
    }
    Ok(owm)
}
