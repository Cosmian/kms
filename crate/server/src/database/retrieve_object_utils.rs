use cosmian_kmip::kmip::kmip_types::StateEnumeration;
use cosmian_kms_client::access::ObjectOperationType;
use tracing::trace;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    result::KResult,
};

/// Retrieve a single object for a given operation type
/// or the Get operation if not found.
///
/// This function assumes that if the user can `Get` the object,
/// then it can also do any other operation with it.
pub(crate) async fn retrieve_object_for_operation(
    uid_or_tags: &str,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ObjectWithMetadata> {
    //TODO: we could improve the retrieve() DB calls to support a list of Any(operation..)
    // https://github.com/Cosmian/kms/issues/93
    Ok(
        match _retrieve_object(uid_or_tags, operation_type, kms, user, params).await {
            Ok(key) => key,
            Err(_) => {
                // see if we can Get: in that case the user can always re-import the object and own it
                _retrieve_object(uid_or_tags, ObjectOperationType::Get, kms, user, params).await?
            }
        },
    )
}

/// Retrieve a single object - inner
async fn _retrieve_object(
    uid_or_tags: &str,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ObjectWithMetadata> {
    trace!(
        "get_key: key_uid_or_tags: {uid_or_tags:?}, user: {user}, operation_type: \
         {operation_type:?}"
    );
    let mut owm_s: Vec<ObjectWithMetadata> = kms
        .db
        .retrieve(uid_or_tags, user, operation_type, params)
        .await?
        .into_values()
        .filter(|owm| {
            owm.state == StateEnumeration::Active || operation_type == ObjectOperationType::Export
        })
        .collect();
    // there can only be one object
    let owm = owm_s.pop().ok_or_else(|| {
        KmsError::ItemNotFound(format!(
            "no active or exportable object found for identifier {uid_or_tags}"
        ))
    })?;
    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "too many objects found for identifier {uid_or_tags}",
        )))
    }
    Ok(owm)
}
