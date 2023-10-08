use cosmian_kmip::kmip::{
    kmip_objects::Object, kmip_operations::ErrorReason, kmip_types::StateEnumeration,
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
pub(crate) use unwrap::unwrap_key;
pub(crate) use wrap::wrap_key;

use crate::{core::KMS, error::KmsError, kms_bail, result::KResult};

mod unwrap;
mod wrap;

async fn get_key(
    key_uid_or_tags: &str,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    //TODO: we could improve the retrieve() DB calls to support a list of Any(operation..)
    Ok(
        match _get_key(key_uid_or_tags, operation_type, kms, user, params).await {
            Ok(key) => key,
            Err(_) => {
                // see if we can Get it which is also acceptable in this case
                _get_key(key_uid_or_tags, ObjectOperationType::Get, kms, user, params).await?
            }
        },
    )
}

/// check if unwrapping key exists and retrieve it
async fn _get_key(
    key_uid_or_tags: &str,
    operation_type: ObjectOperationType,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    let owm = kms
        .db
        .retrieve(key_uid_or_tags, user, operation_type, params)
        .await?
        .remove(key_uid_or_tags)
        .ok_or_else(|| {
            KmsError::KmipError(
                ErrorReason::Item_Not_Found,
                format!("unable to fetch the key with uid: {key_uid_or_tags:} not found"),
            )
        })?;
    // check if unwrapping key is active
    match owm.state {
        StateEnumeration::Active => {
            //OK
        }
        x => {
            kms_bail!(
                "unable to fetch the key with uid: {key_uid_or_tags}. The key is not active: {x:?}"
            )
        }
    }
    Ok(owm.object)
}
