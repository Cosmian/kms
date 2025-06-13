use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::KmipOperation,
    },
    cosmian_kms_interfaces::{ObjectWithMetadata, SessionParams},
};
use tracing::trace;

use crate::{core::KMS, error::KmsError, result::KResult};

//TODO This function should probably not be a free standing function KMS side,
// and should be refactored as part of Database,

/// Retrieve a single object for a given operation type
/// or the Get operation if not found..
///
/// When tags are provided, the function will return the first object
/// that matches the tags and the operation type.
///
/// This function assumes that if the user can `Get` the object,
/// then it can also do any other operation with it.
pub(crate) async fn retrieve_object_for_operation(
    uid_or_tags: &str,
    operation_type: KmipOperation,
    kms: &KMS,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<ObjectWithMetadata> {
    trace!(
        "get_key: key_uid_or_tags: {uid_or_tags:?}, user: {user}, operation_type: \
         {operation_type:?}"
    );

    for owm in kms
        .database
        .retrieve_objects(uid_or_tags, params.clone())
        .await?
        .values()
    {
        if !(owm.state() == State::Active || operation_type == KmipOperation::Export) {
            continue
        }

        if user_has_permission(user, Some(owm), &operation_type, kms, params.clone()).await? {
            let mut owm = owm.to_owned();
            // update the state on the object attributes
            let state = owm.state();
            owm.attributes_mut().state = Some(state);
            if let Ok(ref mut attributes) = owm.object_mut().attributes_mut() {
                attributes.state = Some(state);
            }
            return Ok(owm)
        }
    }

    Err(KmsError::Kmip21Error(
        ErrorReason::Object_Not_Found,
        format!("object not found for identifier {uid_or_tags}",),
    ))
}

/// Check if a user has permission to perform an operation on an object.
///  If the user is the owner of the object, it will always return true.
///  If the user has the `Get` permission, it will always return true.
///  Otherwise, it will check the permissions in the database.
///  # Arguments
///  * `user` - The user to check the permission for.
///  * `owm` - The object to check the permission on.
///  * `operation_type` - The operation to check the permission for.
///  * `kms` - The KMS instance.
///  * `params` - The extra store params.
///  # Returns
///  * `Ok(true)` if the user has permission to perform the operation on the object.
///  * `Ok(false)` if the user does not have permission to perform the operation on the object.
pub(crate) async fn user_has_permission(
    user: &str,
    owm: Option<&ObjectWithMetadata>,
    operation_type: &KmipOperation,
    kms: &KMS,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<bool> {
    let id = match owm {
        Some(object) if user == object.owner() => return Ok(true),
        Some(object) => object.id(),
        None => "*",
    };

    let permissions = kms
        .database
        .list_user_operations_on_object(id, user, false, params)
        .await?;
    Ok(permissions.contains(operation_type) || permissions.contains(&KmipOperation::Get))
}
