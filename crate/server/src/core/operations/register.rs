use cosmian_kms_server_database::reexport::cosmian_kmip::{
    self,
    kmip_0::kmip_types::State,
    kmip_2_1::{
        kmip_objects::ObjectType,
        kmip_operations::{Register, RegisterResponse},
        kmip_types::UniqueIdentifier,
    },
    time_normalize,
};
use cosmian_logger::{debug, trace};

use super::import::process_opaque_object;
use crate::{
    core::{
        KMS,
        operations::import::{
            process_certificate, process_private_key, process_public_key, process_secret_data,
            process_symmetric_key,
        },
        retrieve_object_utils::user_has_permission,
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub(crate) async fn register(
    kms: &KMS,
    mut request: Register,
    owner: &str,

    privileged_users: Option<Vec<String>>,
) -> KResult<RegisterResponse> {
    trace!("{request}");
    if request.protection_storage_masks.is_some() {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // To register an object, check that the user has `Create` access right
    // The `Create` right implicitly grants permission for Create, Import, and Register operations.
    if let Some(users) = privileged_users.clone() {
        let has_permission = user_has_permission(
            owner,
            None,
            &cosmian_kmip::kmip_2_1::KmipOperation::Create,
            kms,
        )
        .await?;

        if !has_permission && !users.iter().any(|u| u == owner) {
            kms_bail!(KmsError::Unauthorized(
                "User does not have create access-right to register objects.".to_owned()
            ))
        }
    }

    if request.object_type != request.object.object_type() {
        kms_bail!(KmsError::InconsistentOperation(
            "Specified object type does not match the type of object to register.".to_owned()
        ))
    }

    // Update lifecycle: determine state based on ActivationDate per KMIP 2.1 spec.
    // Per KMIP 2.1 section 3.1.7 "Key States and Transitions":
    // - If ActivationDate is absent or in the future → PreActive state
    // - If ActivationDate is present and <= now → Active state
    let now = time_normalize()?;

    // Determine the desired initial state based on ActivationDate
    let activation_allows_active = request.attributes.activation_date.is_some_and(|d| d <= now);
    let desired_state = if activation_allows_active {
        debug!(
            "Register: activation_date={:?} <= now, setting state to Active",
            request.attributes.activation_date
        );
        State::Active
    } else {
        debug!("Register: no activation_date or future date, setting state to PreActive");
        State::PreActive
    };

    // Set the state in the request attributes (used by process_* functions)
    request.attributes.state = Some(desired_state);

    // Also set it in the object's attributes for consistency
    // Zero milliseconds for KMIP serialization compatibility
    let now_stored = time_normalize()?;
    if let Ok(object_attributes) = request.object.attributes_mut() {
        object_attributes.state = Some(desired_state);
        // update the last change date
        object_attributes.last_change_date = Some(now_stored);
    }

    // Process the request based on the object type,
    let (uid, operations) = match request.object.object_type() {
        ObjectType::SymmetricKey => {
            Box::pin(process_symmetric_key(kms, request.into(), owner)).await?
        }
        ObjectType::Certificate => process_certificate(request.into())?,
        ObjectType::PublicKey => Box::pin(process_public_key(kms, request.into(), owner)).await?,
        ObjectType::PrivateKey => Box::pin(process_private_key(kms, request.into(), owner)).await?,
        ObjectType::SecretData => Box::pin(process_secret_data(kms, request.into(), owner)).await?,
        ObjectType::OpaqueObject => {
            // Reuse the import path logic (no unwrap/wrap for opaque objects)
            let (uid, ops) = process_opaque_object(request.into())?;
            (uid, ops)
        }
        x => {
            return Err(KmsError::InvalidRequest(format!(
                "Register is not yet supported for objects of type : {x}"
            )));
        }
    };
    kms.database.atomic(owner, &operations).await?;
    debug!("Registered object with uid: {}", uid);
    Ok(RegisterResponse {
        unique_identifier: UniqueIdentifier::TextString(uid),
    })
}
