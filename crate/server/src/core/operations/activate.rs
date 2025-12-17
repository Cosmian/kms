use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::{
            KmipOperation,
            kmip_objects::ObjectType,
            kmip_operations::{Activate, ActivateResponse},
            kmip_types::UniqueIdentifier,
        },
        time_normalize,
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::trace;

use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation},
    error::KmsError,
    result::{KResult, KResultHelper},
};

/// KMIP 2.1 Activate Operation
///
/// This operation requests the server to activate a Managed Object.
/// The operation SHALL only be performed on an object in the Pre-Active state
/// and has the effect of changing its state to Active, and setting its
/// Activation Date to the current date and time.
///
/// # KMIP 2.1 Compliance - Table 166: Activate Errors
///
/// The following Result Reasons SHALL be returned for errors detected in an Activate Operation:
///
/// 1. **Invalid Object Type** - Object type does not support lifecycle states/activation
/// 2. **Object Not Found** - The specified unique identifier does not exist
/// 3. **Wrong Key Lifecycle State** - Object is not in Pre-Active state (e.g., already Active, Deactivated, Destroyed, Compromised)
/// 4. **Attestation Failed** - Attestation validation failed (HSM-specific)
/// 5. **Attestation Required** - Attestation is required but not provided (HSM-specific)
/// 6. **Feature Not Supported** - Server does not support a requested feature
/// 7. **Invalid Field** - A field in the request is invalid
/// 8. **Invalid Message** - The request message structure is invalid
/// 9. **Operation Not Supported** - The operation is not supported by the server
/// 10. **Permission Denied** - User lacks permission to activate the object
/// 11. **Response Too Large** - The response exceeds the maximum allowed size
///
/// # Implementation Notes
///
/// - Object types that support activation: `SymmetricKey`, `PublicKey`, `PrivateKey`, `SplitKey`, `SecretData`, `Certificate`
/// - Object types that do NOT support activation: `OpaqueObject`, `PGPKey`, `CertificateRequest`
/// - Only objects in Pre-Active state can be activated
/// - The activation date is set to the current time when the operation is performed
/// - Permission checks are performed via `retrieve_object_for_operation`
pub(crate) async fn activate(
    kms: &KMS,
    request: Activate,
    user: &str,
) -> KResult<ActivateResponse> {
    trace!("{}", serde_json::to_string(&request)?);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_str()
        .context("Activate: the unique identifier must be a string")?;

    let mut owm: ObjectWithMetadata = Box::pin(retrieve_object_for_operation(
        uid_or_tags,
        KmipOperation::GetAttributes,
        kms,
        user,
    ))
    .await?;
    trace!("Retrieved object for: {}", owm.object());

    // KMIP 2.1 Compliance: Validate object type supports activation
    // According to KMIP spec, only cryptographic objects with lifecycle states can be activated
    // Valid types: SymmetricKey, PublicKey, PrivateKey, SplitKey, SecretData, Certificate
    // Invalid types: OpaqueObject, PGPKey, CertificateRequest (no lifecycle states)
    let object_type = owm.object().object_type();
    match object_type {
        ObjectType::SymmetricKey
        | ObjectType::PublicKey
        | ObjectType::PrivateKey
        | ObjectType::SplitKey
        | ObjectType::SecretData
        | ObjectType::Certificate => {
            // These object types support activation
        }
        _ => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Object_Type,
                format!(
                    "Activate: Object type {object_type:?} does not support activation operation"
                ),
            ));
        }
    }

    // KMIP 2.1 Compliance: Validate the current state of the object
    // According to KMIP spec, Activate can only be performed on PreActive objects
    let current_state = owm.state();
    tracing::debug!(
        "Activate: object {} current state = {:?}",
        owm.id(),
        current_state
    );

    match current_state {
        State::Active => {
            tracing::warn!("Activate: object {} is already Active, rejecting", owm.id());
            return Err(KmsError::Kmip21Error(
                ErrorReason::Wrong_Key_Lifecycle_State,
                format!("Activate: Object {} is already in Active state", owm.id()),
            ));
        }
        State::Deactivated
        | State::Destroyed
        | State::Compromised
        | State::Destroyed_Compromised => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Wrong_Key_Lifecycle_State,
                format!(
                    "Activate: Object {} is in {:?} state and cannot be activated",
                    owm.id(),
                    current_state
                ),
            ));
        }
        State::PreActive => {
            // This is the expected state, continue with activation
        }
    }

    // Update the state of the object to Active and activation date
    let activation_date = time_normalize()?;
    // set milliseconds to zero

    if let Ok(object_attributes) = owm.object_mut().attributes_mut() {
        object_attributes.state = Some(State::Active);
        // update the activation date
        object_attributes.activation_date = Some(activation_date);
    }
    // Update the state in the "external" attributes
    owm.attributes_mut().state = Some(State::Active);
    // Update the activation date in the "external" attributes
    owm.attributes_mut().activation_date = Some(activation_date);

    // Update the object in the database
    kms.database
        .update_object(owm.id(), owm.object(), owm.attributes(), None)
        .await?;

    // Update the state in the database (separate column)
    kms.database.update_state(owm.id(), State::Active).await?;

    // All Objects are activated by default on the KMS, so simply answer OK
    Ok(ActivateResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
    })
}
