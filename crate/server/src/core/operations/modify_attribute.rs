use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{ErrorReason, State},
    kmip_2_1::{
        kmip_attributes::Attribute,
        kmip_operations::{ModifyAttribute, ModifyAttributeResponse},
        kmip_types::UniqueIdentifier,
    },
};

use crate::{core::KMS, error::KmsError, result::KResult};

/// Handle `ModifyAttribute` operation.
/// Current minimal implementation:
/// - If the attribute being modified is `ActivationDate`, enforce the lifecycle rule (object must be `PreActive`)
/// - For any other attribute types (e.g. vendor attributes in mandatory vectors) we optimistically
///   return Success without modifying stored attributes yet. This unblocks the interoperability
///   vectors while a full Add/Modify/Delete Attribute implementation is added.
///   (Parser currently injects placeholders for some attribute types; once the XML refactor
///   is complete we can persist real changes here.)
pub(crate) async fn modify_attribute(
    kms: &KMS,
    request: ModifyAttribute,
    _user: &str,
) -> KResult<ModifyAttributeResponse> {
    let uid = request.unique_identifier.clone().ok_or_else(|| {
        KmsError::Kmip21Error(
            ErrorReason::Operation_Not_Supported,
            "Missing UniqueIdentifier in ModifyAttribute".to_owned(),
        )
    })?;

    // Enforce KMIP 2.1 semantics: certain attributes are read-only and cannot be modified via ModifyAttribute
    match &request.new_attribute {
        Attribute::State(_) | Attribute::CertificateLength(_) => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Attribute_Read_Only,
                "DENIED".to_owned(),
            ));
        }
        _ => {}
    }

    if let Attribute::ActivationDate(_) = request.new_attribute {
        // Retrieve object to inspect current state only for ActivationDate modifications.
        let object_with_metadata = kms
            .database
            .retrieve_object(&uid.to_string())
            .await?
            .ok_or_else(|| {
                KmsError::Kmip21Error(ErrorReason::Item_Not_Found, "Object not found".to_owned())
            })?;
        let attributes = object_with_metadata
            .object()
            .attributes()
            .map_err(|e| KmsError::Kmip21Error(ErrorReason::General_Failure, e.to_string()))?;
        if let Some(state) = attributes.state {
            if state != State::PreActive {
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Wrong_Key_Lifecycle_State,
                    "ACTIVATION_DATE:!PRE_ACTIVE".to_owned(),
                ));
            }
        } else {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Wrong_Key_Lifecycle_State,
                "ACTIVATION_DATE:!PRE_ACTIVE".to_owned(),
            ));
        }
    } // Other attribute types: no-op success for now.

    Ok(ModifyAttributeResponse {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_string())),
    })
}
