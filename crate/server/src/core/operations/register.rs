use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        self,
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_objects::ObjectType,
            kmip_operations::{Register, RegisterResponse},
            kmip_types::UniqueIdentifier,
        },
    },
    cosmian_kms_interfaces::SessionParams,
};
use cosmian_logger::{debug, trace};
use time::OffsetDateTime;

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
    params: Option<Arc<dyn SessionParams>>,
    privileged_users: Option<Vec<String>>,
) -> KResult<RegisterResponse> {
    trace!("Register: {}", serde_json::to_string(&request)?);
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
            params.clone(),
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

    // Update the initial date and last changed date of the object
    // Update the state of the object to Active and activation date
    let now = OffsetDateTime::now_utc()
        .replace_millisecond(0)
        .map_err(|e| KmsError::Default(e.to_string()))?;
    if let Ok(object_attributes) = request.object.attributes_mut() {
        object_attributes.state = Some(State::Active);
        // update the initial date
        object_attributes.initial_date = Some(now);
        // update the last change date
        object_attributes.last_change_date = Some(now);
    }

    // Process the request based on the object type,
    let (uid, operations) = match request.object.object_type() {
        ObjectType::SymmetricKey => {
            Box::pin(process_symmetric_key(
                kms,
                request.into(),
                owner,
                params.clone(),
            ))
            .await?
        }
        ObjectType::Certificate => process_certificate(request.into())?,
        ObjectType::PublicKey => {
            Box::pin(process_public_key(
                kms,
                request.into(),
                owner,
                params.clone(),
            ))
            .await?
        }
        ObjectType::PrivateKey => {
            Box::pin(process_private_key(
                kms,
                request.into(),
                owner,
                params.clone(),
            ))
            .await?
        }
        ObjectType::SecretData => {
            Box::pin(process_secret_data(
                kms,
                request.into(),
                owner,
                params.clone(),
            ))
            .await?
        }
        x => {
            return Err(KmsError::InvalidRequest(format!(
                "Register is not yet supported for objects of type : {x}"
            )))
        }
    };
    kms.database.atomic(owner, &operations, params).await?;
    debug!("Registered object with uid: {}", uid);
    Ok(RegisterResponse {
        unique_identifier: UniqueIdentifier::TextString(uid),
    })
}
