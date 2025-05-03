use std::sync::Arc;

use cosmian_kmip::kmip_2_1::{
    kmip_objects::ObjectType,
    kmip_operations::{Create, CreateResponse},
    kmip_types::UniqueIdentifier,
};
use cosmian_kms_interfaces::SessionParams;
use tracing::{info, trace};
use uuid::Uuid;

use crate::{
    core::{KMS, wrapping::wrap_and_cache},
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub(crate) async fn create(
    kms: &KMS,
    request: Create,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
    privileged_users: Option<Vec<String>>,
) -> KResult<CreateResponse> {
    trace!("Create: {}", serde_json::to_string(&request)?);
    if request.protection_storage_masks.is_some() {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // For creation of an object, check that user has create access-right
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
                "User does not have create access-right.".to_owned()
            ))
        }
    }

    let (unique_identifier, mut object, tags) = match &request.object_type {
        ObjectType::SymmetricKey => KMS::create_symmetric_key_and_tags(&request)?,
        ObjectType::PrivateKey => {
            kms.create_private_key_and_tags(&request, owner, params.clone(), privileged_users)
                .await?
        }
        _ => {
            kms_bail!(KmsError::NotSupported(format!(
                "This server does not yet support creation of: {}",
                request.object_type
            )))
        }
    };

    // make sure we have a unique identifier
    let unique_identifier = UniqueIdentifier::TextString(
        unique_identifier.unwrap_or_else(|| Uuid::new_v4().to_string()),
    );

    // Copy the attributes before the key gets wrapped
    let attributes = object.attributes()?.clone();

    // Wrap the object if requested by the user or on the server params
    wrap_and_cache(kms, owner, params.clone(), &unique_identifier, &mut object).await?;

    // create the object in the database
    let uid = kms
        .database
        .create(
            Some(unique_identifier.to_string()),
            owner,
            &object,
            &attributes,
            &tags,
            params,
        )
        .await?;
    info!(
        uid = uid,
        user = owner,
        "Created Object of type {:?}",
        &object.object_type(),
    );

    Ok(CreateResponse {
        object_type: request.object_type,
        unique_identifier: UniqueIdentifier::TextString(uid),
    })
}
