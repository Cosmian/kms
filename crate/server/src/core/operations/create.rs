use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip,
    cosmian_kmip::{
        kmip_0::kmip_types::State::PreActive,
        kmip_2_1::{
            kmip_objects::ObjectType,
            kmip_operations::{Create, CreateResponse},
            kmip_types::UniqueIdentifier,
        },
    },
    cosmian_kms_interfaces::SessionParams,
};
use time::OffsetDateTime;
use tracing::{info, trace};
use uuid::Uuid;

use crate::{
    core::{
        KMS, operations::digest::digest, retrieve_object_utils::user_has_permission,
        wrapping::wrap_and_cache,
    },
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

    // To create an object, check that the user has `Create` access right
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
        ObjectType::SecretData => KMS::create_secret_data_and_tags(&request)?,
        _ => {
            kms_bail!(KmsError::NotSupported(format!(
                "This server does not yet support creation of: {}",
                request.object_type
            )))
        }
    };

    //Make sure we have a unique identifier.
    let unique_identifier = UniqueIdentifier::TextString(
        unique_identifier.unwrap_or_else(|| Uuid::new_v4().to_string()),
    );

    // Set the state to pre-active and copy the attributes before the key gets wrapped
    let attributes = {
        let digest = digest(&object)?;
        let attributes = object.attributes_mut()?;
        // Update the state to PreActive
        attributes.state = Some(PreActive);
        // update the digest
        attributes.digest = digest;
        // update the initial date
        let now = OffsetDateTime::now_utc();
        attributes.initial_date = Some(now);
        // update original creation date
        attributes.original_creation_date = Some(now);
        // update the last change date
        attributes.last_change_date = Some(now);
        attributes.clone()
    };

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
