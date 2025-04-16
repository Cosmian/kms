use std::sync::Arc;

use cosmian_kmip::kmip_2_1::{
    kmip_data_structures::KeyWrappingSpecification,
    kmip_objects::ObjectType,
    kmip_operations::{Create, CreateResponse},
    kmip_types::{EncryptionKeyInformation, UniqueIdentifier},
};
use cosmian_kms_interfaces::SessionParams;
use cosmian_kms_server_database::CachedUnwrappedObject;
use tracing::{debug, trace};

use crate::{
    core::{KMS, retrieve_object_utils::user_has_permission, wrapping::wrap_key},
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub(crate) async fn create(
    kms: &KMS,
    mut request: Create,
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

    // Copy the atttributes before the key gets wrapped
    let attributes = object.attributes()?.clone();

    // Wrap the key if a wrapping key is provided
    let mut unwrapped_key = None;
    // This is a Cosmian specific extension
    let wrapping_key_id = request.attributes.remove_wrapping_key_id();
    // This is useful to store a key on the default data store but wrapped by a key stored in an HSM
    // extract the wrapping key id
    if let Some(wrapping_key_id) = wrapping_key_id {
        // make a copy of the unwrapped key
        unwrapped_key = Some(object.clone());

        // wrap the current object
        let key_block = object.key_block_mut()?;
        wrap_key(
            key_block,
            &KeyWrappingSpecification {
                encryption_key_information: Some(EncryptionKeyInformation {
                    unique_identifier: UniqueIdentifier::TextString(wrapping_key_id),
                    cryptographic_parameters: None,
                }),
                ..Default::default()
            },
            kms,
            owner,
            params.clone(),
        )
        .await?;
    }

    // create the object in the database
    let uid = kms
        .database
        .create(
            unique_identifier,
            owner,
            &object,
            &attributes,
            &tags,
            params,
        )
        .await?;
    debug!(
        "Created KMS Object of type {:?} with id {uid}",
        &object.object_type(),
    );

    // store the unwrapped object in cache if wrapped
    if let Some(unwrapped_key) = unwrapped_key {
        // add the key to the unwrapped cache
        kms.database
            .unwrapped_cache()
            .insert(
                uid.clone(),
                Ok(CachedUnwrappedObject::new(
                    object.key_signature()?,
                    unwrapped_key,
                )),
            )
            .await;
    }

    Ok(CreateResponse {
        object_type: request.object_type,
        unique_identifier: UniqueIdentifier::TextString(uid),
    })
}
