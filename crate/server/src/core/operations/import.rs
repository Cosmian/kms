use cosmian_kmip::kmip::{
    kmip_data_structures::KeyValue,
    kmip_objects::ObjectType,
    kmip_operations::{Import, ImportResponse},
    kmip_types::{KeyWrapType, StateEnumeration},
};
use cosmian_kms_utils::types::ExtraDatabaseParams;
use tracing::{debug, warn};

use super::wrapping::unwrap_key;
use crate::{core::KMS, result::KResult};

/// Import a new object
pub async fn import(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ImportResponse> {
    let mut object = request.object;
    let object_type = object.object_type();
    let object_key_block = object.key_block_mut()?;
    match object_type {
        ObjectType::SymmetricKey | ObjectType::PublicKey | ObjectType::PrivateKey => {
            // unwrap before storing if requested
            if let Some(KeyWrapType::NotWrapped) = request.key_wrap_type {
                unwrap_key(object_type, object_key_block, kms, owner, params).await?;
            }
            // replace attributes
            object_key_block.key_value = KeyValue {
                key_material: object_key_block.key_value.key_material.clone(),
                attributes: Some(request.attributes),
            };
        }
        x => {
            //TODO keep attributes as separate column in DB
            warn!("Attributes are not yet supported for objects of type : {x}")
        }
    }
    // check if the object will be replaced if it already exists
    let replace_existing = if let Some(v) = request.replace_existing {
        v
    } else {
        false
    };
    // insert or update the object
    let uid = if replace_existing {
        debug!(
            "Upserting object of type: {}, with uid: {}",
            request.object_type, request.unique_identifier
        );
        kms.db
            .upsert(
                &request.unique_identifier,
                owner,
                &object,
                StateEnumeration::Active,
                params,
            )
            .await?;
        request.unique_identifier
    } else {
        debug!("Inserting object of type: {}", request.object_type);
        let id = if request.unique_identifier.is_empty() {
            None
        } else {
            Some(request.unique_identifier)
        };
        kms.db.create(id, owner, &object, params).await?
    };
    Ok(ImportResponse {
        unique_identifier: uid,
    })
}
