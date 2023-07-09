use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyMaterial, KeyValue},
    kmip_operations::{Export, ExportResponse},
    kmip_types::{KeyWrapType, StateEnumeration},
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use tracing::trace;

use crate::{
    core::{
        operations::{unwrap_key, wrapping::wrap_key},
        KMS,
    },
    error::KmsError,
    result::KResult,
};

/// Export an object
///
/// If the request contains a `KeyWrappingData`, the key will be wrapped
/// If the request contains a `KeyWrapType`, the key will be unwrapped
/// If both are present, the key will be wrapped
/// If none are present, the key will be returned as is
pub async fn export(
    kms: &KMS,
    request: Export,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ExportResponse> {
    trace!("Export: {}", serde_json::to_string(&request)?);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(&uid_or_tags, user, ObjectOperationType::Export, params)
        .await?;

    // there can only be one object
    let mut owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::ItemNotFound(uid_or_tags.clone()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many objects for {uid_or_tags}",
        )))
    }

    // according to the KMIP specs the KeyMaterial is not returned if the object is destroyed
    // The rest of the semantics is the same as Get
    match &owm.state {
        StateEnumeration::Active
        | StateEnumeration::PreActive
        | StateEnumeration::Deactivated
        | StateEnumeration::Compromised => {
            // decision on wrapping/unwrapping//nothing
            match &request.key_wrap_type {
                Some(kw) => {
                    match kw {
                        KeyWrapType::NotWrapped => {
                            let object_type = owm.object.object_type();
                            let key_block = owm.object.key_block_mut()?;
                            unwrap_key(object_type, key_block, kms, user, params).await?;
                        }
                        KeyWrapType::AsRegistered => {
                            // do nothing
                        }
                    }
                }
                None => {
                    if let Some(kwd) = &request.key_wrapping_data {
                        // wrap
                        let key_block = owm.object.key_block_mut()?;
                        wrap_key(&owm.id, key_block, kwd, kms, user, params).await?;
                    }
                }
            }
        }
        StateEnumeration::Destroyed | StateEnumeration::Destroyed_Compromised => {
            let key_block = owm.object.key_block_mut()?;
            key_block.key_value = KeyValue {
                key_material: KeyMaterial::ByteString(vec![]),
                ..key_block.key_value.clone()
            };
        }
    }

    Ok(ExportResponse {
        object_type: owm.object.object_type(),
        unique_identifier: owm.id,
        attributes: owm.object.attributes()?.clone(),
        object: owm.object,
    })
}
