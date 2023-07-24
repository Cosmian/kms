use cosmian_kmip::kmip::{
    kmip_operations::{Get, GetResponse},
    kmip_types::{KeyWrapType, StateEnumeration},
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use tracing::{debug, trace};

use crate::{
    core::{
        operations::wrapping::{unwrap_key, wrap_key},
        KMS,
    },
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    result::KResult,
};

/// Get an object
///
/// If the request contains a `KeyWrappingData`, the key will be wrapped
/// If the request contains a `KeyWrapType`, the key will be unwrapped
/// If both are present, the key will be wrapped
/// If none are present, the key will be returned as is
pub(crate) async fn get(
    kms: &KMS,
    request: Get,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<GetResponse> {
    trace!("Get: {}", serde_json::to_string(&request)?);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // there can only be one object
    let mut owm = get_active_object(kms, &uid_or_tags, user, params).await?;

    // decision on wrapping/unwrapping//nothing
    match &request.key_wrap_type {
        Some(kw) => {
            match kw {
                KeyWrapType::NotWrapped => {
                    let object_type = owm.object.object_type();
                    let key_block = owm.object.key_block_mut()?;
                    unwrap_key(object_type, key_block, kms, user, params).await?
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

    debug!(
        "Retrieved Object: {} with id {uid_or_tags}",
        &owm.object.object_type()
    );

    Ok(GetResponse {
        object_type: owm.object.object_type(),
        unique_identifier: owm.id.clone(),
        object: owm.object,
    })
}

/// Get a single active object
pub(crate) async fn get_active_object(
    kms: &KMS,
    uid_or_tags: &str,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ObjectWithMetadata> {
    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(uid_or_tags, user, ObjectOperationType::Get, params)
        .await?
        .into_iter()
        .filter(|owm| owm.state == StateEnumeration::Active)
        .collect::<Vec<ObjectWithMetadata>>();

    // there can only be one object
    let owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::ItemNotFound(uid_or_tags.to_owned()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many active objects for {uid_or_tags}",
        )))
    }

    Ok(owm)
}
