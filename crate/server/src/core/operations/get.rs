use cosmian_kmip::kmip::{
    kmip_data_structures::KeyWrappingData,
    kmip_objects::Object,
    kmip_operations::{Get, GetResponse},
    kmip_types::{KeyWrapType, StateEnumeration},
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationTypes};
use tracing::{debug, trace};

use crate::{
    core::{
        operations::wrapping::{unwrap_key, wrap_key},
        KMS,
    },
    error::KmsError,
    result::KResult,
};

/// Get an object
/// If the request contains a KeyWrappingData, the key will be wrapped
/// If the request contains a KeyWrapType, the key will be unwrapped
/// If both are present, the key will be wrapped
/// If none are present, the key will be returned as is
///
pub async fn get(
    kms: &KMS,
    request: Get,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<GetResponse> {
    trace!("Get: {}", serde_json::to_string(&request)?);
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;
    let (object, state) = get_(
        kms,
        unique_identifier,
        request.key_wrap_type,
        request.key_wrapping_data,
        owner,
        params,
        ObjectOperationTypes::Get,
    )
    .await?;

    //
    check_state_active(state, unique_identifier)?;

    Ok(GetResponse {
        object_type: object.object_type(),
        unique_identifier: unique_identifier.clone(),
        object,
    })
}

/// Check if the state of the object is active
pub(crate) fn check_state_active(state: StateEnumeration, unique_identifier: &str) -> KResult<()> {
    match state {
        StateEnumeration::Active => {
            // ok
        }
        StateEnumeration::Deactivated => {
            return Err(KmsError::ItemNotFound(format!(
                "Object with unique identifier: {unique_identifier} is deactivated"
            )))
        }
        StateEnumeration::Destroyed => {
            return Err(KmsError::ItemNotFound(format!(
                "Object with unique identifier: {unique_identifier} is destroyed"
            )))
        }
        StateEnumeration::Compromised => {
            return Err(KmsError::ItemNotFound(format!(
                "Object with unique identifier: {unique_identifier} is compromised"
            )))
        }

        StateEnumeration::PreActive => {
            return Err(KmsError::ItemNotFound(format!(
                "Object with unique identifier: {unique_identifier} is pre-active"
            )))
        }
        StateEnumeration::Destroyed_Compromised => {
            return Err(KmsError::ItemNotFound(format!(
                "Object with unique identifier: {unique_identifier} is destroyed and compromised"
            )))
        }
    }
    Ok(())
}

/// Get an object
pub(crate) async fn get_(
    kms: &KMS,
    unique_identifier: &str,
    key_wrap_type: Option<KeyWrapType>,
    key_wrapping_data: Option<KeyWrappingData>,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
    operation_type: ObjectOperationTypes,
) -> KResult<(Object, StateEnumeration)> {
    trace!("retrieving KMIP Object with id: {unique_identifier}");
    let (mut object, state) = kms
        .db
        .retrieve(unique_identifier, user, operation_type, params)
        .await?
        .ok_or_else(|| {
            KmsError::ItemNotFound(format!(
                "Object with unique identifier: {unique_identifier} not found"
            ))
        })?;
    debug!(
        "Retrieved Object: {} with id {unique_identifier}",
        &object.object_type()
    );

    // decision on wrapping/unwrapping//nothing
    match key_wrap_type {
        Some(kw) => {
            match kw {
                KeyWrapType::NotWrapped => {
                    let object_type = object.object_type();
                    let key_block = object.key_block_mut()?;
                    unwrap_key(object_type, key_block, kms, user, params).await?
                }
                KeyWrapType::AsRegistered => {
                    // do nothing
                }
            }
        }
        None => {
            if let Some(kwd) = key_wrapping_data {
                // wrap
                let key_block = object.key_block_mut()?;
                wrap_key(unique_identifier, key_block, &kwd, kms, user, params).await?;
            }
        }
    }

    Ok((object, state))
}
