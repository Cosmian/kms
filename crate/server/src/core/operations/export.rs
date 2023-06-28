use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyMaterial, KeyValue},
    kmip_operations::{Export, ExportResponse},
    kmip_types::StateEnumeration,
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use tracing::trace;

use crate::{
    core::{
        operations::{get::get_, uids::uid_from_identifier_tags},
        KMS,
    },
    error::KmsError,
    result::KResult,
};

/// Export an object
/// If the request contains a KeyWrappingData, the key will be wrapped
/// If the request contains a KeyWrapType, the key will be unwrapped
/// If both are present, the key will be wrapped
/// If none are present, the key will be returned as is
///
pub async fn export(
    kms: &KMS,
    request: Export,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ExportResponse> {
    trace!("Export: {}", serde_json::to_string(&request)?);

    // there must be an identifier
    let identifier = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // retrieve from tags or use passed identifier
    let unique_identifier =
        uid_from_identifier_tags(kms, &identifier, user, ObjectOperationType::Encrypt, params)
            .await?
            .unwrap_or(identifier);

    let (mut object, state) = get_(
        kms,
        &unique_identifier,
        request.key_wrap_type,
        request.key_wrapping_data,
        user,
        params,
        ObjectOperationType::Export,
    )
    .await?;

    // according to the KMIP specs the KeyMaterial is not returned if the object is destroyed
    match state {
        StateEnumeration::Active
        | StateEnumeration::PreActive
        | StateEnumeration::Deactivated
        | StateEnumeration::Compromised => {}
        StateEnumeration::Destroyed | StateEnumeration::Destroyed_Compromised => {
            let key_block = object.key_block_mut()?;
            key_block.key_value = KeyValue {
                key_material: KeyMaterial::ByteString(vec![]),
                ..key_block.key_value.clone()
            };
        }
    }

    Ok(ExportResponse {
        object_type: object.object_type(),
        unique_identifier,
        attributes: object.attributes()?.clone(),
        object,
    })
}
