use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyMaterial, KeyValue},
    kmip_objects::{
        Object,
        ObjectType::{PrivateKey, PublicKey, SymmetricKey},
    },
    kmip_operations::{Destroy, DestroyResponse},
    kmip_types::{KeyFormatType, LinkType, StateEnumeration},
};
use cosmian_kms_utils::types::{ExtraDatabaseParams, ObjectOperationTypes};

use super::get::get_;
use crate::{
    core::{cover_crypt::destroy_user_decryption_keys, KMS},
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Destroy a KMIP Object
pub async fn destroy_operation(
    kms: &KMS,
    request: Destroy,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<DestroyResponse> {
    let unique_identifier = &request
        .unique_identifier
        .to_owned()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // retrieve the object
    let (object, state) = get_(
        kms,
        unique_identifier,
        None,
        None,
        user,
        params,
        ObjectOperationTypes::Destroy,
    )
    .await?;

    // perform the chain of destroy operations depending on the type of object
    let object_type = object.object_type();
    match object_type {
        SymmetricKey => {
            // revoke the key
            destroy_key_core(unique_identifier, object, state, kms, params).await?;
        }
        PrivateKey => {
            let private_key =
                destroy_key_core(unique_identifier, object, state, kms, params).await?;
            if let Some(public_key_id) = private_key.attributes()?.get_link(LinkType::PublicKeyLink)
            {
                let _ = destroy_key(&public_key_id, kms, user, params).await;
            }
            if let KeyFormatType::CoverCryptSecretKey = private_key.key_block()?.key_format_type {
                destroy_user_decryption_keys(unique_identifier, kms, user, params).await?
            }
        }
        PublicKey => {
            // revoke the public key
            let public_key =
                destroy_key_core(unique_identifier, object, state, kms, params).await?;
            if let Some(private_key_id) =
                public_key.attributes()?.get_link(LinkType::PrivateKeyLink)
            {
                if let Ok(private_key) = destroy_key(&private_key_id, kms, user, params).await {
                    if let KeyFormatType::CoverCryptSecretKey =
                        private_key.key_block()?.key_format_type
                    {
                        destroy_user_decryption_keys(&private_key_id, kms, user, params).await?
                    }
                }
            }
        }
        x => kms_bail!(KmsError::NotSupported(format!(
            "revoke operation is not supported for object type {:?}",
            x
        ))),
    };

    Ok(DestroyResponse {
        unique_identifier: unique_identifier.to_string(),
    })
}

/// Revoke a key, knowing the object and state
#[allow(clippy::too_many_arguments)]
async fn destroy_key_core(
    unique_identifier: &str,
    mut object: Object,
    state: StateEnumeration,
    kms: &KMS,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    //
    let new_state = match state {
        StateEnumeration::Active => {
            return Err(KmsError::InvalidRequest(format!(
                "Object with unique identifier: {unique_identifier} is active. It must be revoked \
                 first"
            )))
        }
        StateEnumeration::Deactivated | StateEnumeration::PreActive => StateEnumeration::Destroyed,
        StateEnumeration::Compromised => StateEnumeration::Destroyed_Compromised,
        StateEnumeration::Destroyed | StateEnumeration::Destroyed_Compromised => return Ok(object),
    };

    // the KMIP specs mandates that e KeyMaterial be destroyed
    let key_block = object.key_block_mut()?;
    key_block.key_value = KeyValue {
        key_material: KeyMaterial::ByteString(vec![]),
        attributes: key_block.key_value.attributes.clone(),
    };

    kms.db
        .update_object(unique_identifier, &object, params)
        .await?;

    kms.db
        .update_state(unique_identifier, new_state, params)
        .await?;

    Ok(object)
}

/// Revoke a key from its id
pub(crate) async fn destroy_key(
    unique_identifier: &str,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    // retrieve the object
    let (object, state) = get_(
        kms,
        unique_identifier,
        None,
        None,
        user,
        params,
        ObjectOperationTypes::Destroy,
    )
    .await?;

    destroy_key_core(unique_identifier, object, state, kms, params).await
}
