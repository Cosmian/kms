use async_recursion::async_recursion;
use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyMaterial, KeyValue},
    kmip_objects::{
        Object,
        ObjectType::{self, PrivateKey, PublicKey, SymmetricKey},
    },
    kmip_operations::{Destroy, DestroyResponse},
    kmip_types::{KeyFormatType, LinkType, StateEnumeration},
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};

use crate::{
    core::{cover_crypt::destroy_user_decryption_keys, KMS},
    database::object_with_metadata::ObjectWithMetadata,
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
    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    recursively_destroy_key(&uid_or_tags, kms, user, params).await?;
    Ok(DestroyResponse {
        unique_identifier: uid_or_tags,
    })
}

/// Recursively destroy keys
#[async_recursion]
pub(crate) async fn recursively_destroy_key<'a: 'async_recursion>(
    uid_or_tags: &str,
    kms: &KMS,
    user: &str,
    params: Option<&'a ExtraDatabaseParams>,
) -> KResult<()> {
    // retrieve from tags or use passed identifier
    let owm_s = kms
        .db
        .retrieve(uid_or_tags, user, ObjectOperationType::Decrypt, params)
        .await?
        .into_iter()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            owm.state != StateEnumeration::Destroyed
                && (object_type == ObjectType::PrivateKey
                    || object_type == ObjectType::SymmetricKey
                    || object_type == ObjectType::PublicKey)
        })
        .collect::<Vec<ObjectWithMetadata>>();

    if owm_s.is_empty() {
        return Err(KmsError::ItemNotFound(uid_or_tags.to_owned()))
    }

    // destroy the keys found
    for owm in owm_s {
        // perform the chain of destroy operations depending on the type of object
        let object_type = owm.object.object_type();
        match object_type {
            SymmetricKey => {
                // destroy the key
                destroy_key_core(&owm.id, owm.object, owm.state, kms, params).await?;
            }
            PrivateKey => {
                // for Covercrypt, if that is a master secret key, destroy the user decryption keys
                if let KeyFormatType::CoverCryptSecretKey = owm.object.key_block()?.key_format_type
                {
                    destroy_user_decryption_keys(&owm.id, kms, user, params).await?
                }
                // destroy any linked public key
                if let Some(public_key_id) =
                    owm.object.attributes()?.get_link(LinkType::PublicKeyLink)
                {
                    recursively_destroy_key(&public_key_id, kms, user, params).await?;
                }
                // now destroy the private key
                destroy_key_core(&owm.id, owm.object, owm.state, kms, params).await?;
            }
            PublicKey => {
                // destroy any linked private key
                if let Some(private_key_id) =
                    owm.object.attributes()?.get_link(LinkType::PrivateKeyLink)
                {
                    recursively_destroy_key(&private_key_id, kms, user, params).await?;
                }
                // destroy the public key
                destroy_key_core(&owm.id, owm.object, owm.state, kms, params).await?;
            }
            x => kms_bail!(KmsError::NotSupported(format!(
                "destroy operation is not supported for object type {:?}",
                x
            ))),
        };
    }

    Ok(())
}

/// Destroy a key, knowing the object and state
#[allow(clippy::too_many_arguments)]
async fn destroy_key_core(
    unique_identifier: &str,
    mut object: Object,
    state: StateEnumeration,
    kms: &KMS,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
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
        // already destroyed, return the object
        StateEnumeration::Destroyed | StateEnumeration::Destroyed_Compromised => return Ok(()),
    };

    // the KMIP specs mandates that e KeyMaterial be destroyed
    let key_block = object.key_block_mut()?;
    key_block.key_value = KeyValue {
        key_material: KeyMaterial::ByteString(vec![]),
        attributes: key_block.key_value.attributes.clone(),
    };

    kms.db
        .update_object(unique_identifier, &object, None, params)
        .await?;

    kms.db
        .update_state(unique_identifier, new_state, params)
        .await?;

    Ok(())
}
