use std::collections::HashSet;

use async_recursion::async_recursion;
use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyMaterial, KeyValue},
    kmip_objects::{
        Object,
        ObjectType::{self, PrivateKey, PublicKey, SymmetricKey},
    },
    kmip_operations::{Destroy, DestroyResponse, ErrorReason},
    kmip_types::{Attributes, KeyFormatType, LinkType, StateEnumeration},
};
use cosmian_kms_client::access::ObjectOperationType;
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::{
    core::{
        cover_crypt::destroy_user_decryption_keys, extra_database_params::ExtraDatabaseParams, KMS,
    },
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Destroy a KMIP Object
pub(crate) async fn destroy_operation(
    kms: &KMS,
    request: Destroy,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<DestroyResponse> {
    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    recursively_destroy_key(
        uid_or_tags
            .as_str()
            .context("Destroy: unique_identifier must be a string")?,
        kms,
        user,
        params,
        HashSet::new(),
    )
    .await?;
    Ok(DestroyResponse {
        unique_identifier: uid_or_tags.clone(),
    })
}

/// Recursively destroy keys
#[async_recursion(?Send)]
pub(crate) async fn recursively_destroy_key(
    uid_or_tags: &str,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
    // keys that should be skipped
    mut ids_to_skip: HashSet<String>,
) -> KResult<()> {
    // retrieve from tags or use passed identifier
    let owm_s = kms
        .db
        .retrieve(uid_or_tags, user, ObjectOperationType::Destroy, params)
        .await?
        .into_values()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            owm.state != StateEnumeration::Destroyed
                && (object_type == ObjectType::PrivateKey
                    || object_type == ObjectType::SymmetricKey
                    || object_type == ObjectType::Certificate
                    || object_type == ObjectType::PublicKey)
        })
        .collect::<Vec<ObjectWithMetadata>>();

    if owm_s.is_empty() {
        return Err(KmsError::KmipError(
            ErrorReason::Item_Not_Found,
            uid_or_tags.to_owned(),
        ))
    }

    // destroy the keys found
    for mut owm in owm_s {
        // perform the chain of destroy operations depending on the type of object
        let object_type = owm.object.object_type();
        match object_type {
            SymmetricKey | ObjectType::Certificate => {
                // destroy the key
                destroy_key_core(&owm.id, &mut owm.object, owm.state, kms, params).await?;
            }
            PrivateKey => {
                //add this key to the ids to skip
                ids_to_skip.insert(owm.id.clone());
                // for Covercrypt, if that is a master secret key, destroy the user decryption keys
                if owm.object.key_block()?.key_format_type == KeyFormatType::CoverCryptSecretKey {
                    destroy_user_decryption_keys(&owm.id, kms, user, params, ids_to_skip.clone())
                        .await?;
                }
                // destroy any linked public key
                if let Some(public_key_id) = owm
                    .object
                    .attributes()?
                    .get_link(LinkType::PublicKeyLink)
                    .map(|l| l.to_string())
                {
                    if !ids_to_skip.contains(&public_key_id) {
                        recursively_destroy_key(
                            &public_key_id,
                            kms,
                            user,
                            params,
                            ids_to_skip.clone(),
                        )
                        .await?;
                    }
                }

                // destroy the private key
                destroy_key_core(&owm.id, &mut owm.object, owm.state, kms, params).await?;
            }
            PublicKey => {
                //add this key to the ids to skip
                ids_to_skip.insert(owm.id.clone());
                // destroy any linked private key
                if let Some(private_key_id) = owm
                    .object
                    .attributes()?
                    .get_link(LinkType::PrivateKeyLink)
                    .map(|l| l.to_string())
                {
                    if !ids_to_skip.contains(&private_key_id) {
                        recursively_destroy_key(
                            &private_key_id,
                            kms,
                            user,
                            params,
                            ids_to_skip.clone(),
                        )
                        .await?;
                    }
                }

                // destroy the public key
                destroy_key_core(&owm.id, &mut owm.object, owm.state, kms, params).await?;
            }
            x => kms_bail!(KmsError::NotSupported(format!(
                "destroy operation is not supported for object type {x:?}"
            ))),
        };
    }

    Ok(())
}

/// Destroy a key, knowing the object and state
async fn destroy_key_core(
    unique_identifier: &str,
    object: &mut Object,
    state: StateEnumeration,
    kms: &KMS,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    // map the state to the new state
    let new_state = match state {
        StateEnumeration::Active => {
            return Err(KmsError::InvalidRequest(format!(
                "Object with unique identifier: {unique_identifier} is active. It must be revoked \
                 first"
            )))
        }
        StateEnumeration::Deactivated | StateEnumeration::PreActive => StateEnumeration::Destroyed,
        StateEnumeration::Compromised => StateEnumeration::Destroyed_Compromised,
        // already destroyed, return
        StateEnumeration::Destroyed | StateEnumeration::Destroyed_Compromised => return Ok(()),
    };

    // the KMIP specs mandates that e KeyMaterial be destroyed
    trace!("destroy: object: {object}");
    let attributes = if let Object::Certificate { .. } = object {
        trace!("Certificate destroying");
        Attributes::default()
    } else {
        let key_block = object.key_block_mut()?;
        key_block.key_value = KeyValue {
            key_material: KeyMaterial::ByteString(Zeroizing::from(vec![])),
            attributes: key_block.key_value.attributes.clone(),
        };
        key_block.attributes()?.clone()
    };

    kms.db
        .update_object(unique_identifier, object, &attributes, None, params)
        .await?;

    kms.db
        .update_state(unique_identifier, new_state, params)
        .await?;

    debug!(
        "Object with unique identifier: {} destroyed",
        unique_identifier
    );

    Ok(())
}
