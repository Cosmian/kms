use std::collections::HashSet;

use async_recursion::async_recursion;
use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Destroy, DestroyResponse, ErrorReason},
    kmip_types::{Attributes, KeyFormatType, LinkType, StateEnumeration, UniqueIdentifier},
    KmipOperation,
};
use cosmian_kms_server_database::ExtraStoreParams;
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::{
    core::{
        cover_crypt::destroy_user_decryption_keys,
        uid_utils::{has_prefix, uids_from_unique_identifier},
        KMS,
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Destroy a KMIP Object
pub(crate) async fn destroy_operation(
    kms: &KMS,
    request: Destroy,
    user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<DestroyResponse> {
    // there must be an identifier
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    recursively_destroy_key(unique_identifier, kms, user, params, HashSet::new()).await?;
    Ok(DestroyResponse {
        unique_identifier: unique_identifier.clone(),
    })
}

/// Recursively destroy keys
#[async_recursion(?Send)]
pub(crate) async fn recursively_destroy_key(
    unique_identifier: &UniqueIdentifier,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraStoreParams>,
    // keys that should be skipped
    mut ids_to_skip: HashSet<String>,
) -> KResult<()> {
    let uids = uids_from_unique_identifier(unique_identifier, kms, params)
        .await
        .context("Destroy")?;

    let mut count = 0;
    for uid in uids {
        if let Some(_prefix) = has_prefix(&uid) {
            // ensure user can destroy
            if !kms.database.is_object_owned_by(&uid, user, params).await? {
                let ops = kms
                    .database
                    .list_user_operations_on_object(&uid, user, false, params)
                    .await?;
                if !ops.iter().any(|p| KmipOperation::Destroy == *p) {
                    continue
                }
            }
            kms.database.delete(&uid, params).await?;
            count += 1;
            debug!("Destroy: object {uid} destroyed by user: {user}");
            continue
        }

        //Default database: retrieve the object
        let mut owm = match kms.database.retrieve_object(&uid, params).await? {
            Some(owm) => owm,
            None => continue,
        };

        if user != owm.owner() {
            let permissions = kms
                .database
                .list_user_operations_on_object(owm.id(), user, false, params)
                .await?;
            if !permissions.contains(&KmipOperation::Destroy) {
                continue
            }
        }
        let object_type = owm.object().object_type();
        if owm.state() == StateEnumeration::Destroyed
            || (object_type != ObjectType::PrivateKey
                && object_type != ObjectType::SymmetricKey
                && object_type != ObjectType::Certificate
                && object_type != ObjectType::PublicKey)
        {
            continue
        }
        count += 1;
        // perform the chain of destroy operations depending on the type of object
        let object_type = owm.object().object_type();
        match object_type {
            ObjectType::SymmetricKey | ObjectType::Certificate => {
                // destroy the key
                let id = owm.id().to_owned();
                let state = owm.state();
                destroy_key_core(&id, owm.object_mut(), state, kms, params).await?;
            }
            ObjectType::PrivateKey => {
                //add this key to the ids to skip
                ids_to_skip.insert(owm.id().to_owned());
                // for Covercrypt, if that is a master secret key, destroy the user decryption keys
                if owm.object().key_block()?.key_format_type == KeyFormatType::CoverCryptSecretKey {
                    destroy_user_decryption_keys(owm.id(), kms, user, params, ids_to_skip.clone())
                        .await?;
                }
                // destroy any linked public key
                if let Some(public_key_id) = owm
                    .object()
                    .attributes()?
                    .get_link(LinkType::PublicKeyLink)
                    .map(|l| l.to_string())
                {
                    if !ids_to_skip.contains(&public_key_id) {
                        recursively_destroy_key(
                            &UniqueIdentifier::TextString(public_key_id),
                            kms,
                            user,
                            params,
                            ids_to_skip.clone(),
                        )
                        .await?;
                    }
                }

                // destroy the private key
                let id = owm.id().to_owned();
                let state = owm.state();
                destroy_key_core(&id, owm.object_mut(), state, kms, params).await?;
            }
            ObjectType::PublicKey => {
                //add this key to the ids to skip
                ids_to_skip.insert(owm.id().to_owned());
                // destroy any linked private key
                if let Some(private_key_id) = owm
                    .object()
                    .attributes()?
                    .get_link(LinkType::PrivateKeyLink)
                    .map(|l| l.to_string())
                {
                    if !ids_to_skip.contains(&private_key_id) {
                        recursively_destroy_key(
                            &UniqueIdentifier::TextString(private_key_id),
                            kms,
                            user,
                            params,
                            ids_to_skip.clone(),
                        )
                        .await?;
                    }
                }

                // destroy the public key
                let id = owm.id().to_owned();
                let state = owm.state();
                destroy_key_core(&id, owm.object_mut(), state, kms, params).await?;
            }
            x => kms_bail!(KmsError::NotSupported(format!(
                "destroy operation is not supported for object type {x:?}"
            ))),
        };
        debug!(
            "Object type: {}, with unique identifier: {}, destroyed by user {}",
            owm.object().object_type(),
            owm.id(),
            user
        );
    }

    if count == 0 {
        return Err(KmsError::KmipError(
            ErrorReason::Item_Not_Found,
            unique_identifier.to_string(),
        ))
    }

    Ok(())
}

/// Destroy a key, knowing the object and state
async fn destroy_key_core(
    unique_identifier: &str,
    object: &mut Object,
    state: StateEnumeration,
    kms: &KMS,
    params: Option<&ExtraStoreParams>,
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

    kms.database
        .update_object(unique_identifier, object, &attributes, None, params)
        .await?;

    kms.database
        .update_state(unique_identifier, new_state, params)
        .await?;

    debug!(
        "Object with unique identifier: {} destroyed",
        unique_identifier
    );

    Ok(())
}
