use std::collections::HashSet;

use async_recursion::async_recursion;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{ErrorReason, State},
    kmip_2_1::{
        KmipOperation,
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Destroy, DestroyResponse},
        kmip_types::{KeyFormatType, LinkType, UniqueIdentifier},
    },
};
use cosmian_logger::{debug, info, trace};
use zeroize::Zeroizing;

#[cfg(feature = "non-fips")]
use crate::core::cover_crypt::destroy_user_decryption_keys;
use crate::{
    core::{
        KMS,
        uid_utils::{has_prefix, uids_from_unique_identifier},
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
) -> KResult<DestroyResponse> {
    trace!("{request}");
    // there must be an identifier
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    recursively_destroy_object(
        unique_identifier,
        request.remove,
        request.cascade,
        kms,
        user,
        HashSet::new(),
    )
    .await?;

    Ok(DestroyResponse {
        unique_identifier: unique_identifier.clone(),
    })
}

/// This function is called recursively to destroy all the objects
/// that are linked to the object being destroyed
#[async_recursion(?Send)]
pub(crate) async fn recursively_destroy_object(
    unique_identifier: &UniqueIdentifier,
    remove: bool,
    cascade: bool,
    kms: &KMS,
    user: &str,
    // keys that should be skipped
    mut ids_to_skip: HashSet<String>,
) -> KResult<()> {
    trace!(
        "uid={} remove={} cascade={}",
        unique_identifier, remove, cascade
    );
    let uids = uids_from_unique_identifier(unique_identifier, kms)
        .await
        .context("Destroy")?;

    let mut count = 0;
    for uid in uids {
        let op_start = std::time::Instant::now();
        // If the object has a prefix (external object store),
        // destroy all the objects with this prefix
        if let Some(_prefix) = has_prefix(&uid) {
            // ensure user can destroy
            if !kms.database.is_object_owned_by(&uid, user).await? {
                let ops = kms
                    .database
                    .list_user_operations_on_object(&uid, user, false)
                    .await?;
                if !ops.iter().any(|p| KmipOperation::Destroy == *p) {
                    continue;
                }
            }
            kms.database.delete(&uid).await?;
            count += 1;
            info!(uid = uid, user = user, "Destroyed object");
            continue;
        }

        // Default database: retrieve the object
        let Some(mut owm) = kms.database.retrieve_object(&uid).await? else {
            continue;
        };

        // Check if the object is owned by the user
        // If the object is not owned by the user, check if the user has destroy permissions
        if user != owm.owner() {
            let permissions = kms
                .database
                .list_user_operations_on_object(owm.id(), user, false)
                .await?;
            if !permissions.contains(&KmipOperation::Destroy) {
                continue;
            }
        }

        // Determine the effective current state. In some historical paths the DB "state" column
        // was persisted as Active while the serialized attributes (both in object key_block and in
        // metadata) still held a PreActive state (KMIP compliant initial state after Create).
        // We treat such objects as effectively PreActive for lifecycle enforcement so that
        // Destroy is allowed without a prior Revoke, matching KMIP and mandatory vector expectations.
        let db_state = owm.state();
        let attributes_state = owm
            .object()
            .attributes()
            .unwrap_or_else(|_| owm.attributes())
            .state
            .unwrap_or(db_state);
        let effective_state = attributes_state;
        // Policy evaluation: use the effective state from attributes for KMIP compliance
        let activation_date = owm
            .object()
            .attributes()
            .unwrap_or_else(|_| owm.attributes())
            .activation_date;
        let effective_policy_state = effective_state;

        // Check if the object is already destroyed or of an unsupported type for Destroy
        let object_type = owm.object().object_type();
        if effective_state == State::Destroyed
            || effective_state == State::Destroyed_Compromised
            || (object_type != ObjectType::PrivateKey
                && object_type != ObjectType::SymmetricKey
                && object_type != ObjectType::Certificate
                && object_type != ObjectType::SecretData
                && object_type != ObjectType::PublicKey
                && object_type != ObjectType::OpaqueObject)
        {
            continue;
        }

        // KMIP 2.1 lifecycle enforcement:
        // - Objects created via Register (start Active) can be destroyed directly
        // - Objects created via Create then explicitly Activated require revocation before destroy
        // - PreActive objects can always be destroyed directly
        // The key distinction is explicit vs implicit activation.
        trace!(
            "[destroy] policy-eval uid={} type={:?} db_state={:?} attr_state={:?} effective_state={:?} activation_date={:?} policy_state={:?} remove={}",
            owm.id(),
            object_type,
            db_state,
            attributes_state,
            effective_state,
            activation_date,
            effective_policy_state,
            remove
        );

        // Check if this is an explicitly activated object that requires revocation
        let requires_revocation = effective_policy_state == State::Active
            && matches!(
                object_type,
                ObjectType::SymmetricKey
                    | ObjectType::SecretData
                    | ObjectType::Certificate
                    | ObjectType::PrivateKey
                    | ObjectType::PublicKey
            )
            // Only objects that were explicitly activated (Create -> Activate flow) require revocation
            // Objects that were registered (Register -> already Active) can be destroyed directly
            // We can distinguish by checking if activation_date exists and initial_date exists,
            // and if activation_date exists (indicating explicit activation)
            // For Create→Activate flow, activation_date will be set by the Activate operation
            // For Register flow, objects start Active without needing explicit activation
            && activation_date.is_some();

        if requires_revocation {
            trace!(
                "[destroy] DENY revoke-before-destroy (explicitly activated) uid={} type={:?} state={:?} activation_date={:?} initial_date={:?}",
                owm.id(),
                object_type,
                effective_policy_state,
                activation_date,
                owm.attributes().initial_date
            );
            return Err(KmsError::Kmip21Error(
                ErrorReason::Wrong_Key_Lifecycle_State,
                "DENIED".to_owned(),
            ));
        }

        // perform the chain of destroy operations depending on the type of object
        count += 1;
        let object_type = owm.object().object_type();

        match object_type {
            ObjectType::SymmetricKey
            | ObjectType::Certificate
            | ObjectType::SecretData
            | ObjectType::OpaqueObject => {
                // destroy the key
                let id = owm.id().to_owned();
                let state = effective_state;
                destroy_core(&id, remove, owm.object_mut(), state, kms).await?;
            }
            ObjectType::PrivateKey => {
                // add this key to the ids to skip
                ids_to_skip.insert(owm.id().to_owned());
                // for Covercrypt, if that is a master secret key, destroy the user decryption keys
                #[cfg(feature = "non-fips")]
                if cascade
                    && owm.object().key_block()?.key_format_type
                        == KeyFormatType::CoverCryptSecretKey
                {
                    destroy_user_decryption_keys(
                        owm.id(),
                        remove,
                        true, // always cascade when destroying a `Covercrypt` master private key
                        kms,
                        user,
                        ids_to_skip.clone(),
                    )
                    .await?;
                }
                // When cascading, destroy any linked public key
                if cascade {
                    if let Some(public_key_id) = owm
                        .object()
                        .attributes()
                        .unwrap_or_else(|_| owm.attributes())
                        .get_link(LinkType::PublicKeyLink)
                        .map(|l| l.to_string())
                    {
                        if !ids_to_skip.contains(&public_key_id) {
                            recursively_destroy_object(
                                &UniqueIdentifier::TextString(public_key_id),
                                remove,
                                cascade,
                                kms,
                                user,
                                ids_to_skip.clone(),
                            )
                            .await?;
                        }
                    }
                }

                // destroy the private key
                let id = owm.id().to_owned();
                let state = effective_state;
                destroy_core(&id, remove, owm.object_mut(), state, kms).await?;
            }
            ObjectType::PublicKey => {
                ids_to_skip.insert(owm.id().to_owned());
                // For CoverCrypt, if the linked private key is a master secret key, destroy the user decryption keys
                if cascade {
                    if let Some(private_key_id) = owm
                        .object()
                        .attributes()
                        .unwrap_or_else(|_| owm.attributes())
                        .get_link(LinkType::PrivateKeyLink)
                        .map(|l| l.to_string())
                    {
                        #[cfg(feature = "non-fips")]
                        if let Ok(Some(private_owm)) =
                            kms.database.retrieve_object(&private_key_id).await
                        {
                            if let Ok(kb) = private_owm.object().key_block() {
                                if kb.key_format_type == KeyFormatType::CoverCryptSecretKey {
                                    destroy_user_decryption_keys(
                                        &private_key_id,
                                        remove,
                                        true, // always cascade when destroying a `Covercrypt` master private key
                                        kms,
                                        user,
                                        ids_to_skip.clone(),
                                    )
                                    .await?;
                                }
                            }
                        }
                        // Try to destroy the linked private key, but don't fail if it's not allowed
                        // This allows destroying a PreActive public key even if its linked private key is Active
                        if !ids_to_skip.contains(&private_key_id) {
                            let private_key_id_clone = private_key_id.clone();
                            if let Err(e) = recursively_destroy_object(
                                &UniqueIdentifier::TextString(private_key_id),
                                remove,
                                cascade,
                                kms,
                                user,
                                ids_to_skip.clone(),
                            )
                            .await
                            {
                                // Log the error but continue with public key destruction
                                trace!(
                                    "[destroy] Failed to destroy linked private key {}: {:?}. Continuing with public key destruction.",
                                    private_key_id_clone, e
                                );
                            }
                        }
                    }
                }
                // Destroy the public key
                let id = owm.id().to_owned();
                let state = effective_state;
                destroy_core(&id, remove, owm.object_mut(), state, kms).await?;
            }
            x => kms_bail!(KmsError::NotSupported(format!(
                "destroy operation is not supported for object type {x:?}"
            ))),
        }
        // Per-object KMIP metrics recording
        if let Some(metrics) = &kms.metrics {
            metrics.record_kmip_operation("Destroy", user);
            let duration = op_start.elapsed().as_secs_f64();
            metrics.record_kmip_operation_duration("Destroy", duration);
        }
        debug!(
            "Object type: {}, with unique identifier: {}, destroyed by user {}",
            owm.object().object_type(),
            owm.id(),
            user
        );
    }

    if count == 0 {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Item_Not_Found,
            unique_identifier.to_string(),
        ));
    }

    Ok(())
}

/// Destroy an Object, knowing the object and state
async fn destroy_core(
    unique_identifier: &str,
    remove: bool,
    object: &mut Object,
    state: State,
    kms: &KMS,
) -> KResult<()> {
    if remove {
        remove_from_database(unique_identifier, state, kms).await
    } else {
        update_as_destroyed(unique_identifier, object, state, kms).await
    }
}

/// Remove an Object from the database
/// This is a Cosmian specific operation
async fn remove_from_database(unique_identifier: &str, state: State, kms: &KMS) -> KResult<()> {
    if state == State::Active {
        return Err(KmsError::InvalidRequest(format!(
            "Object with unique identifier: {unique_identifier} is active. It must be revoked \
             first"
        )));
    }
    kms.database.delete(unique_identifier).await?;
    Ok(())
}

/// Destroy an Object, knowing the object and state
/// This is the standard KMIP Destroy operation
async fn update_as_destroyed(
    unique_identifier: &str,
    object: &mut Object,
    state: State,
    kms: &KMS,
) -> KResult<()> {
    // Determine target destroyed state. Historically Active objects were rejected earlier unless
    // policy relaxed (e.g. for freshly registered asymmetric keys). We now allow an Active state
    // to transition directly to Destroyed when the caller passed earlier lifecycle checks.
    let new_state = match state {
        State::Active | State::PreActive | State::Deactivated => State::Destroyed,
        State::Compromised => State::Destroyed_Compromised,
        State::Destroyed | State::Destroyed_Compromised => return Ok(()),
    };

    // The KMIP specs mandates that KeyMaterial be destroyed. For objects lacking a Key Block
    // (OpaqueObject) we instead zero the opaque_data_value. Certificates are handled by clearing
    // attributes to defaults.
    trace!(
        "[destroy-core] uid={unique_identifier} type={:?} pre-state={:?} object={object}",
        object.object_type(),
        state
    );
    let attributes = match object {
        Object::Certificate { .. } => {
            trace!("[destroy-core] certificate zeroization uid={unique_identifier}");
            Attributes::default()
        }
        Object::OpaqueObject(_) => {
            if let Object::OpaqueObject(inner) = object {
                trace!(
                    "[destroy-core] opaque object zeroization uid={unique_identifier} len={} ",
                    inner.opaque_data_value.len()
                );
                inner.opaque_data_value.clear();
            }
            // OpaqueObject has no embedded attributes; use default container
            Attributes::default()
        }
        _ => {
            let key_block = object.key_block_mut()?;
            let attributes = key_block.attributes().cloned().unwrap_or_default();
            // Empty the Key Material
            key_block.key_format_type = KeyFormatType::Raw;
            key_block.key_value = Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::from(vec![])),
                attributes: Some(attributes.clone()),
            });
            attributes
        }
    };

    kms.database
        .update_object(unique_identifier, object, &attributes, None)
        .await?;

    kms.database
        .update_state(unique_identifier, new_state)
        .await?;

    debug!(
        "Object with unique identifier: {} destroyed",
        unique_identifier
    );

    Ok(())
}
