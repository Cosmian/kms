use std::collections::HashSet;

use async_recursion::async_recursion;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::KeyFormatType;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, RevocationReason, RevocationReasonCode, State},
        kmip_2_1::{
            KmipOperation,
            kmip_objects::ObjectType,
            kmip_operations::{Revoke, RevokeResponse},
            kmip_types::{LinkType, UniqueIdentifier},
        },
        time_normalize,
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{debug, info, trace};
use time::OffsetDateTime;

#[cfg(feature = "non-fips")]
use crate::core::cover_crypt::revoke_user_decryption_keys;
use crate::{
    core::{
        KMS,
        uid_utils::{has_prefix, uids_from_unique_identifier},
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

pub(crate) async fn revoke_operation(
    kms: &KMS,
    request: Revoke,
    user: &str,
) -> KResult<RevokeResponse> {
    trace!("{request}");
    // there must be an identifier
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // TODO   Reasons should be kept in the database
    let revocation_reason = request.revocation_reason.clone();
    let compromise_occurrence_date = request.compromise_occurrence_date;

    // For demo purposes, make some keys non-revocable (like Google CSE and MS DKE keys)
    if let Some(non_revocable_key_id) = &kms.params.non_revocable_key_id {
        if non_revocable_key_id.contains(&unique_identifier.to_string()) {
            trace!("Non revocable keys detected: won't be revoked {non_revocable_key_id:?}");
            return Ok(RevokeResponse {
                unique_identifier: UniqueIdentifier::TextString(unique_identifier.to_string()),
            });
        }
    }

    recursively_revoke_key(
        unique_identifier,
        revocation_reason,
        compromise_occurrence_date,
        request.cascade,
        kms,
        user,
        HashSet::new(),
    )
    .await?;

    Ok(RevokeResponse {
        unique_identifier: unique_identifier.clone(),
    })
}

/// Recursively revoke keys
#[allow(clippy::too_many_arguments)]
#[async_recursion(?Send)]
pub(crate) async fn recursively_revoke_key(
    unique_identifier: &UniqueIdentifier,
    revocation_reason: RevocationReason,
    compromise_occurrence_date: Option<OffsetDateTime>,
    cascade: bool,
    kms: &KMS,
    user: &str,
    // keys that should be skipped
    mut ids_to_skip: HashSet<String>,
) -> KResult<()> {
    let uids = uids_from_unique_identifier(unique_identifier, kms)
        .await
        .context("Revoke")?;

    let mut count = 0;
    for uid in uids {
        // Revoke does not apply to prefixed objects
        // TODO: this should probably be a setting on the Objects Store, i.e. whether the store supports objects states
        if let Some(prefix) = has_prefix(&uid) {
            // ensure user can revoke
            if !kms.database.is_object_owned_by(&uid, user).await? {
                let ops = kms
                    .database
                    .list_user_operations_on_object(&uid, user, false)
                    .await?;
                if !ops.iter().any(|p| KmipOperation::Revoke == *p) {
                    continue;
                }
            }
            if kms
                .database
                .update_state(&uid, State::Deactivated)
                .await
                .is_ok()
            {
                count += 1;
                debug!(
                    "Object with unique identifier: {} revoked by user {}",
                    uid, user
                );
                continue;
            }
            return Err(KmsError::NotSupported(format!(
                "Objects with prefix '{prefix}' cannot be revoked. Destroy them directly."
            )));
        }
        // retrieve the object
        let Some(owm) = kms.database.retrieve_object(&uid).await? else {
            continue;
        };

        let object_type = owm.object().object_type();
        let uid = owm.id().to_owned();
        if owm.state() != State::Active && owm.state() != State::PreActive {
            // Special case: if this is the direct target of the Revoke request (first uid) and the
            // object is already Destroyed / Destroyed_Compromised, KMIP profile AKLC-M-2-21 still
            // expects a successful Revoke earlier in the sequence (i.e., we shouldn't emit
            // Item_Not_Found just because a linked public key was previously destroyed). We allow
            // Destroyed states to pass through without performing a state transition.
            if owm.state() == State::Destroyed || owm.state() == State::Destroyed_Compromised {
                trace!(
                    "[revoke] proceed-destroyed uid={uid} state={:?}",
                    owm.state()
                );
            } else {
                trace!(
                    "[revoke] skip uid={uid} reason=state-not-revocable state={:?}",
                    owm.state()
                );
                continue;
            }
        }
        if object_type != ObjectType::PrivateKey
            && object_type != ObjectType::Certificate
            && object_type != ObjectType::SymmetricKey
            && object_type != ObjectType::PublicKey
            && object_type != ObjectType::SecretData
            && object_type != ObjectType::OpaqueObject
        {
            continue;
        }
        // if the user is not the owner, we need to check if the user has the right to decrypt
        // or get the key (in which case it can decrypt on its side)
        if user != owm.owner() {
            let permissions = kms
                .database
                .list_user_operations_on_object(owm.id(), user, false)
                .await?;
            if !permissions.contains(&KmipOperation::Revoke) {
                continue;
            }
        }
        count += 1;
        // Perform the chain of revoke operations depending on the type of object
        let object_type = owm.object().object_type();
        match object_type {
            ObjectType::SymmetricKey
            | ObjectType::Certificate
            | ObjectType::SecretData
            | ObjectType::OpaqueObject => {
                // revoke the key
                revoke_key_core(
                    owm,
                    revocation_reason.clone(),
                    compromise_occurrence_date,
                    kms,
                )
                .await?;
            }
            ObjectType::PrivateKey => {
                // add this key to the ids to skip
                ids_to_skip.insert(owm.id().to_owned());
                // For Covercrypt master secret keys (non-fips), revoke related user decryption keys.
                #[cfg(feature = "non-fips")]
                if owm.object().key_block()?.key_format_type == KeyFormatType::CoverCryptSecretKey {
                    revoke_user_decryption_keys(
                        &uid,
                        revocation_reason.clone(),
                        compromise_occurrence_date,
                        kms,
                        user,
                        ids_to_skip.clone(),
                    )
                    .await?;
                }
                // Conditional cascade to the linked public key only when requested via Revoke.cascade=true.
                if cascade {
                    if let Some(public_key_id) = owm
                        .object()
                        .attributes()
                        .unwrap_or_else(|_| owm.attributes())
                        .get_link(LinkType::PublicKeyLink)
                        .map(|l| l.to_string())
                    {
                        if !ids_to_skip.contains(&public_key_id) {
                            recursively_revoke_key(
                                &UniqueIdentifier::TextString(public_key_id),
                                revocation_reason.clone(),
                                compromise_occurrence_date,
                                cascade,
                                kms,
                                user,
                                ids_to_skip.clone(),
                            )
                            .await?;
                        }
                    }
                }
                revoke_key_core(
                    owm,
                    revocation_reason.clone(),
                    compromise_occurrence_date,
                    kms,
                )
                .await?;
            }
            ObjectType::PublicKey => {
                ids_to_skip.insert(owm.id().to_owned());
                // Conditional cascade to the linked private key only when requested via Revoke.cascade=true.
                if cascade {
                    if let Some(private_key_id) = owm
                        .object()
                        .attributes()
                        .unwrap_or_else(|_| owm.attributes())
                        .get_link(LinkType::PrivateKeyLink)
                        .map(|l| l.to_string())
                    {
                        if !ids_to_skip.contains(&private_key_id) {
                            recursively_revoke_key(
                                &UniqueIdentifier::TextString(private_key_id),
                                revocation_reason.clone(),
                                compromise_occurrence_date,
                                cascade,
                                kms,
                                user,
                                ids_to_skip.clone(),
                            )
                            .await?;
                        }
                    }
                }
                revoke_key_core(
                    owm,
                    revocation_reason.clone(),
                    compromise_occurrence_date,
                    kms,
                )
                .await?;
            }
            x => kms_bail!(KmsError::NotSupported(format!(
                "revoke operation is not supported for object type {x:?}"
            ))),
        }

        info!(
            uid = uid,
            user = user,
            "Revoked object type: {}",
            object_type,
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

/// Revoke a key, knowing the object and state
async fn revoke_key_core(
    mut owm: ObjectWithMetadata,
    revocation_reason: RevocationReason,
    compromise_occurrence_date: Option<OffsetDateTime>,
    kms: &KMS,
) -> KResult<()> {
    // Update the state of the object to Active and activation date
    let now = time_normalize()?;
    let state = match revocation_reason {
        RevocationReason {
            revocation_reason_code:
                RevocationReasonCode::KeyCompromise | RevocationReasonCode::CACompromise,
            ..
        } => State::Compromised,
        _ => State::Deactivated,
    };

    if let Ok(object_attributes) = owm.object_mut().attributes_mut() {
        object_attributes.state = Some(state);
        // update the deactivation date
        object_attributes.deactivation_date = Some(now);
        // update the compromise occurrence date if provided
        if let Some(date) = compromise_occurrence_date {
            object_attributes.compromise_occurrence_date = Some(date);
        }
    }
    // Update the state in the "external" attributes
    owm.attributes_mut().state = Some(state);
    // Update the deactivation date in the "external" attributes
    owm.attributes_mut().deactivation_date = Some(now);
    // Update the compromise occurrence date in the "external" attributes if provided
    if let Some(date) = compromise_occurrence_date {
        owm.attributes_mut().compromise_occurrence_date = Some(date);
    }

    kms.database
        .update_object(owm.id(), owm.object(), owm.attributes(), None)
        .await?;

    kms.database.update_state(owm.id(), state).await?;

    debug!("Object with unique identifier: {} revoked", owm.id());

    Ok(())
}
