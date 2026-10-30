use std::collections::HashSet;

use async_recursion::async_recursion;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::KeyFormatType;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, RevocationReason, RevocationReasonCode, State},
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_objects::{Certificate, Object, ObjectType},
            kmip_operations::{Revoke, RevokeResponse},
            kmip_types::{LinkType, UniqueIdentifier},
        },
        time_normalize,
    },
    cosmian_kms_interfaces::{AtomicOperation, ObjectWithMetadata},
};
use cosmian_logger::{debug, info, trace, warn};
use openssl::x509::X509;
use time::OffsetDateTime;

#[cfg(feature = "non-fips")]
use crate::core::cover_crypt::revoke_user_decryption_keys;
use crate::{
    core::{
        KMS,
        uid_utils::{ObjectHandle, resolve_uids},
    },
    error::KmsError,
    middlewares::UserId,
    result::{KResult, KResultHelper},
};

pub(crate) async fn revoke_operation(
    kms: &KMS,
    mut request: Revoke,
    user: &UserId,
) -> KResult<RevokeResponse> {
    trace!("Revoke request");
    // there must be an identifier
    let unique_identifier = request
        .unique_identifier
        .take()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    let revocation_reason = request.revocation_reason;
    let compromise_occurrence_date = request.compromise_occurrence_date;
    // KMIP 2.1 Table 295: the Compromise Occurrence Date SHALL NOT be specified for
    // revocation reasons other than key/CA compromise.
    if compromise_occurrence_date.is_some() && !is_compromise(&revocation_reason) {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            "Revoke: Compromise Occurrence Date is only allowed with a Key Compromise or CA \
             Compromise revocation reason"
                .to_owned(),
        ));
    }

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
        &unique_identifier,
        revocation_reason,
        compromise_occurrence_date,
        request.cascade,
        kms,
        user,
        HashSet::new(),
    )
    .await?;

    Ok(RevokeResponse { unique_identifier })
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
    user: &UserId,
    // keys that should be skipped
    mut ids_to_skip: HashSet<String>,
) -> KResult<()> {
    let uids = resolve_uids(ObjectHandle::try_from(unique_identifier)?, kms)
        .await
        .context("Revoke")?;
    let op_start = std::time::Instant::now();

    let mut count = 0;
    for uid in uids {
        // Revoke does not apply to prefixed objects
        // TODO: this should probably be a setting on the Objects Store, i.e. whether the store supports objects states
        if let ObjectHandle::Hsm { prefix, .. } = ObjectHandle::from(&uid) {
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
            // KMIP 2.1 §6.1.44: KeyCompromise/CACompromise → Compromised; all others → Deactivated
            let revoked_state = if is_compromise(&revocation_reason) {
                State::Compromised
            } else {
                State::Deactivated
            };
            if kms.database.update_state(&uid, revoked_state).await.is_ok() {
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

        // Permission check BEFORE any state inspection (COSMIAN-2026-037 anti-oracle): a
        // caller without the Revoke right must not distinguish missing, destroyed or
        // ungranted objects.
        if !kms
            .user_can_perform_operation(&owm, user, &KmipOperation::Revoke)
            .await?
        {
            continue;
        }
        let object_type = owm.object().object_type();
        let uid = owm.id().to_owned();
        if object_type == ObjectType::CertificateRequest {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Object_Type,
                format!("Revoke: object type {object_type:?} cannot be revoked"),
            ));
        }
        // KMIP 2.1 §4.57: only the listed state transitions are permitted.
        let current_state = owm.effective_state();
        // A non-compromise Revoke of an object that is already Deactivated or Destroyed changes
        // nothing and succeeds, so that Revoke -> Destroy sequences stay idempotent.
        if !is_compromise(&revocation_reason)
            && matches!(
                current_state,
                State::Deactivated | State::Destroyed | State::Destroyed_Compromised
            )
        {
            count += 1;
            continue;
        }
        // Opaque Objects have no Activate operation, so they stay Pre-Active after Register
        // and must still be revocable.
        let current_state =
            if object_type == ObjectType::OpaqueObject && current_state == State::PreActive {
                State::Active
            } else {
                current_state
            };
        let Some(target_state) = revocation_target_state(&revocation_reason, current_state) else {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Wrong_Key_Lifecycle_State,
                format!(
                    "Revoke: object {uid} in state {current_state:?} cannot be revoked with \
                     reason {:?}",
                    revocation_reason.revocation_reason_code
                ),
            ));
        };
        count += 1;
        // Perform the chain of revoke operations depending on the type of object
        match object_type {
            ObjectType::Certificate => {
                // Read the issuer link before the object is mutated, so we can
                // trigger background CRL regeneration after the state change.
                let issuer_id = owm
                    .object()
                    .attributes()
                    .ok()
                    .or_else(|| Some(owm.attributes()))
                    .and_then(|attrs| attrs.get_link(LinkType::CertificateLink))
                    .map(|l| l.to_string());
                // Extract the serial number (before `owm` is consumed below) so the
                // OCSP response cache entry for this exact certificate can be
                // evicted once revoked — otherwise a relying party polling OCSP
                // with no nonce could keep receiving a stale cached `good`
                // response until `ocsp_cache_ttl_secs` naturally expires.
                let serial_hex = extract_serial_hex_for_ocsp_cache(owm.object());

                Box::pin(revoke_key_core(
                    owm,
                    revocation_reason.clone(),
                    compromise_occurrence_date,
                    target_state,
                    kms,
                ))
                .await?;

                if let (Some(issuer_id), Some(serial_hex)) = (issuer_id.clone(), serial_hex) {
                    crate::routes::ocsp::evict_ocsp_cache_entry(&issuer_id, &serial_hex).await;
                }

                // Fire-and-forget CRL regeneration: when the server knows its own
                // public URL, immediately refresh the CRL so the CDP endpoint serves
                // an up-to-date list without requiring a manual generate-crl call.
                // Errors here must never fail the Revoke operation.
                //
                // Server-triggered: neither the revoking user (e.g. a leaf-certificate
                // owner) nor `default_username` can generally use the CA key. The key is
                // authorized as the issuer certificate's owner.
                if kms.params.kms_public_url.is_some() {
                    if let Some(issuer_id) = issuer_id {
                        trigger_crl_regeneration(kms, &issuer_id).await;
                    }
                }
            }
            ObjectType::SymmetricKey
            | ObjectType::PGPKey
            | ObjectType::SecretData
            | ObjectType::OpaqueObject
            | ObjectType::SplitKey => {
                // revoke the key
                Box::pin(revoke_key_core(
                    owm,
                    revocation_reason.clone(),
                    compromise_occurrence_date,
                    target_state,
                    kms,
                ))
                .await?;
            }
            ObjectType::PrivateKey | ObjectType::PublicKey => {
                ids_to_skip.insert(owm.id().to_owned());
                // For Covercrypt master secret keys (non-fips), revoke user decryption keys.
                #[cfg(feature = "non-fips")]
                if object_type == ObjectType::PrivateKey
                    && owm.object().key_block()?.key_format_type
                        == KeyFormatType::CoverCryptSecretKey
                {
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
                // Cascade to the paired counterpart (PrivateKey → PublicKey, PublicKey → PrivateKey)
                // only when Revoke.cascade=true.
                if cascade {
                    let link_type = if object_type == ObjectType::PrivateKey {
                        LinkType::PublicKeyLink
                    } else {
                        LinkType::PrivateKeyLink
                    };
                    if let Some(linked_id) = owm
                        .object()
                        .attributes()
                        .unwrap_or_else(|_| owm.attributes())
                        .get_link(link_type)
                        .map(|l| l.to_string())
                    {
                        if !ids_to_skip.contains(&linked_id) {
                            match recursively_revoke_key(
                                &UniqueIdentifier::TextString(linked_id),
                                revocation_reason.clone(),
                                compromise_occurrence_date,
                                cascade,
                                kms,
                                user,
                                ids_to_skip.clone(),
                            )
                            .await
                            {
                                // A linked key already in a state this reason cannot
                                // transition (e.g. already Deactivated) is left as is.
                                Err(KmsError::Kmip21Error(
                                    ErrorReason::Wrong_Key_Lifecycle_State,
                                    msg,
                                )) => trace!("[revoke] cascade skipped: {msg}"),
                                other => other?,
                            }
                            kms.record_cascading_metrics("Revoke", op_start, user);
                        }
                    }
                }
                Box::pin(revoke_key_core(
                    owm,
                    revocation_reason.clone(),
                    compromise_occurrence_date,
                    target_state,
                    kms,
                ))
                .await?;
            }
            // rejected with Invalid_Object_Type above
            ObjectType::CertificateRequest => {}
        }

        info!(
            uid = uid,
            user = user.as_str(),
            "Revoked object type: {}",
            object_type,
        );
    }

    if count == 0 {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Object_Not_Found,
            unique_identifier.to_string(),
        ));
    }

    Ok(())
}

/// Revoke an object, knowing the object and the target state.
///
/// KMIP 2.1 §6.1.44 / §4.10 / §4.18: a compromise sets the Compromise Date (and the
/// Compromise Occurrence Date, defaulting to the Initial Date); any other reason
/// deactivates the object and sets its Deactivation Date.
async fn revoke_key_core(
    mut owm: ObjectWithMetadata,
    revocation_reason: RevocationReason,
    compromise_occurrence_date: Option<OffsetDateTime>,
    state: State,
    kms: &KMS,
) -> KResult<()> {
    let now = time_normalize()?;
    let compromised = matches!(state, State::Compromised | State::Destroyed_Compromised);
    let compromise_occurrence_date = compromise_occurrence_date.or_else(|| {
        owm.attributes()
            .initial_date
            .or_else(|| owm.object().attributes().ok().and_then(|a| a.initial_date))
    });
    let apply = |attributes: &mut Attributes| {
        attributes.state = Some(state);
        if compromised {
            attributes.compromise_date = Some(now);
            if compromise_occurrence_date.is_some() {
                attributes.compromise_occurrence_date = compromise_occurrence_date;
            }
        } else {
            attributes.deactivation_date = Some(now);
        }
        // persist the revocation reason (needed for CRL generation per RFC 5280 §5.3.1)
        attributes.revocation_reason = Some(revocation_reason.clone());
    };
    if let Ok(object_attributes) = owm.object_mut().attributes_mut() {
        apply(object_attributes);
    }
    apply(owm.attributes_mut());

    let (id, object, attributes) = owm.into_parts();
    kms.database
        .atomic(
            &UserId::from(kms.params.default_username.as_str()),
            &[
                AtomicOperation::UpdateObject((id.clone(), object, attributes, None)),
                AtomicOperation::UpdateState((id.clone(), state)),
            ],
        )
        .await?;

    if compromised {
        // A compromised key must not keep serving open multi-part operations.
        kms.multi_part.purge_key(&id);
    }
    debug!("Object with unique identifier: {id} revoked");

    Ok(())
}

/// Whether the revocation reason is a key or CA compromise.
const fn is_compromise(reason: &RevocationReason) -> bool {
    matches!(
        reason.revocation_reason_code,
        RevocationReasonCode::KeyCompromise | RevocationReasonCode::CACompromise
    )
}

/// Return the [`State`] an object in `current` state transitions to when revoked for
/// `reason`, or `None` when KMIP 2.1 §4.57 permits no such transition.
///
/// - compromise: Pre-Active / Active / Deactivated → Compromised (transitions 3, 5, 8),
///   Destroyed → Destroyed Compromised (transition 10)
/// - any other reason: Active → Deactivated (transition 6)
const fn revocation_target_state(reason: &RevocationReason, current: State) -> Option<State> {
    match (is_compromise(reason), current) {
        (true, State::PreActive | State::Active | State::Deactivated) => Some(State::Compromised),
        (true, State::Destroyed) => Some(State::Destroyed_Compromised),
        (false, State::Active) => Some(State::Deactivated),
        _ => None,
    }
}

/// Extract a certificate's serial number as an upper-case hex string, in the exact
/// format the OCSP responder uses as part of its cache key (`"{ca_uid}:{serial_hex}"`,
/// see `crate::routes::ocsp::handler`). Returns `None` for anything that is not a
/// parseable certificate (should not happen for an object already matched as
/// `ObjectType::Certificate`, but this must never fail the parent `Revoke`).
fn extract_serial_hex_for_ocsp_cache(object: &Object) -> Option<String> {
    let Object::Certificate(Certificate {
        certificate_value, ..
    }) = object
    else {
        return None;
    };
    let x509 = X509::from_der(certificate_value).ok()?;
    let serial_bytes = x509.serial_number().to_bn().ok()?.to_vec();
    Some(hex::encode_upper(serial_bytes))
}

/// Trigger CRL regeneration for `issuer_id` after a certificate revocation.
///
/// The CRL is generated by the server itself: the signing key is authorized as the issuer
/// certificate's owner, not as the revoking user (see `generate_crl::regenerate_crl`). Errors
/// are logged and never fail the Revoke operation.
async fn trigger_crl_regeneration(kms: &KMS, issuer_id: &str) {
    info!(
        issuer_id = issuer_id,
        "Auto-CRL: triggered CRL regeneration for issuer '{issuer_id}' after certificate revocation"
    );

    if let Err(e) = Box::pin(crate::core::operations::generate_crl::regenerate_crl(
        kms, issuer_id,
    ))
    .await
    {
        warn!(
            issuer_id = issuer_id,
            "Auto-CRL: CRL regeneration failed for issuer '{issuer_id}': {e}"
        );
    }
}
