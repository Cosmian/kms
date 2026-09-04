use std::collections::HashSet;

use async_recursion::async_recursion;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::KeyFormatType;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, RevocationReason, RevocationReasonCode, State},
        kmip_2_1::{
            KmipOperation,
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
    kms_bail,
    middlewares::UserId,
    result::{KResult, KResultHelper},
};

pub(crate) async fn revoke_operation(
    kms: &KMS,
    request: Revoke,
    user: &UserId,
) -> KResult<RevokeResponse> {
    trace!("{request}");
    // there must be an identifier
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

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
            let revoked_state = revocation_target_state(&revocation_reason);
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

        let object_type = owm.object().object_type();
        let uid = owm.id().to_owned();
        // KMIP 2.1 §6.1.44 state-transition guard:
        // • Active / PreActive → proceed normally.
        // • Destroyed / Destroyed_Compromised → allow pass-through (AKLC-M-2-21).
        // • Deactivated → only proceed for Compromise reasons (transition #8).
        // • anything else → skip.
        match owm.state() {
            State::Active | State::PreActive => {}
            State::Destroyed | State::Destroyed_Compromised => {
                trace!(
                    "[revoke] proceed-destroyed uid={uid} state={:?}",
                    owm.state()
                );
                // AKLC-M-2-21 compatibility: succeed without performing a state
                // transition. Counting the object prevents a spurious Item_Not_Found
                // when a cascade Revoke reaches a linked key that was already destroyed.
                count += 1;
                continue;
            }
            State::Deactivated => {
                // Transition #8: Deactivated → Compromised is valid only for Compromise reasons.
                // For all others treat as a no-op so that Revoke → Destroy sequences still succeed.
                if !matches!(
                    revocation_reason.revocation_reason_code,
                    RevocationReasonCode::KeyCompromise | RevocationReasonCode::CACompromise
                ) {
                    count += 1;
                    continue;
                }
            }
            State::Compromised => {
                trace!(
                    "[revoke] skip uid={uid} reason=state-not-revocable state={:?}",
                    owm.state()
                );
                continue;
            }
        }
        if !matches!(
            object_type,
            ObjectType::PrivateKey
                | ObjectType::Certificate
                | ObjectType::SymmetricKey
                | ObjectType::PublicKey
                | ObjectType::SecretData
                | ObjectType::OpaqueObject
                | ObjectType::SplitKey
        ) {
            continue;
        }
        // if the user is not the owner, we need to check if the user has the right to revoke
        if !kms
            .user_can_perform_operation(&owm, user, &KmipOperation::Revoke)
            .await?
        {
            continue;
        }
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
                if kms.params.kms_public_url.is_some() {
                    if let Some(issuer_id) = issuer_id {
                        trigger_crl_regeneration(kms, &issuer_id, user).await;
                    }
                }
            }
            ObjectType::SymmetricKey
            | ObjectType::SecretData
            | ObjectType::OpaqueObject
            | ObjectType::SplitKey => {
                // revoke the key
                Box::pin(revoke_key_core(
                    owm,
                    revocation_reason.clone(),
                    compromise_occurrence_date,
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
                            recursively_revoke_key(
                                &UniqueIdentifier::TextString(linked_id),
                                revocation_reason.clone(),
                                compromise_occurrence_date,
                                cascade,
                                kms,
                                user,
                                ids_to_skip.clone(),
                            )
                            .await?;
                            kms.record_cascading_metrics("Revoke", op_start, user);
                        }
                    }
                }
                Box::pin(revoke_key_core(
                    owm,
                    revocation_reason.clone(),
                    compromise_occurrence_date,
                    kms,
                ))
                .await?;
            }
            x => kms_bail!(KmsError::NotSupported(format!(
                "revoke operation is not supported for object type {x:?}"
            ))),
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
    let now = time_normalize()?;
    let state = revocation_target_state(&revocation_reason);

    if let Ok(object_attributes) = owm.object_mut().attributes_mut() {
        object_attributes.state = Some(state);
        // update the deactivation date
        object_attributes.deactivation_date = Some(now);
        // update the compromise occurrence date if provided
        if let Some(date) = compromise_occurrence_date {
            object_attributes.compromise_occurrence_date = Some(date);
        }
        // persist the revocation reason (needed for CRL generation per RFC 5280 §5.3.1)
        object_attributes.revocation_reason = Some(revocation_reason.clone());
    }
    // Update the state in the "external" attributes
    owm.attributes_mut().state = Some(state);
    // Update the deactivation date in the "external" attributes
    owm.attributes_mut().deactivation_date = Some(now);
    // Update the compromise occurrence date in the "external" attributes if provided
    if let Some(date) = compromise_occurrence_date {
        owm.attributes_mut().compromise_occurrence_date = Some(date);
    }
    // Persist the revocation reason in the "external" attributes
    owm.attributes_mut().revocation_reason = Some(revocation_reason);

    kms.database
        .atomic(
            &UserId::from(kms.params.default_username.as_str()),
            &[
                AtomicOperation::UpdateObject((
                    owm.id().to_owned(),
                    owm.object().clone(),
                    owm.attributes().clone(),
                    None,
                )),
                AtomicOperation::UpdateState((owm.id().to_owned(), state)),
            ],
        )
        .await?;

    debug!("Object with unique identifier: {} revoked", owm.id());

    Ok(())
}

/// Return the [`State`] an object transitions to when revoked for the given `reason`.
///
/// - `KeyCompromise` / `CACompromise` → [`State::Compromised`]
/// - all other reason codes → [`State::Deactivated`]
const fn revocation_target_state(reason: &RevocationReason) -> State {
    match reason.revocation_reason_code {
        RevocationReasonCode::KeyCompromise | RevocationReasonCode::CACompromise => {
            State::Compromised
        }
        _ => State::Deactivated,
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
/// CRL content is public information (RFC 5280 §3) so no special role is required.
/// The signer is the first active Crypto Officer when one exists, because
/// `generate_crl` gates the `find_all` bypass on the CO role whenever
/// `crypto_officer.users` is configured. When no CO is configured (or none has
/// completed the ceremony) the `revoking_user` identity is used instead: that user
/// has already proven they can access the CA chain (owner or explicit `Revoke`
/// grant), so they can also read the CA certificate and its private key to sign the
/// CRL. Using `default_username` caused a silent permission failure when the CA
/// objects were owned by a different user.
///
/// Errors are logged at `warn` level and never propagated — this must not fail
/// the parent `Revoke` operation.
async fn trigger_crl_regeneration(kms: &KMS, issuer_id: &str, revoking_user: &UserId) {
    let signer = match kms.find_active_co().await {
        Ok(Some(co)) => co,
        _ => revoking_user.clone(),
    };

    info!(
        issuer_id = issuer_id,
        "Auto-CRL: triggered CRL regeneration for issuer '{issuer_id}' after certificate revocation"
    );

    if let Err(e) =
        crate::core::operations::generate_crl::generate_crl(kms, issuer_id, None, &signer).await
    {
        warn!(
            issuer_id = issuer_id,
            "Auto-CRL: CRL regeneration failed for issuer '{issuer_id}': {e}"
        );
    }
}
