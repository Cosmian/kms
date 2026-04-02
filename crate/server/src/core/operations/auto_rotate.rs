use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            extra::tagging::{VENDOR_ATTR_TAG, VENDOR_ID_COSMIAN},
            kmip_attributes::Attributes,
            kmip_objects::ObjectType,
            kmip_operations::{Certify, CreateKeyPair, ReKey, ReKeyKeyPair},
            kmip_types::{LinkType, LinkedObjectIdentifier, UniqueIdentifier},
        },
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use cosmian_logger::{debug, warn};
use time::OffsetDateTime;

use crate::{
    core::{
        KMS,
        operations::{certify::certify, create_key_pair, rekey, rekey_keypair},
    },
    result::KResult,
};

/// Rotate a single managed object identified by `uid` on behalf of its owner.
///
/// Dispatches based on object type:
/// - `SymmetricKey` → `ReKey` (new UID, KMIP §6.1.46)
/// - `PrivateKey` → `ReKeyKeyPair` (new UIDs for both private and public, KMIP §6.1.47)
/// - `PublicKey` → follows `PrivateKeyLink` to the private key and rotates the whole key pair
/// - `Certificate` → `Certify` with the existing cert UID (upsert / re-sign, KMIP §4.48)
/// - All other types → skipped with a warning (not rotatable per KMIP spec)
///
/// After a successful rotation this function emits an OpenTelemetry counter
/// `kms.key.auto_rotation` labelled with the detected algorithm.
#[allow(clippy::large_stack_frames)]
pub(crate) async fn auto_rotate_key(kms: &KMS, uid: &str, owner: &str) -> KResult<()> {
    // Retrieve the object to determine its type
    let Some(owm) = kms.database.retrieve_object(uid).await? else {
        warn!("object {uid} not found, skipping");
        return Ok(());
    };

    let object_type = owm.object().object_type();
    let algorithm = owm
        .attributes()
        .cryptographic_algorithm
        .map_or_else(|| "Unknown".to_owned(), |a| a.to_string());

    // Guard: skip objects whose rotation policy has already been cleared, e.g. by a
    // concurrent rotation of the paired private key.
    if owm.attributes().rotate_interval.is_none_or(|i| i == 0) {
        debug!("object {uid} has rotate_interval=0 (already rotated or cleared), skipping");
        return Ok(());
    }

    debug!("[auto_rotate_key] rotating {object_type:?} uid={uid} algorithm={algorithm}");

    match object_type {
        ObjectType::SymmetricKey => {
            // Capture the rotation policy BEFORE rekey (which sets rotate_interval=0 on the old key).
            let old_rotate_interval = owm.attributes().rotate_interval;
            let old_rotate_name = owm.attributes().rotate_name.clone();
            let old_rotate_offset = owm.attributes().rotate_offset;

            let request = ReKey {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                ..ReKey::default()
            };
            let response = Box::pin(rekey(kms, request, owner)).await?;
            let new_uid = response.unique_identifier.to_string();
            debug!("symmetric key {uid} rotated → new uid={new_uid}");

            // Transfer the rotation policy to the new key so it continues to
            // auto-rotate at the same cadence. The old key already has
            // rotate_interval = Some(0) written by rekey.rs Phase-2.
            if let Some(new_owm) = kms.database.retrieve_object(&new_uid).await? {
                let mut new_attrs = new_owm.attributes().clone();
                new_attrs.rotate_interval = old_rotate_interval;
                new_attrs.rotate_name = old_rotate_name;
                new_attrs.rotate_offset = old_rotate_offset;
                new_attrs.initial_date = Some(OffsetDateTime::now_utc());
                let new_tags = kms.database.retrieve_tags(&new_uid).await?;
                kms.database
                    .update_object(&new_uid, new_owm.object(), &new_attrs, Some(&new_tags))
                    .await?;
            }
        }

        ObjectType::PrivateKey => {
            // Capture the rotation policy BEFORE rekey (which sets rotate_interval=0 on the old key).
            let old_rotate_interval = owm.attributes().rotate_interval;
            let old_rotate_name = owm.attributes().rotate_name.clone();
            let old_rotate_offset = owm.attributes().rotate_offset;

            // Remember the linked public key UID so we can clear its rotation policy too
            // (preventing the cron from later trying to independently rotate the public key).
            let old_public_key_uid = owm
                .attributes()
                .get_link(LinkType::PublicKeyLink)
                .map(|l| l.to_string());

            // Determine whether this is a CoverCrypt key.
            // `rekey_keypair` only works for CoverCrypt; for RSA/EC/PQC keys it returns
            // Item_Not_Found so we must use `rotate_asymmetric_keypair` instead.
            #[cfg(feature = "non-fips")]
            let is_cover_crypt = {
                use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
                owm.attributes().cryptographic_algorithm == Some(CryptographicAlgorithm::CoverCrypt)
            };
            #[cfg(not(feature = "non-fips"))]
            let is_cover_crypt = false;

            if is_cover_crypt {
                // CoverCrypt: rekey_keypair modifies the master key in-place (same UIDs).
                let request = ReKeyKeyPair {
                    private_key_unique_identifier: Some(UniqueIdentifier::TextString(
                        uid.to_owned(),
                    )),
                    private_key_attributes: Some(owm.attributes().to_owned()),
                    ..ReKeyKeyPair::default()
                };
                let response = Box::pin(rekey_keypair(kms, request, owner, None)).await?;
                let new_uid = response.private_key_unique_identifier.to_string();
                debug!("CoverCrypt key pair {uid} rekeyed → uid={new_uid}");

                // Re-arm the rotation policy on the (same) key so the next cycle fires.
                if let Some(new_owm) = kms.database.retrieve_object(&new_uid).await? {
                    let mut new_attrs = new_owm.attributes().clone();
                    new_attrs.rotate_interval = old_rotate_interval;
                    new_attrs.rotate_name = old_rotate_name;
                    new_attrs.rotate_offset = old_rotate_offset;
                    new_attrs.initial_date = Some(OffsetDateTime::now_utc());
                    // Increment the rotation generation counter so notifications report the
                    // correct generation number (CoverCrypt rekeys in-place, same UID).
                    new_attrs.rotate_generation =
                        Some(new_attrs.rotate_generation.unwrap_or(0) + 1);
                    let new_tags = kms.database.retrieve_tags(&new_uid).await?;
                    kms.database
                        .update_object(&new_uid, new_owm.object(), &new_attrs, Some(&new_tags))
                        .await?;
                }
            } else {
                // RSA / EC / PQC: create an entirely new key pair and manage all links.
                Box::pin(rotate_asymmetric_keypair(
                    kms,
                    uid,
                    old_public_key_uid.as_deref(),
                    owner,
                    old_rotate_interval,
                    old_rotate_name,
                    old_rotate_offset,
                ))
                .await?;
                // `rotate_asymmetric_keypair` already clears rotate_interval on both old keys
                // and transfers the policy to the new private key.
                return Ok(());
            }

            // For CoverCrypt: clear the old public key's rotation policy so the cron does not
            // try to independently rotate the public key.
            if let Some(ref old_pk_uid) = old_public_key_uid {
                if let Some(old_pk_owm) = kms.database.retrieve_object(old_pk_uid).await? {
                    let mut old_pk_attrs = old_pk_owm.attributes().clone();
                    if old_pk_attrs.rotate_interval.is_some_and(|i| i != 0) {
                        old_pk_attrs.rotate_interval = Some(0);
                        let old_pk_tags = kms.database.retrieve_tags(old_pk_uid).await?;
                        kms.database
                            .update_object(
                                old_pk_uid,
                                old_pk_owm.object(),
                                &old_pk_attrs,
                                Some(&old_pk_tags),
                            )
                            .await?;
                    }
                }
            }
        }

        ObjectType::PublicKey => {
            // The rotation policy may have been set on the public key (not or in addition
            // to the private key).  We capture it here so we can use it as the policy for
            // the new key pair even when the private key itself has no rotate_interval set.
            let old_rotate_interval = owm.attributes().rotate_interval;
            let old_rotate_name = owm.attributes().rotate_name.clone();
            let old_rotate_offset = owm.attributes().rotate_offset;

            let Some(private_key_id) = owm.attributes().get_link(LinkType::PrivateKeyLink) else {
                warn!(
                    "public key {uid} has no PrivateKeyLink — cannot rotate \
                     without the associated private key; clearing rotation policy"
                );
                let mut attrs = owm.attributes().clone();
                attrs.rotate_interval = Some(0);
                let tags = kms.database.retrieve_tags(uid).await?;
                kms.database
                    .update_object(uid, owm.object(), &attrs, Some(&tags))
                    .await?;
                return Ok(());
            };
            let private_key_uid = private_key_id.to_string();

            // Retrieve the private key to determine the algorithm.
            // Some DB backends (e.g. redis-findex) return Err for a missing key rather than
            // Ok(None); handle both cases gracefully instead of propagating the error.
            let private_owm = match kms.database.retrieve_object(&private_key_uid).await {
                Ok(Some(owm)) => owm,
                Ok(None) => {
                    warn!(
                        "public key {uid}: linked private key {private_key_uid} not found; \
                         clearing rotation policy"
                    );
                    let mut attrs = owm.attributes().clone();
                    attrs.rotate_interval = Some(0);
                    let tags = kms.database.retrieve_tags(uid).await?;
                    kms.database
                        .update_object(uid, owm.object(), &attrs, Some(&tags))
                        .await?;
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "public key {uid}: cannot retrieve linked private key \
                         {private_key_uid}: {e}; clearing rotation policy"
                    );
                    let mut attrs = owm.attributes().clone();
                    attrs.rotate_interval = Some(0);
                    let tags = kms.database.retrieve_tags(uid).await?;
                    kms.database
                        .update_object(uid, owm.object(), &attrs, Some(&tags))
                        .await?;
                    return Ok(());
                }
            };

            // Choose the rotation path based on the key algorithm.
            // Do NOT delegate through auto_rotate_key (which has a guard that would skip
            // the private key if its own rotate_interval is None/0).
            #[cfg(feature = "non-fips")]
            let is_cover_crypt = {
                use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
                private_owm.attributes().cryptographic_algorithm
                    == Some(CryptographicAlgorithm::CoverCrypt)
            };
            #[cfg(not(feature = "non-fips"))]
            let is_cover_crypt = {
                let _ = &private_owm; // suppress unused-variable warning in FIPS builds
                false
            };

            if is_cover_crypt {
                // CoverCrypt: ReKeyKeyPair modifies the master keys in-place (same UIDs).
                let request = ReKeyKeyPair {
                    private_key_unique_identifier: Some(UniqueIdentifier::TextString(
                        private_key_uid.clone(),
                    )),
                    private_key_attributes: Some(private_owm.attributes().to_owned()),
                    ..ReKeyKeyPair::default()
                };
                let response = Box::pin(rekey_keypair(kms, request, owner, None)).await?;
                let new_uid = response.private_key_unique_identifier.to_string();
                debug!(
                    "CoverCrypt key pair (triggered by public key {uid}) rekeyed \
                     → uid={new_uid}"
                );
                // Re-arm rotation policy on the master private key.
                if let Some(new_owm) = kms.database.retrieve_object(&new_uid).await? {
                    let mut new_attrs = new_owm.attributes().clone();
                    new_attrs.rotate_interval = old_rotate_interval;
                    new_attrs.rotate_name = old_rotate_name;
                    new_attrs.rotate_offset = old_rotate_offset;
                    new_attrs.initial_date = Some(OffsetDateTime::now_utc());
                    let new_tags = kms.database.retrieve_tags(&new_uid).await?;
                    kms.database
                        .update_object(&new_uid, new_owm.object(), &new_attrs, Some(&new_tags))
                        .await?;
                }
                // Clear rotation policy on the old public key.
                let mut attrs = owm.attributes().clone();
                attrs.rotate_interval = Some(0);
                let tags = kms.database.retrieve_tags(uid).await?;
                kms.database
                    .update_object(uid, owm.object(), &attrs, Some(&tags))
                    .await?;
            } else {
                // RSA / EC / PQC: create an entirely new key pair.
                // Pass the public key UID explicitly; `rotate_asymmetric_keypair` will clear
                // rotate_interval on BOTH old keys atomically.
                // Use the rotation policy captured from the PUBLIC KEY (the private key may
                // have rotate_interval=None if the user only set the policy on the public key).
                Box::pin(rotate_asymmetric_keypair(
                    kms,
                    &private_key_uid,
                    Some(uid),
                    owner,
                    old_rotate_interval,
                    old_rotate_name,
                    old_rotate_offset,
                ))
                .await?;
                return Ok(());
            }
        }

        ObjectType::Certificate => {
            // Renewal creates a completely NEW set of objects (new private key, public key,
            // and certificate). The old objects are preserved as-is, with a
            // ReplacementObjectLink pointing to their successors (KMIP 2.1 §4.48 semantics).
            let existing_attrs = owm.attributes().clone();
            let new_generation = existing_attrs.rotate_generation.unwrap_or(0) + 1;

            // Collect the old private key UID — needed to look up the crypto algorithm.
            let old_private_key_id = existing_attrs
                .get_link(LinkType::PrivateKeyLink)
                .map(|l| l.to_string());

            // build_and_sign_certificate strips cryptographic_algorithm from cert attributes,
            // so we must fetch it (plus key-size / curve) from the linked private key.
            let Some(ref old_private_key_uid) = old_private_key_id else {
                warn!(
                    "certificate {uid} has no PrivateKeyLink — cannot auto-renew \
                     without the linked private key, skipping"
                );
                return Ok(());
            };
            let Some(old_pk_owm) = kms.database.retrieve_object(old_private_key_uid).await? else {
                warn!(
                    "certificate {uid}: linked private key {old_private_key_uid} not found, \
                     cannot auto-renew, skipping"
                );
                return Ok(());
            };
            let Some(cryptographic_algorithm) = old_pk_owm.attributes().cryptographic_algorithm
            else {
                warn!(
                    "certificate {uid}: linked private key {old_private_key_uid} has no \
                     cryptographic_algorithm; cannot generate replacement key pair, skipping"
                );
                return Ok(());
            };
            let cryptographic_length = old_pk_owm.attributes().cryptographic_length;
            let cryptographic_parameters = old_pk_owm.attributes().cryptographic_parameters.clone();

            // Build a Certify request that creates entirely new objects.
            // Omitting `unique_identifier` causes get_subject to take the
            // Subject::KeypairAndSubjectName path: fresh private key, public key, and
            // certificate UIDs are all auto-assigned.
            // The new cert inherits the rotation policy so it continues to auto-rotate
            // at the same cadence; the old cert's interval is set to 0 below.
            let certify_attrs = Attributes {
                certificate_attributes: existing_attrs.certificate_attributes.clone(),
                cryptographic_algorithm: Some(cryptographic_algorithm),
                cryptographic_length,
                cryptographic_parameters,
                rotate_generation: Some(new_generation),
                // Preserve custom vendor metadata so the new cert inherits user-defined
                // vendor attributes from the old certificate.
                vendor_attributes: existing_attrs.vendor_attributes.clone(),
                ..Attributes::default()
            };
            let new_certify_request = Certify {
                unique_identifier: None,
                attributes: Some(certify_attrs),
                ..Certify::default()
            };
            let response = Box::pin(certify(kms, new_certify_request, owner, None)).await?;
            let new_cert_uid = response.unique_identifier.to_string();

            // ------------------------------------------------------------------
            // Add cross-links and stop auto-rotation on the old certificate.
            // The old private/public keys are NOT given ReplacementObjectLink
            // because only the certificate is the subject of the auto-rotate
            // policy; the key pair is renewed as a side-effect of cert renewal
            // and the old keys should not track the new ones via links.
            //
            // Both the old-cert update (adds ReplacementObjectLink) and the
            // new-cert update (sets rotate_interval) are done in a single
            // `database.atomic()` call to eliminate a race condition where a
            // client could read ReplacementObjectLink on the old cert before
            // rotate_interval has been written to the new cert.
            // ------------------------------------------------------------------

            let old_cert_tags = kms.database.retrieve_tags(uid).await?;

            // Prepare old-cert attributes: add ReplacementObjectLink, clear rotation policy.
            let mut old_cert_attrs = existing_attrs.clone();
            old_cert_attrs.set_link(
                LinkType::ReplacementObjectLink,
                LinkedObjectIdentifier::TextString(new_cert_uid.clone()),
            );
            old_cert_attrs.rotate_interval = Some(0);
            old_cert_attrs.rotate_date = None;
            old_cert_attrs.initial_date = None;

            // Prepare new-cert attributes: add ReplacedObjectLink, inherit rotation policy.
            let new_cert_op =
                if let Some(new_cert_owm) = kms.database.retrieve_object(&new_cert_uid).await? {
                    let mut new_cert_attrs = new_cert_owm.attributes().clone();
                    new_cert_attrs.set_link(
                        LinkType::ReplacedObjectLink,
                        LinkedObjectIdentifier::TextString(uid.to_owned()),
                    );
                    // Inherit rotation policy from the old cert.
                    new_cert_attrs.rotate_interval = existing_attrs.rotate_interval;
                    new_cert_attrs
                        .rotate_name
                        .clone_from(&existing_attrs.rotate_name);
                    new_cert_attrs.rotate_offset = existing_attrs.rotate_offset;
                    // Reset the rotation-timer origin on the new cert so the next
                    // rotation fires after one full interval from now.
                    new_cert_attrs.initial_date = Some(OffsetDateTime::now_utc());
                    // Inherit the old cert's user-defined tags so the new cert remains findable
                    // under the same user-defined labels. System tags (starting with '_') are
                    // excluded — they are re-assigned by the DB automatically.
                    let new_cert_inherited_tags: std::collections::HashSet<String> = old_cert_tags
                        .iter()
                        .filter(|t| !t.starts_with('_'))
                        .cloned()
                        .collect();
                    let op = AtomicOperation::UpdateObject((
                        new_cert_uid.clone(),
                        new_cert_owm.object().clone(),
                        new_cert_attrs,
                        Some(new_cert_inherited_tags),
                    ));
                    Some(op)
                } else {
                    None
                };

            // Atomically update old cert and (if found) new cert so that
            // ReplacementObjectLink and rotate_interval are always consistent.
            let mut atomic_ops = vec![AtomicOperation::UpdateObject((
                uid.to_owned(),
                owm.object().clone(),
                old_cert_attrs,
                Some(old_cert_tags),
            ))];
            if let Some(op) = new_cert_op {
                atomic_ops.push(op);
            }
            kms.database.atomic(owner, &atomic_ops).await?;

            // 3. Old private/public keys: no ReplacementObjectLink is written.
            // Only the certificate carries the auto-rotate policy; the key pair
            // is renewed as a side-effect and the old keys should not track the
            // new ones via links.

            debug!(
                "certificate {uid} renewed → new cert uid={new_cert_uid} \
                 (generation={new_generation})"
            );
        }

        other => {
            warn!(
                "object {uid} has unsupported type {other:?} for \
                 auto-rotation (KMIP defines rotation only for SymmetricKey, PrivateKey, \
                 PublicKey, and Certificate), skipping"
            );
            return Ok(());
        }
    }

    // Emit OTel counter if metrics are configured
    if let Some(ref metrics) = kms.metrics {
        metrics.increment_auto_rotation_counter(&algorithm);
    }

    Ok(())
}

/// Rotate an RSA / EC / PQC key pair by creating an entirely new key pair with the same
/// algorithm parameters, then atomically:
///
/// 1. Setting `ReplacementObjectLink` on the old private and public keys → new keys.
/// 2. Setting `ReplacedObjectLink` on the new keys → old keys.
/// 3. Clearing `rotate_interval = 0` on BOTH old keys so the cron does not re-trigger.
/// 4. Transferring the rotation policy to the **new private key** so the cycle continues.
async fn rotate_asymmetric_keypair(
    kms: &KMS,
    old_private_uid: &str,
    old_public_uid: Option<&str>,
    owner: &str,
    old_rotate_interval: Option<i32>,
    old_rotate_name: Option<String>,
    old_rotate_offset: Option<i32>,
) -> KResult<()> {
    let Some(old_sk_owm) = kms.database.retrieve_object(old_private_uid).await? else {
        warn!("rotate_asymmetric_keypair: old private key {old_private_uid} not found");
        return Ok(());
    };
    let old_sk_attrs = old_sk_owm.attributes();
    let old_generation = old_sk_attrs.rotate_generation.unwrap_or(0);

    // Resolve the old public key UID so we can fetch its usage mask.
    let resolved_pk_uid_for_mask = old_public_uid.map(str::to_owned).or_else(|| {
        old_sk_attrs
            .get_link(LinkType::PublicKeyLink)
            .map(|l| l.to_string())
    });

    let old_pk_usage_mask = if let Some(ref pk_uid) = resolved_pk_uid_for_mask {
        kms.database
            .retrieve_object(pk_uid)
            .await
            .ok()
            .flatten()
            .and_then(|owm| owm.attributes().cryptographic_usage_mask)
    } else {
        None
    };

    // Build a CreateKeyPair request that copies the algorithm and key-size / curve.
    // Pass usage masks as key-specific attributes because `create_rsa_key_pair` reads
    // them from `private_key_attributes` / `public_key_attributes`, not `common_attributes`.
    // Clone vendor attributes but strip the Cosmian tag entry.
    // Tags are forwarded explicitly via update_object (with system tags filtered)
    // so passing them here would cause check_user_tags to reject system tags
    // like `_sk` / `_pk` that the old key carries.
    let vendor_attrs_for_new = old_sk_attrs.vendor_attributes.as_ref().map(|vas| {
        vas.iter()
            .filter(|va| {
                !(va.vendor_identification == VENDOR_ID_COSMIAN
                    && va.attribute_name == VENDOR_ATTR_TAG)
            })
            .cloned()
            .collect::<Vec<_>>()
    });

    let new_common_attrs = Attributes {
        cryptographic_algorithm: old_sk_attrs.cryptographic_algorithm,
        cryptographic_length: old_sk_attrs.cryptographic_length,
        cryptographic_domain_parameters: old_sk_attrs.cryptographic_domain_parameters,
        cryptographic_parameters: old_sk_attrs.cryptographic_parameters.clone(),
        rotate_generation: Some(old_generation + 1),
        // Preserve custom vendor metadata (non-tag entries only; tags are set
        // explicitly below via update_object with system tags stripped).
        vendor_attributes: vendor_attrs_for_new,
        ..Attributes::default()
    };
    let new_private_key_attrs = old_sk_attrs
        .cryptographic_usage_mask
        .map(|mask| Attributes {
            cryptographic_usage_mask: Some(mask),
            ..Attributes::default()
        });
    let new_public_key_attrs = old_pk_usage_mask.map(|mask| Attributes {
        cryptographic_usage_mask: Some(mask),
        ..Attributes::default()
    });
    let create_request = CreateKeyPair {
        common_attributes: Some(new_common_attrs),
        private_key_attributes: new_private_key_attrs,
        public_key_attributes: new_public_key_attrs,
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
    };
    // `privileged_users = None` skips the permission check; we act on behalf of the owner.
    let resp = Box::pin(create_key_pair(kms, create_request, owner, None)).await?;
    let new_private_uid = resp.private_key_unique_identifier.to_string();
    let new_public_uid = resp.public_key_unique_identifier.to_string();
    debug!(
        "asymmetric key pair {old_private_uid} rotated → new private={new_private_uid} \
         public={new_public_uid}"
    );

    let now = OffsetDateTime::now_utc();

    // ── Prepare atomic operations ──────────────────────────────────────────────
    // 1. Old private key: add ReplacementObjectLink, clear rotate_interval.
    let old_sk_tags = kms.database.retrieve_tags(old_private_uid).await?;
    // Keep a copy so the new private key inherits the same user-defined tags.
    // Filter out system-reserved tags (those starting with '_') — only user-defined
    // labels should be forwarded; system tags are re-assigned automatically.
    let old_sk_tags_for_new: std::collections::HashSet<String> = old_sk_tags
        .iter()
        .filter(|t| !t.starts_with('_'))
        .cloned()
        .collect();
    let mut old_sk_attrs_mut = old_sk_owm.attributes().clone();
    old_sk_attrs_mut.set_link(
        LinkType::ReplacementObjectLink,
        LinkedObjectIdentifier::TextString(new_private_uid.clone()),
    );
    old_sk_attrs_mut.rotate_interval = Some(0);
    old_sk_attrs_mut.rotate_latest = Some(false);

    let mut atomic_ops = vec![AtomicOperation::UpdateObject((
        old_private_uid.to_owned(),
        old_sk_owm.object().clone(),
        old_sk_attrs_mut,
        Some(old_sk_tags),
    ))];

    // 2. Old public key (if known): add ReplacementObjectLink, clear rotate_interval.
    // Reuse the resolved UID computed earlier (when we fetched the usage mask).
    let resolved_old_public_uid = resolved_pk_uid_for_mask;

    let mut old_pk_tags_for_new = std::collections::HashSet::new();
    if let Some(ref old_pk_uid) = resolved_old_public_uid {
        if let Some(old_pk_owm) = kms.database.retrieve_object(old_pk_uid).await? {
            let old_pk_tags = kms.database.retrieve_tags(old_pk_uid).await?;
            // Keep a copy so the new public key inherits the same user-defined tags.
            // Filter out system-reserved tags (those starting with '_') — only user-defined
            // labels should be forwarded; system tags are re-assigned automatically.
            old_pk_tags_for_new = old_pk_tags
                .iter()
                .filter(|t| !t.starts_with('_'))
                .cloned()
                .collect();
            let mut old_pk_attrs = old_pk_owm.attributes().clone();
            old_pk_attrs.set_link(
                LinkType::ReplacementObjectLink,
                LinkedObjectIdentifier::TextString(new_public_uid.clone()),
            );
            old_pk_attrs.rotate_interval = Some(0);
            old_pk_attrs.rotate_latest = Some(false);
            atomic_ops.push(AtomicOperation::UpdateObject((
                old_pk_uid.clone(),
                old_pk_owm.object().clone(),
                old_pk_attrs,
                Some(old_pk_tags),
            )));
        }
    }

    // 3. New private key: add ReplacedObjectLink and transfer rotation policy.
    //    Activate immediately — the key replaces an Active key.
    if let Some(new_sk_owm) = kms.database.retrieve_object(&new_private_uid).await? {
        let mut new_sk_attrs = new_sk_owm.attributes().clone();
        new_sk_attrs.set_link(
            LinkType::ReplacedObjectLink,
            LinkedObjectIdentifier::TextString(old_private_uid.to_owned()),
        );
        new_sk_attrs.rotate_interval = old_rotate_interval;
        new_sk_attrs.rotate_name.clone_from(&old_rotate_name);
        new_sk_attrs.rotate_offset = old_rotate_offset;
        new_sk_attrs.initial_date = Some(now);
        new_sk_attrs.rotate_latest = Some(true);
        new_sk_attrs.state = Some(State::Active);
        new_sk_attrs.activation_date = Some(now);
        // Inherit old private key's user-defined tags so the new key is findable
        // under the same labels.
        atomic_ops.push(AtomicOperation::UpdateObject((
            new_private_uid.clone(),
            new_sk_owm.object().clone(),
            new_sk_attrs,
            Some(old_sk_tags_for_new),
        )));
    }

    // 4. New public key: add ReplacedObjectLink (no rotation policy on public keys).
    //    Activate immediately — the key replaces an Active key.
    if let Some(ref old_pk_uid) = resolved_old_public_uid {
        if let Some(new_pk_owm) = kms.database.retrieve_object(&new_public_uid).await? {
            let mut new_pk_attrs = new_pk_owm.attributes().clone();
            new_pk_attrs.set_link(
                LinkType::ReplacedObjectLink,
                LinkedObjectIdentifier::TextString(old_pk_uid.clone()),
            );
            new_pk_attrs.rotate_latest = Some(true);
            new_pk_attrs.state = Some(State::Active);
            new_pk_attrs.activation_date = Some(now);
            // Inherit old public key's user-defined tags so the new key is findable
            // under the same labels.
            atomic_ops.push(AtomicOperation::UpdateObject((
                new_public_uid.clone(),
                new_pk_owm.object().clone(),
                new_pk_attrs,
                Some(old_pk_tags_for_new),
            )));
        }
    }

    kms.database.atomic(owner, &atomic_ops).await?;
    Ok(())
}

/// Find all objects due for rotation and rotate them.
///
/// Called periodically by the scheduler (see `crate::cron`).
/// Uses [`Database::find_due_for_rotation`] to find candidates, then calls
/// [`auto_rotate_key`] for each one.
pub(crate) async fn run_auto_rotation(kms: &KMS) {
    let now = OffsetDateTime::now_utc();

    let due_uids = match kms.database.find_due_for_rotation(now).await {
        Ok(uids) => uids,
        Err(e) => {
            warn!("auto-rotation: failed to query due keys: {e}");
            return;
        }
    };

    if due_uids.is_empty() {
        return;
    }

    debug!(
        "auto-rotation: {} object(s) due for rotation",
        due_uids.len()
    );

    for uid in &due_uids {
        // Retrieve the owner and object type before rotation for notification purposes
        let (owner, object_type_str, algorithm) = match kms.database.retrieve_object(uid).await {
            Ok(Some(owm)) => {
                let owner = owm.owner().to_owned();
                let object_type_str = format!("{:?}", owm.object().object_type());
                let algorithm = owm
                    .attributes()
                    .cryptographic_algorithm
                    .map_or_else(|| "Unknown".to_owned(), |a| a.to_string());
                (owner, object_type_str, algorithm)
            }
            Ok(None) => {
                warn!("auto-rotation: object {uid} not found, skipping");
                continue;
            }
            Err(e) => {
                warn!("auto-rotation: failed to retrieve object {uid}: {e}, skipping");
                continue;
            }
        };

        match Box::pin(auto_rotate_key(kms, uid, &owner)).await {
            Ok(()) => {
                if !kms.renewal_strategy.all_silent() && kms.renewal_strategy.notify_on_success {
                    let msg = format!(
                        "Object '{uid}' ({object_type_str}, algorithm: {algorithm}) was \
                         automatically rotated."
                    );
                    if let Err(e) = kms
                        .database
                        .create_notification(&owner, "rotation_success", &msg, Some(uid), now)
                        .await
                    {
                        warn!("auto-rotation: failed to create notification for {uid}: {e}");
                    }
                    if let Some(ref notifier) = kms.email_notifier {
                        // Retrieve the actual rotation generation. After rekey the old key carries
                        // a ReplacementObjectLink → new key. The new key has rotate_generation set.
                        // For in-place rekey (CoverCrypt), the same UID is updated directly.
                        let generation = async {
                            use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::LinkType;
                            let old_owm = kms.database.retrieve_object(uid).await.ok().flatten()?;
                            // Follow replacement link to the new key if present
                            if let Some(new_id) =
                                old_owm.attributes().get_link(LinkType::ReplacementObjectLink)
                            {
                                let new_owm = kms
                                    .database
                                    .retrieve_object(&new_id.to_string())
                                    .await
                                    .ok()
                                    .flatten()?;
                                new_owm.attributes().rotate_generation
                            } else {
                                // In-place rekey (CoverCrypt): generation is on the same object
                                old_owm.attributes().rotate_generation
                            }
                        }
                        .await
                        .unwrap_or(0);
                        notifier
                            .send_rotation_success(
                                uid,
                                &object_type_str,
                                &owner,
                                &algorithm,
                                generation,
                                now,
                            )
                            .await;
                    }
                }
            }
            Err(e) => {
                warn!("auto-rotation: failed to rotate object {uid}: {e}");
                if !kms.renewal_strategy.all_silent() && kms.renewal_strategy.notify_on_failure {
                    let msg =
                        format!("Auto-rotation of object '{uid}' ({object_type_str}) failed: {e}");
                    if let Err(ne) = kms
                        .database
                        .create_notification(&owner, "rotation_failure", &msg, Some(uid), now)
                        .await
                    {
                        warn!(
                            "auto-rotation: failed to create failure notification for {uid}: {ne}"
                        );
                    }
                    if let Some(ref notifier) = kms.email_notifier {
                        notifier
                            .send_rotation_failure(uid, &owner, &e.to_string())
                            .await;
                    }
                }
            }
        }
    }
}

/// Check all objects approaching their scheduled renewal date and emit warning notifications.
///
/// For each configured warning threshold (e.g. 30, 7, 1 days), objects whose renewal
/// date falls within that window receive exactly one warning notification (tracked via
/// the `rotate_last_warning_days` attribute to prevent duplicate sends).
pub(crate) async fn dispatch_renewal_warnings(kms: &KMS) {
    if !kms.renewal_strategy.warnings_enabled() {
        return;
    }

    let thresholds = kms.renewal_strategy.sorted_thresholds();
    if thresholds.is_empty() {
        return;
    }

    let now = OffsetDateTime::now_utc();
    // Find all objects that would be due within the largest threshold window.
    let max_days = *thresholds.first().unwrap_or(&30);
    let future_now = now + time::Duration::seconds(i64::from(max_days) * 86_400);

    let candidates = match kms.database.find_due_for_rotation(future_now).await {
        Ok(uids) => uids,
        Err(e) => {
            warn!("renewal-warnings: failed to query candidates: {e}");
            return;
        }
    };

    for uid in &candidates {
        let Ok(Some(owm)) = kms.database.retrieve_object(uid).await else {
            continue;
        };

        let attrs = owm.attributes();

        // Skip objects already due for rotation (the auto-rotation cron will handle them)
        let Some(interval) = attrs.rotate_interval.filter(|&i| i > 0) else {
            continue;
        };

        // Compute days_until_renewal
        let next_rotation = {
            if let Some(last_rotate) = attrs.rotate_date {
                last_rotate + time::Duration::seconds(i64::from(interval))
            } else if let Some(initial) = attrs.initial_date {
                let offset = attrs.rotate_offset.map_or(0, i64::from);
                initial + time::Duration::seconds(i64::from(interval) + offset)
            } else {
                continue;
            }
        };

        if next_rotation <= now {
            // Already due, auto-rotation will handle
            continue;
        }

        let secs_until = (next_rotation - now).whole_seconds().max(0);
        let days_until = u32::try_from(secs_until / 86_400).unwrap_or(u32::MAX);

        // Find the matching threshold (largest threshold that days_until is still within)
        let matching_threshold = thresholds.iter().find(|&&t| days_until <= t);
        let Some(&threshold) = matching_threshold else {
            continue;
        };

        // Check if we already sent a warning for this threshold in the current cycle
        let last_warned = attrs.rotate_last_warning_days.unwrap_or(0);
        if last_warned >= i32::try_from(threshold).unwrap_or(i32::MAX) {
            continue;
        }

        let owner = owm.owner().to_owned();
        let object_type_str = format!("{:?}", owm.object().object_type());
        let interval_days = interval / 86_400;

        let msg = format!(
            "Object '{uid}' ({object_type_str}) is scheduled for renewal in \
             approximately {days_until} day(s) (rotation interval: {interval_days} days)."
        );

        if let Err(e) = kms
            .database
            .create_notification(&owner, "renewal_warning", &msg, Some(uid), now)
            .await
        {
            warn!("renewal-warnings: failed to create notification for {uid}: {e}");
            continue;
        }

        if let Some(ref notifier) = kms.email_notifier {
            notifier
                .send_renewal_warning(uid, &object_type_str, &owner, days_until, interval_days)
                .await;
        }

        // Record that we've sent a warning for this threshold so it's not re-sent.
        let mut new_attrs = attrs.clone();
        new_attrs.rotate_last_warning_days = Some(i32::try_from(threshold).unwrap_or(i32::MAX));
        let tags = kms.database.retrieve_tags(uid).await.unwrap_or_default();
        if let Err(e) = kms
            .database
            .update_object(uid, owm.object(), &new_attrs, Some(&tags))
            .await
        {
            warn!("renewal-warnings: failed to update rotate_last_warning_days for {uid}: {e}");
        }
    }
}
