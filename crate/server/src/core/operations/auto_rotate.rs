//! Auto-rotation scheduler.
//!
//! This module provides:
//! - [`auto_rotate_key`] — rotates a single managed object via the existing KMIP
//!   rekey pipeline (`ReKey`, `ReKeyKeyPair`, `ReCertify`).
//! - [`run_auto_rotation`] — iterates keys due for rotation and triggers re-key operations.
//! - [`dispatch_renewal_warnings`] — placeholder for future notification system.
//!
//! The rotation logic is intentionally thin: it delegates to the same operations
//! used by manual rotation (`rekey`, `rekey_keypair`, `recertify`) and only adds
//! rotation policy transfer to the newly created key.

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{ReCertify, ReKey, ReKeyKeyPair},
        kmip_types::{LinkType, UniqueIdentifier},
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{debug, warn};
use time::OffsetDateTime;

use crate::{
    core::{
        KMS,
        operations::{recertify, rekey, rekey_keypair},
    },
    result::KResult,
};

// ─── Shared helper ──────────────────────────────────────────────────────────

/// Transfer the rotation policy from the old object's attributes to the new key,
/// resetting `initial_date` so the next rotation fires at the correct time.
async fn transfer_rotation_policy(kms: &KMS, old_attrs: &Attributes, new_uid: &str) -> KResult<()> {
    let Some(new_owm) = kms.database.retrieve_object(new_uid).await? else {
        warn!("transfer_rotation_policy: new object {new_uid} not found after rotation");
        return Ok(());
    };
    let mut new_attrs = new_owm.attributes().clone();
    new_attrs.rotate_interval = old_attrs.rotate_interval;
    new_attrs.rotate_name.clone_from(&old_attrs.rotate_name);
    new_attrs.rotate_offset = old_attrs.rotate_offset;
    new_attrs.initial_date = Some(OffsetDateTime::now_utc());
    let new_tags = kms.database.retrieve_tags(new_uid).await?;
    kms.database
        .update_object(new_uid, new_owm.object(), &new_attrs, Some(&new_tags))
        .await?;
    Ok(())
}

/// Clear rotation policy on a paired key (e.g., public key when private was rotated)
/// so the cron does not independently rotate it.
async fn clear_rotation_policy(kms: &KMS, uid: &str) -> KResult<()> {
    let Some(owm) = kms.database.retrieve_object(uid).await? else {
        return Ok(());
    };
    if owm.attributes().rotate_interval.is_some_and(|i| i != 0) {
        let mut attrs = owm.attributes().clone();
        attrs.rotate_interval = Some(0);
        let tags = kms.database.retrieve_tags(uid).await?;
        kms.database
            .update_object(uid, owm.object(), &attrs, Some(&tags))
            .await?;
    }
    Ok(())
}

// ─── Main entry point ───────────────────────────────────────────────────────

/// Rotate a single managed object identified by `uid` on behalf of its owner.
///
/// Dispatches based on object type:
/// - `SymmetricKey` → `ReKey` (KMIP §6.1.46)
/// - `PrivateKey` → `ReKeyKeyPair` (KMIP §6.1.47)
/// - `PublicKey` → follows `PrivateKeyLink` to the private key and rotates the key pair
/// - `Certificate` → `ReCertify` (KMIP §6.1.45)
/// - All other types → skipped with a warning
///
/// After rotation, the rotation policy (interval, name, offset) is transferred
/// to the new key so the next cycle fires correctly.
pub(crate) async fn auto_rotate_key(kms: &KMS, uid: &str, owner: &str) -> KResult<()> {
    let Some(owm) = kms.database.retrieve_object(uid).await? else {
        warn!("auto-rotation: object {uid} not found, skipping");
        return Ok(());
    };

    let object_type = owm.object().object_type();

    // Guard: skip objects whose rotation policy has already been cleared.
    if owm.attributes().rotate_interval.is_none_or(|i| i == 0) {
        debug!("auto-rotation: {uid} has rotate_interval=0 (already rotated or cleared), skipping");
        return Ok(());
    }

    debug!("[auto_rotate_key] rotating {object_type:?} uid={uid}");

    match object_type {
        ObjectType::SymmetricKey => {
            rotate_symmetric_key(kms, uid, owner, &owm).await?;
        }
        ObjectType::PrivateKey => {
            Box::pin(rotate_private_key(kms, uid, owner, &owm)).await?;
        }
        ObjectType::PublicKey => {
            Box::pin(rotate_public_key(kms, uid, owner, &owm)).await?;
        }
        ObjectType::Certificate => {
            rotate_certificate(kms, uid, owner, &owm).await?;
        }
        other => {
            warn!("auto-rotation: object {uid} has unsupported type {other:?}, skipping");
        }
    }

    Ok(())
}

// ─── Type-specific rotation functions ───────────────────────────────────────

/// Symmetric key rotation via `ReKey`.
async fn rotate_symmetric_key(
    kms: &KMS,
    uid: &str,
    owner: &str,
    owm: &ObjectWithMetadata,
) -> KResult<()> {
    let old_attrs = owm.attributes().clone();

    let request = ReKey {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        ..ReKey::default()
    };
    let response = Box::pin(rekey(kms, request, owner)).await?;
    let new_uid = response.unique_identifier.to_string();
    debug!("auto-rotation: symmetric key {uid} → {new_uid}");

    transfer_rotation_policy(kms, &old_attrs, &new_uid).await
}

/// Private key rotation via `ReKeyKeyPair`.
///
/// Works for all algorithms: RSA, EC, PQC, and `CoverCrypt`. The `rekey_keypair`
/// operation handles algorithm-specific logic internally (e.g., `CoverCrypt`
/// performs in-place attribute rekey while RSA/EC/PQC creates a new key pair).
async fn rotate_private_key(
    kms: &KMS,
    uid: &str,
    owner: &str,
    owm: &ObjectWithMetadata,
) -> KResult<()> {
    let old_attrs = owm.attributes().clone();

    let request = ReKeyKeyPair {
        private_key_unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        ..ReKeyKeyPair::default()
    };
    let response = Box::pin(rekey_keypair(kms, request, owner)).await?;
    let new_sk_uid = response.private_key_unique_identifier.to_string();
    debug!("auto-rotation: private key {uid} → {new_sk_uid}");

    // Transfer rotation policy to the new (or same, for CoverCrypt) private key.
    transfer_rotation_policy(kms, &old_attrs, &new_sk_uid).await?;

    // Clear rotation policy on the paired public key so it is not independently rotated.
    if let Some(pk_link) = owm.attributes().get_link(LinkType::PublicKeyLink) {
        clear_rotation_policy(kms, &pk_link.to_string()).await?;
    }

    Ok(())
}

/// Public key rotation: follows `PrivateKeyLink` and rotates the key pair.
async fn rotate_public_key(
    kms: &KMS,
    uid: &str,
    owner: &str,
    owm: &ObjectWithMetadata,
) -> KResult<()> {
    let Some(private_key_id) = owm.attributes().get_link(LinkType::PrivateKeyLink) else {
        warn!(
            "auto-rotation: public key {uid} has no PrivateKeyLink, \
             clearing rotation policy"
        );
        clear_rotation_policy(kms, uid).await?;
        return Ok(());
    };
    let private_key_uid = private_key_id.to_string();

    // Retrieve private key to capture its attributes for policy transfer.
    let Some(private_owm) = kms.database.retrieve_object(&private_key_uid).await? else {
        warn!(
            "auto-rotation: public key {uid}: private key {private_key_uid} not found, \
             clearing rotation policy"
        );
        clear_rotation_policy(kms, uid).await?;
        return Ok(());
    };

    // Use the public key's rotation policy (since it was the one that triggered).
    let old_attrs = owm.attributes().clone();

    let request = ReKeyKeyPair {
        private_key_unique_identifier: Some(UniqueIdentifier::TextString(private_key_uid.clone())),
        ..ReKeyKeyPair::default()
    };
    let response = Box::pin(rekey_keypair(kms, request, owner)).await?;
    let new_sk_uid = response.private_key_unique_identifier.to_string();
    debug!("auto-rotation: public key {uid} triggered keypair rotation → new SK {new_sk_uid}");

    // Transfer rotation policy to the new private key.
    transfer_rotation_policy(kms, &old_attrs, &new_sk_uid).await?;

    // Clear rotation policy on the old public key (it was the trigger, now superseded).
    clear_rotation_policy(kms, uid).await?;

    // Suppress unused variable warning when non-fips feature is not active.
    let _ = &private_owm;

    Ok(())
}

/// Certificate rotation via `ReCertify`.
async fn rotate_certificate(
    kms: &KMS,
    uid: &str,
    owner: &str,
    owm: &ObjectWithMetadata,
) -> KResult<()> {
    let old_attrs = owm.attributes().clone();

    let request = ReCertify {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        ..ReCertify::default()
    };
    let response = Box::pin(recertify(kms, request, owner)).await?;
    let new_cert_uid = response.unique_identifier.to_string();
    debug!("auto-rotation: certificate {uid} → {new_cert_uid}");

    transfer_rotation_policy(kms, &old_attrs, &new_cert_uid).await
}

// ─── Scheduler entry points ─────────────────────────────────────────────────

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
        let owner = match kms.database.retrieve_object(uid).await {
            Ok(Some(owm)) => owm.owner().to_owned(),
            Ok(None) => {
                warn!("auto-rotation: object {uid} not found, skipping");
                continue;
            }
            Err(e) => {
                warn!("auto-rotation: failed to retrieve object {uid}: {e}, skipping");
                continue;
            }
        };

        if let Err(e) = Box::pin(auto_rotate_key(kms, uid, &owner)).await {
            warn!("auto-rotation: failed to rotate object {uid}: {e}");
        }
    }
}

/// Dispatch renewal warnings to keys that are approaching their rotation date.
///
/// Placeholder for future notification functionality. Currently a no-op.
pub(crate) async fn dispatch_renewal_warnings(_kms: &KMS) {
    // TODO: implement warning dispatch when notification infrastructure is ready
}
