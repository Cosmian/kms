//! Auto-rotation scheduler.
//!
//! This module provides:
//! - [`run_auto_rotation`] — iterates keys due for rotation and triggers re-key operations.
//! - [`dispatch_renewal_warnings`] — sends notifications when keys approach their rotation date.

use std::collections::HashMap;

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_objects::ObjectType,
    kmip_operations::{ReCertify, ReKey, ReKeyKeyPair},
    kmip_types::UniqueIdentifier,
};
use cosmian_logger::{debug, info, warn};

use crate::{
    core::{
        KMS,
        operations::{
            recertify::recertify,
            rekey::{rekey, rekey_keypair},
        },
        uid_utils::ObjectHandle,
    },
    middlewares::UserId,
    result::KResult,
};

/// Threshold days at which renewal warnings are emitted before the next scheduled rotation.
///
/// Ordered ascending so that `.find(|&&t| days <= t)` returns the most specific (smallest)
/// matching threshold — e.g. a key due in 5 days matches threshold 7, not 30.
const WARNING_THRESHOLDS_DAYS: [i64; 3] = [1, 7, 30];

/// Rotate all keys that are past their scheduled rotation time.
///
/// Queries the database for Active keys whose `rotate_interval` has elapsed
/// since their last rotation (or `initial_date + rotate_offset` for first rotation),
/// then issues a `ReKey` or `ReKeyKeyPair` on behalf of the key owner.
///
/// Each key is rotated independently: a failure on one key never blocks the others.
/// HSM-resident keys (UID prefix `hsm::`) are skipped — the KMS cannot generate
/// key material inside an HSM.
///
/// # Metrics
///
/// Increments the `kms.key.auto_rotation` `OTel` counter on each attempt, labeled
/// with `uid`, `algorithm`, and `outcome` (`"success"` / `"failure"`).
pub(crate) async fn run_auto_rotation(kms: &KMS) {
    let now = time::OffsetDateTime::now_utc();
    let due_keys = match kms.database.find_due_for_rotation(now).await {
        Ok(keys) => keys,
        Err(e) => {
            warn!("[auto-rotate] Failed to query keys due for rotation: {e}");
            return;
        }
    };

    if due_keys.is_empty() {
        debug!("[auto-rotate] No keys due for rotation at {now}");
        return;
    }
    info!(
        "[auto-rotate] Found {} key(s) due for rotation",
        due_keys.len()
    );

    for (uid, owner) in &due_keys {
        if let Err(e) = Box::pin(rotate_one_key(
            kms,
            ObjectHandle::from(uid),
            &UserId::from(owner.as_str()),
        ))
        .await
        {
            // Logged inside rotate_one_key; the outer loop continues.
            debug!("[auto-rotate] rotate_one_key returned: {e}");
        }
    }
}

/// Attempt to rotate a single key, returning `Ok(())` on success.
///
/// After a successful rotation the replacement key inherits the original key's
/// rotation policy (`rotate_automatic = true`, `rotate_interval = old_interval`)
/// so that auto-rotation continues indefinitely — matching the behaviour of
/// AWS KMS, Azure Key Vault, and GCP Cloud KMS.
///
/// Errors are also logged as `warn!` here so the caller loop can continue.
async fn rotate_one_key(kms: &KMS, handle: ObjectHandle<'_>, owner: &UserId) -> KResult<()> {
    let uid = handle.as_str();
    // HSM keys: the KMS cannot generate new key material inside an HSM
    if handle.is_hsm() {
        debug!("[auto-rotate] Skipping HSM key {uid}");
        return Ok(());
    }

    // Retrieve the object to determine its type, algorithm, and rotation policy.
    // We capture `old_interval` here so the replacement can be re-armed after rotation.
    let owm = match kms.database.retrieve_object(uid).await {
        Ok(Some(owm)) => owm,
        Ok(None) => {
            warn!("[auto-rotate] Key {uid} not found; skipping");
            return Ok(());
        }
        Err(e) => {
            warn!("[auto-rotate] Failed to retrieve key {uid}: {e}; skipping");
            return Ok(());
        }
    };

    let object_type = owm.object().object_type();
    let algorithm = owm
        .attributes()
        .cryptographic_algorithm
        .map_or_else(|| "unknown".to_owned(), |a| format!("{a:?}"));

    // Capture the rotation policy before dispatching so we can re-arm the replacement.
    let old_interval = owm.attributes().rotate_interval.filter(|&i| i > 0);

    // Dispatch to the appropriate KMIP rotation operation and return the new key's UID.
    let new_uid_result: KResult<String> = match object_type {
        ObjectType::SymmetricKey => {
            let request = ReKey {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                offset: None,
                attributes: None,
                protection_storage_masks: None,
            };
            Box::pin(rekey(kms, request, owner))
                .await
                .map(|r| r.unique_identifier.to_string())
        }
        ObjectType::PrivateKey => {
            let request = ReKeyKeyPair {
                private_key_unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                ..ReKeyKeyPair::default()
            };
            Box::pin(rekey_keypair(kms, request, owner))
                .await
                .map(|r| r.private_key_unique_identifier.to_string())
        }
        ObjectType::Certificate => {
            let request = ReCertify {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                offset: None,
                attributes: None,
                certificate_request_type: None,
                certificate_request_value: None,
                protection_storage_masks: None,
            };
            Box::pin(recertify(kms, request, owner))
                .await
                .map(|r| r.unique_identifier.to_string())
        }
        // Public keys are rotated atomically as a side-effect of rotating the paired
        // PrivateKey via `rekey_keypair`. Schedule auto-rotation on the PrivateKey instead.
        ObjectType::PublicKey => {
            debug!(
                "[auto-rotate] Skipping {uid}: PublicKey is rotated as part of its paired \
                 PrivateKey rotation"
            );
            return Ok(());
        }
        other => {
            debug!(
                "[auto-rotate] Skipping {uid}: object type {other:?} has no auto-rotation support"
            );
            return Ok(());
        }
    };

    match &new_uid_result {
        Ok(new_uid) => {
            info!("[auto-rotate] Key {uid} (owner={owner}, algo={algorithm}) rotated successfully");
            if let Some(ref m) = kms.metrics {
                m.record_key_auto_rotation(uid, &algorithm, "success");
            }
            // Re-arm the replacement key with the original rotation policy so that
            // auto-rotation continues indefinitely without operator intervention.
            // `set_rotation_metadata_from` zeroes `rotate_interval` to prevent
            // accidental double-rotation on manual rekeys; the scheduler is
            // responsible for re-arming its own replacements.
            if let Some(interval) = old_interval {
                if let Err(e) =
                    rearm_rotation_policy(kms, ObjectHandle::from(new_uid), interval).await
                {
                    warn!(
                        "[auto-rotate] Failed to re-arm rotation policy on replacement {new_uid}: {e}"
                    );
                }
            }
        }
        Err(e) => {
            warn!("[auto-rotate] Failed to rotate key {uid} (owner={owner}): {e}");
            if let Some(ref m) = kms.metrics {
                m.record_key_auto_rotation(uid, &algorithm, "failure");
            }
        }
    }

    new_uid_result.map(|_| ())
}

/// Re-arm the rotation policy on a replacement key after a successful auto-rotation.
///
/// `set_rotation_metadata_from` intentionally zeroes `rotate_interval` on manual rekeys so
/// the user must opt back in. For auto-rotation, the scheduler re-arms the replacement here,
/// preserving perpetual rotation — matching AWS KMS, Azure Key Vault, and GCP Cloud KMS.
async fn rearm_rotation_policy(kms: &KMS, handle: ObjectHandle<'_>, interval: i64) -> KResult<()> {
    let new_uid = handle.as_str();
    let owm = match kms.database.retrieve_object(new_uid).await {
        Ok(Some(owm)) => owm,
        Ok(None) => {
            return Err(crate::error::KmsError::ServerError(format!(
                "Replacement key {new_uid} not found; cannot re-arm rotation policy"
            )));
        }
        Err(e) => {
            return Err(crate::error::KmsError::ServerError(format!(
                "Failed to retrieve replacement key {new_uid}: {e}"
            )));
        }
    };

    let mut new_attrs = owm.attributes().clone();
    new_attrs.rotate_automatic = Some(true);
    new_attrs.rotate_interval = Some(interval);

    kms.database
        .update_object(new_uid, owm.object(), &new_attrs, None)
        .await
        .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))
}

/// Check keys approaching rotation and emit renewal-warning log events.
///
/// For each Active key whose next rotation falls within the next
/// [`WARNING_THRESHOLDS_DAYS`] days, an `info!` event is emitted at the
/// most urgent matching threshold and an `OTel` counter is incremented.
///
/// Deduplication is handled by the caller-supplied `warned` map, which persists
/// across cron ticks (owned by `spawn_auto_rotation_cron`).  An entry
/// `uid → threshold` is inserted after each warning; if the same uid already
/// maps to the same threshold the warning is skipped.  When a key is rotated its
/// old UID is deactivated and disappears from future query results, so stale
/// entries never cause problems.  On server restart the map is empty; at most one
/// extra warning fires per key per restart, which is harmless.
///
/// Full notification delivery (SMTP, webhook) is wired in a follow-up PR.
pub(crate) async fn dispatch_renewal_warnings(kms: &KMS, warned: &mut HashMap<String, i64>) {
    let now = time::OffsetDateTime::now_utc();
    let max_horizon = WARNING_THRESHOLDS_DAYS.iter().copied().max().unwrap_or(30);
    let horizon = now + time::Duration::days(max_horizon);

    // Reuse the existing query with a future horizon to find all keys due within the window
    let approaching = match kms.database.find_due_for_rotation(horizon).await {
        Ok(keys) => keys,
        Err(e) => {
            debug!("[auto-rotate] Failed to query keys for renewal warnings: {e}");
            return;
        }
    };

    for (uid, owner) in &approaching {
        // HSM keys are excluded from auto-rotation, skip warnings too
        if ObjectHandle::from(uid).is_hsm() {
            continue;
        }

        let Ok(Some(owm)) = kms.database.retrieve_object(uid).await else {
            continue;
        };

        let attrs = owm.attributes();
        let Some(days) = days_until_next_rotation(attrs, now) else {
            continue;
        };

        // Already past deadline → run_auto_rotation handles it; nothing to warn.
        // Same-day keys (days == 0, i.e. less than one full day remaining) are still
        // valid warning targets at the 1-day threshold.
        if days < 0 {
            continue;
        }

        // Find the most urgent matching threshold
        let Some(&threshold) = WARNING_THRESHOLDS_DAYS.iter().find(|&&t| days <= t) else {
            continue;
        };

        // Deduplication: skip if this (uid, threshold) pair was already warned in this
        // process run. The `warned` map is owned by the cron scheduler and survives
        // across ticks, preventing log flooding when the interval is short.
        if warned.get(uid.as_str()).copied() == Some(threshold) {
            continue;
        }

        let algorithm = attrs
            .cryptographic_algorithm
            .map_or_else(|| "unknown".to_owned(), |a| format!("{a:?}"));

        info!(
            "[auto-rotate] Key {uid} (owner={owner}) rotation due in {days} day(s) \
             (warning threshold: {threshold} days)"
        );

        if let Some(ref m) = kms.metrics {
            m.record_rotation_warning(uid, &algorithm, threshold);
        }

        warned.insert(uid.clone(), threshold);
    }
}

/// Compute the number of whole days until the next scheduled rotation for a key.
///
/// Returns `None` if the rotation schedule cannot be determined (no interval, no anchor date).
/// Returns a negative number if the deadline has already passed.
fn days_until_next_rotation(
    attrs: &cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attributes,
    now: time::OffsetDateTime,
) -> Option<i64> {
    let interval_secs = attrs.rotate_interval.filter(|&s| s > 0)?;
    let interval = time::Duration::seconds(interval_secs);

    let next_rotation = if let Some(last_rotate) = attrs.rotate_date {
        last_rotate + interval
    } else {
        let initial = attrs.initial_date?;
        let offset = time::Duration::seconds(attrs.rotate_offset.unwrap_or(0));
        initial + offset + interval
    };

    Some((next_rotation - now).whole_days())
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::panic_in_result_fn)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_attributes::{Attribute, Attributes},
            kmip_operations::SetAttribute,
            kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
            requests::create_symmetric_key_kmip_object,
        },
    };
    use openssl::rand::rand_bytes;

    use super::days_until_next_rotation;
    use crate::{
        config::ServerParams,
        core::{
            KMS,
            operations::{
                auto_rotate::{dispatch_renewal_warnings, run_auto_rotation},
                set_attribute,
            },
        },
        middlewares::UserId,
        result::KResult,
        tests::test_utils::https_clap_config,
    };

    // ── Helper ────────────────────────────────────────────────────────────────

    async fn test_kms() -> KResult<Arc<KMS>> {
        crate::openssl_providers::init_openssl_providers_for_tests();
        let cfg = https_clap_config();
        Ok(Arc::new(
            KMS::instantiate(Arc::new(ServerParams::try_from(cfg)?)).await?,
        ))
    }

    fn make_aes256_key()
    -> cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::Object {
        let mut bytes = [0_u8; 32];
        #[expect(clippy::unwrap_used)]
        rand_bytes(&mut bytes).unwrap();
        #[expect(clippy::unwrap_used)]
        create_symmetric_key_kmip_object(
            "x-vendor",
            &bytes,
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Default::default()
            },
        )
        .unwrap()
    }

    // ── Unit tests for days_until_next_rotation() ─────────────────────────────

    fn now() -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }

    /// Key with `initial_date` 3 days ago, `rotate_interval` = 1 day → 2 days past deadline.
    #[test]
    fn test_overdue_key_initial_date() {
        let now = now();
        let attrs = Attributes {
            rotate_interval: Some(86_400), // 1 day
            initial_date: Some(now - time::Duration::days(3)),
            ..Default::default()
        };
        let days = days_until_next_rotation(&attrs, now).expect("should have a schedule");
        assert!(days < 0, "expected negative (overdue), got {days}");
    }

    /// Key with `initial_date` 30 min ago, `rotate_interval` = 1 h → 0 days remaining (same day).
    #[test]
    fn test_upcoming_key_same_day() {
        let now = now();
        let attrs = Attributes {
            rotate_interval: Some(3600),
            initial_date: Some(now - time::Duration::minutes(30)),
            ..Default::default()
        };
        let days = days_until_next_rotation(&attrs, now).expect("should have a schedule");
        assert_eq!(days, 0, "30 min remaining → 0 whole days, got {days}");
    }

    /// Key with `initial_date` 1 week ago, `rotate_interval` = 10 days → 3 days remaining.
    #[test]
    fn test_key_not_yet_due() {
        let now = now();
        let attrs = Attributes {
            rotate_interval: Some(10 * 86_400), // 10 days
            initial_date: Some(now - time::Duration::days(7)),
            ..Default::default()
        };
        let days = days_until_next_rotation(&attrs, now).expect("should have a schedule");
        assert_eq!(days, 3, "10 - 7 = 3 days remaining, got {days}");
    }

    /// Key rotated 3 days ago with a 7-day interval → 4 days remaining.
    #[test]
    fn test_key_uses_rotate_date_when_set() {
        let now = now();
        let attrs = Attributes {
            rotate_interval: Some(7 * 86_400), // 7 days
            rotate_date: Some(now - time::Duration::days(3)),
            initial_date: Some(now - time::Duration::days(30)), // ignored when rotate_date is set
            ..Default::default()
        };
        let days = days_until_next_rotation(&attrs, now).expect("should have a schedule");
        assert_eq!(
            days, 4,
            "rotate_date 3 days ago + 7-day interval → 4 remaining, got {days}"
        );
    }

    /// Key with `rotate_offset` shifts the first deadline.
    #[test]
    fn test_rotate_offset_applied() {
        let now = now();
        let attrs = Attributes {
            rotate_interval: Some(10 * 86_400),                // 10 days
            rotate_offset: Some(5 * 86_400),                   // 5-day delay before first rotation
            initial_date: Some(now - time::Duration::days(6)), // 6 days ago
            ..Default::default()
        };
        // next = initial + offset + interval = -6 + 5 + 10 = +9 days from now
        let days = days_until_next_rotation(&attrs, now).expect("should have a schedule");
        assert_eq!(days, 9, "offset applied: 9 days remaining, got {days}");
    }

    /// Key with no `rotate_interval` → `None` (no rotation schedule).
    #[test]
    fn test_no_interval_returns_none() {
        let now = now();
        let attrs = Attributes {
            rotate_interval: None,
            initial_date: Some(now - time::Duration::hours(2)),
            ..Default::default()
        };
        assert!(
            days_until_next_rotation(&attrs, now).is_none(),
            "missing interval should return None"
        );
    }

    /// Key with `rotate_interval = 0` → `None` (disabled).
    #[test]
    fn test_zero_interval_returns_none() {
        let now = now();
        let attrs = Attributes {
            rotate_interval: Some(0),
            initial_date: Some(now - time::Duration::hours(2)),
            ..Default::default()
        };
        assert!(
            days_until_next_rotation(&attrs, now).is_none(),
            "zero interval should return None"
        );
    }

    /// Key with no anchor dates → `None`.
    #[test]
    fn test_no_anchor_dates_returns_none() {
        let now = now();
        let attrs = Attributes {
            rotate_interval: Some(3600),
            initial_date: None,
            rotate_date: None,
            ..Default::default()
        };
        assert!(
            days_until_next_rotation(&attrs, now).is_none(),
            "no anchor dates should return None"
        );
    }

    // ── Integration: run_auto_rotation dispatches ReKey for due symmetric key ─

    /// Verify that `run_auto_rotation` issues a `ReKey` for a symmetric key whose
    /// rotation deadline has already passed:
    /// - The original key must end up `Deactivated` (KMIP §4.57 transition 6).
    /// - A new key linked via `ReplacedObjectLink` must exist in the database.
    #[tokio::test]
    async fn test_auto_rotation_rotates_due_symmetric_key() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from("auto_rotate_test_owner@example.com");
        let now = time::OffsetDateTime::now_utc();

        // Create a key that is 2 h past its 1-h rotation deadline
        let uid = uuid::Uuid::new_v4().to_string();
        let key_object = make_aes256_key();
        let key_attrs = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            state: Some(State::Active),
            rotate_automatic: Some(true),
            rotate_interval: Some(3600),
            initial_date: Some(now - time::Duration::hours(2)),
            ..Default::default()
        };
        kms.database
            .create(
                Some(uid.clone()),
                &owner,
                &key_object,
                &key_attrs,
                &HashSet::new(),
            )
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;

        // Trigger auto-rotation
        run_auto_rotation(&kms).await;

        // Original key must be Deactivated
        let owm = kms
            .database
            .retrieve_object(&uid)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("original key must still exist after rotation");
        assert_eq!(
            owm.state(),
            State::Deactivated,
            "original key must be Deactivated after auto-rotation"
        );

        // A replacement key must be linked via ReplacedObjectLink
        let replacement_linked = owm
            .attributes()
            .link
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|lnk| {
                lnk.link_type
                    == cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::LinkType::ReplacementObjectLink
            });
        assert!(
            replacement_linked,
            "original key must have a ReplacementObjectLink to the new key"
        );

        Ok(())
    }

    /// Verify that `run_auto_rotation` skips HSM-resident keys (uid prefix `hsm::`).
    #[tokio::test]
    async fn test_auto_rotation_skips_hsm_keys() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from("auto_rotate_hsm_test@example.com");
        let now = time::OffsetDateTime::now_utc();

        // Store a key with an HSM-style UID (bypasses database-level HSM routing
        // because no real HSM is configured; we just verify the scheduler skips it)
        let hsm_uid = format!("hsm::softhsm2::0::{}", uuid::Uuid::new_v4());
        let key_object = make_aes256_key();
        let key_attrs = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            state: Some(State::Active),
            rotate_automatic: Some(true),
            rotate_interval: Some(3600),
            initial_date: Some(now - time::Duration::hours(2)),
            ..Default::default()
        };

        // Create in the SQL store directly (the Database will route to the
        // default SQL backend since the HSM routes are not configured in tests)
        if kms
            .database
            .create(
                Some(hsm_uid.clone()),
                &owner,
                &key_object,
                &key_attrs,
                &HashSet::new(),
            )
            .await
            .is_ok()
        {
            // If the key was created, verify run_auto_rotation does NOT rotate it
            run_auto_rotation(&kms).await;

            let owm = kms
                .database
                .retrieve_object(&hsm_uid)
                .await
                .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
                .expect("HSM key must still exist");
            // State must remain Active (not rotated, not deactivated)
            assert_eq!(
                owm.state(),
                State::Active,
                "HSM key must remain Active — scheduler must not rotate it"
            );
        }
        // If create() rejected the HSM uid (routing error), the test trivially passes
        // because there is nothing to be accidentally rotated.

        Ok(())
    }

    /// Verify that a key whose owner only set `RotateInterval` (without `RotateAutomatic`)
    /// is still picked up and rotated by the scheduler.
    ///
    /// Regression test for the bug where `find_due_for_rotation` requires
    /// `rotate_automatic = true`, but `SetAttribute RotateInterval` did not implicitly
    /// set it, causing the cron to silently skip such keys.
    #[tokio::test]
    async fn test_auto_rotation_implicit_enable_via_set_interval() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from("implicit_enable_test@example.com");
        let now = time::OffsetDateTime::now_utc();

        // Create an overdue key — but WITHOUT rotate_automatic, simulating a key
        // that was configured only with interval+offset via SetAttribute.
        let uid = uuid::Uuid::new_v4().to_string();
        let key_object = make_aes256_key();
        let key_attrs = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            state: Some(State::Active),
            rotate_interval: Some(3600),
            initial_date: Some(now - time::Duration::hours(2)), // already overdue
            // rotate_automatic intentionally absent
            ..Default::default()
        };
        kms.database
            .create(
                Some(uid.clone()),
                &owner,
                &key_object,
                &key_attrs,
                &HashSet::new(),
            )
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;

        // Without the fix, the scheduler would never rotate this key.
        // Confirm it is NOT yet in the due-for-rotation result.
        let due_before = kms
            .database
            .find_due_for_rotation(now)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;
        assert!(
            !due_before.iter().any(|(u, _)| u == &uid),
            "key without rotate_automatic must not appear in find_due_for_rotation before SetAttribute"
        );

        // Now simulate what a user would do: call SetAttribute RotateInterval.
        // The fix auto-sets rotate_automatic = true when rotate_automatic is absent.
        set_attribute(
            &kms,
            SetAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
                new_attribute: Attribute::RotateInterval(3600),
            },
            &owner,
        )
        .await?;

        // rotate_automatic must now be true in the stored attributes.
        let owm = kms
            .database
            .retrieve_object(&uid)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("key must exist after SetAttribute");
        assert_eq!(
            owm.attributes().rotate_automatic,
            Some(true),
            "SetAttribute RotateInterval must implicitly set rotate_automatic = true"
        );

        // The key must now appear in find_due_for_rotation.
        let due_after = kms
            .database
            .find_due_for_rotation(now)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;
        assert!(
            due_after.iter().any(|(u, _)| u == &uid),
            "key must appear in find_due_for_rotation after SetAttribute RotateInterval"
        );

        // Finally, the scheduler must rotate it.
        run_auto_rotation(&kms).await;
        let rotated = kms
            .database
            .retrieve_object(&uid)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("key must still exist after rotation");
        assert_eq!(
            rotated.state(),
            State::Deactivated,
            "original key must be Deactivated after scheduler runs"
        );

        Ok(())
    }

    /// Verify that `Certify` sets `initial_date` on the new certificate so that the
    /// auto-rotation scheduler can compute the first rotation deadline without any
    /// manual override.
    ///
    /// Regression test: freshly-created certificates with `rotate_automatic = true`
    /// and `rotate_interval > 0` were silently skipped by the scheduler because
    /// `initial_date` was `None`, causing `days_until_next_rotation` to return `None`.
    #[tokio::test]
    async fn test_certify_sets_initial_date_for_auto_rotation() -> KResult<()> {
        use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
            kmip_operations::Certify,
            kmip_types::{CertificateAttributes, CryptographicDomainParameters, RecommendedCurve},
        };

        let kms = test_kms().await?;
        let owner = UserId::from("initial_date_cert_test@example.com");

        // Create a self-signed EC certificate.
        let certify_req = Certify {
            attributes: Some(Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                    recommended_curve: Some(RecommendedCurve::P256),
                    ..CryptographicDomainParameters::default()
                }),
                certificate_attributes: Some(CertificateAttributes::parse_subject_line(
                    "CN=initial-date-test",
                )?),
                ..Attributes::default()
            }),
            ..Certify::default()
        };
        let cert_id = kms
            .certify(certify_req, &owner)
            .await?
            .unique_identifier
            .to_string();

        let cert_owm = kms
            .database
            .retrieve_object(&cert_id)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("certificate must exist after Certify");

        assert!(
            cert_owm.attributes().initial_date.is_some(),
            "Certify must set initial_date so the scheduler can compute the first rotation deadline"
        );

        // Now enable auto-rotation via SetAttribute RotateInterval
        // (which also auto-sets rotate_automatic = true).
        set_attribute(
            &kms,
            SetAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(cert_id.clone())),
                new_attribute: Attribute::RotateInterval(3600),
            },
            &owner,
        )
        .await?;

        // The cert must appear in find_due_for_rotation at now + 2h
        // because next_rotation = initial_date + 1h < now + 2h.
        let horizon = time::OffsetDateTime::now_utc() + time::Duration::hours(2);
        let due = kms
            .database
            .find_due_for_rotation(horizon)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;
        assert!(
            due.iter().any(|(uid, _)| uid == &cert_id),
            "certificate must appear in find_due_for_rotation once initial_date + interval has elapsed"
        );

        Ok(())
    }

    /// Verify that `Certify` with `rotate_automatic = true` and `rotate_interval` embedded
    /// in the request attributes is enough to make `find_due_for_rotation` pick up the
    /// certificate once the interval has elapsed — without any subsequent `SetAttribute` call.
    ///
    /// This is the ergonomic "one-shot" API for callers who know the rotation policy at
    /// creation time.
    #[tokio::test]
    async fn test_certify_with_rotation_policy_found_by_scheduler() -> KResult<()> {
        use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
            kmip_operations::Certify,
            kmip_types::{CertificateAttributes, CryptographicDomainParameters, RecommendedCurve},
        };

        let kms = test_kms().await?;
        let owner = UserId::from("certify_with_policy_test@example.com");

        // Certify with rotation policy baked in — no separate SetAttribute needed.
        let certify_req = Certify {
            attributes: Some(Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                    recommended_curve: Some(RecommendedCurve::P256),
                    ..CryptographicDomainParameters::default()
                }),
                certificate_attributes: Some(CertificateAttributes::parse_subject_line(
                    "CN=policy-at-creation-test",
                )?),
                rotate_automatic: Some(true),
                rotate_interval: Some(3600), // 1 hour
                ..Attributes::default()
            }),
            ..Certify::default()
        };
        let cert_id = kms
            .certify(certify_req, &owner)
            .await?
            .unique_identifier
            .to_string();

        // The cert must appear in find_due_for_rotation at now + 2h.
        let horizon = time::OffsetDateTime::now_utc() + time::Duration::hours(2);
        let due = kms
            .database
            .find_due_for_rotation(horizon)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;
        assert!(
            due.iter().any(|(uid, _)| uid == &cert_id),
            "certificate with rotation policy embedded in Certify request must appear in \
             find_due_for_rotation once initial_date + interval has elapsed"
        );

        Ok(())
    }

    /// Verify that `run_auto_rotation` issues a `ReCertify` for a self-signed certificate whose
    /// rotation deadline has already passed:
    /// - The original certificate must end up `Deactivated`.
    /// - A new certificate linked via `ReplacementObjectLink` must exist in the database.
    ///
    /// This test exercises the `Certificate` arm added to `rotate_one_key`.
    #[tokio::test]
    async fn test_auto_rotation_rotates_due_certificate() -> KResult<()> {
        use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
            kmip_operations::Certify,
            kmip_types::{
                CertificateAttributes, CryptographicAlgorithm, CryptographicDomainParameters,
                RecommendedCurve,
            },
        };

        let kms = test_kms().await?;
        let owner = UserId::from("auto_rotate_cert_test@example.com");
        let now = time::OffsetDateTime::now_utc();

        // Step 1: Create a self-signed EC certificate via the Certify operation.
        // Certify with no unique_identifier and only certificate_attributes generates
        // a fresh EC keypair and signs a self-signed certificate.
        let certify_req = Certify {
            attributes: Some(Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                    recommended_curve: Some(RecommendedCurve::P256),
                    ..CryptographicDomainParameters::default()
                }),
                certificate_attributes: Some(CertificateAttributes::parse_subject_line(
                    "CN=auto-rotate-test",
                )?),
                ..Attributes::default()
            }),
            ..Certify::default()
        };
        let cert_id = kms
            .certify(certify_req, &owner)
            .await?
            .unique_identifier
            .to_string();

        // The Certify operation creates the new keypair in Active state — no explicit
        // Activate call needed. The signing private key is ready for recertify().
        let cert_owm = kms
            .database
            .retrieve_object(&cert_id)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("certificate must exist after Certify");

        // Step 2: Set rotation attributes on the certificate so it is immediately due.
        let mut cert_attrs = cert_owm.attributes().clone();
        cert_attrs.rotate_automatic = Some(true);
        cert_attrs.rotate_interval = Some(3600); // 1 hour
        cert_attrs.initial_date = Some(now - time::Duration::hours(2)); // 2 h ago → overdue
        kms.database
            .update_object(&cert_id, cert_owm.object(), &cert_attrs, None)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;

        // Diagnostic: verify find_due_for_rotation returns this cert.
        let due = kms
            .database
            .find_due_for_rotation(time::OffsetDateTime::now_utc())
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;
        let found_cert = due.iter().any(|(uid, _)| uid == &cert_id);
        assert!(
            found_cert,
            "certificate {cert_id} must appear in find_due_for_rotation before auto-rotation"
        );

        // Step 4: Trigger auto-rotation.
        run_auto_rotation(&kms).await;

        // Step 5: The original certificate must be Deactivated.
        let updated_owm = kms
            .database
            .retrieve_object(&cert_id)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("original certificate must still exist after rotation");
        assert_eq!(
            updated_owm.state(),
            State::Deactivated,
            "original certificate must be Deactivated after auto-rotation"
        );

        // Step 6: A ReplacementObjectLink must point to the new certificate.
        let has_replacement = updated_owm
            .attributes()
            .link
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|lnk| {
                lnk.link_type == cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::LinkType::ReplacementObjectLink
            });
        assert!(
            has_replacement,
            "original certificate must have a ReplacementObjectLink to the new certificate"
        );

        Ok(())
    }

    /// Verify that after a successful auto-rotation the replacement key is re-armed with the
    /// original rotation policy so that perpetual rotation chains work without operator
    /// intervention — matching the behaviour of AWS KMS, Azure Key Vault, and GCP Cloud KMS.
    #[tokio::test]
    async fn test_auto_rotation_perpetual_chain() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from("perpetual_chain_test@example.com");
        let now = time::OffsetDateTime::now_utc();

        // Create a key that is 2 h past its 1-h rotation deadline.
        let uid = uuid::Uuid::new_v4().to_string();
        let key_object = make_aes256_key();
        let key_attrs = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            state: Some(State::Active),
            rotate_automatic: Some(true),
            rotate_interval: Some(3600), // 1 hour
            initial_date: Some(now - time::Duration::hours(2)),
            ..Default::default()
        };
        kms.database
            .create(
                Some(uid.clone()),
                &owner,
                &key_object,
                &key_attrs,
                &HashSet::new(),
            )
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;

        // First rotation cycle.
        run_auto_rotation(&kms).await;

        // Retrieve the original key and follow ReplacementObjectLink to the new key.
        let old_owm = kms
            .database
            .retrieve_object(&uid)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("original key must exist");
        assert_eq!(
            old_owm.state(),
            State::Deactivated,
            "original key must be Deactivated after first rotation"
        );

        let new_uid = old_owm
            .attributes()
            .link
            .as_deref()
            .unwrap_or_default()
            .iter()
            .find(|lnk| {
                lnk.link_type
                    == cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::LinkType::ReplacementObjectLink
            })
            .map(|lnk| lnk.linked_object_identifier.to_string())
            .expect("original key must have a ReplacementObjectLink");

        // The replacement key MUST have the same rotation policy re-armed.
        let new_owm = kms
            .database
            .retrieve_object(&new_uid)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("replacement key must exist");

        let new_attrs = new_owm.attributes();
        assert_eq!(
            new_attrs.rotate_automatic,
            Some(true),
            "replacement key must have rotate_automatic = true"
        );
        assert_eq!(
            new_attrs.rotate_interval,
            Some(3600),
            "replacement key must inherit the original rotate_interval"
        );

        Ok(())
    }

    /// Verify that `dispatch_renewal_warnings` deduplicates: the same threshold must
    /// only emit once across consecutive cron ticks, and a different (more urgent)
    /// threshold must emit when the deadline draws nearer.
    #[tokio::test]
    async fn test_renewal_warning_deduplication() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from("warning_dedup_test@example.com");
        let now = time::OffsetDateTime::now_utc();

        // Create a key due in 5 days — matches the 7-day threshold.
        let uid = uuid::Uuid::new_v4().to_string();
        let key_object = make_aes256_key();
        let key_attrs = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            state: Some(State::Active),
            rotate_automatic: Some(true),
            rotate_interval: Some(7 * 86_400), // 7 days
            initial_date: Some(now - time::Duration::days(2)), // 2 days ago → due in 5 days
            ..Default::default()
        };
        kms.database
            .create(
                Some(uid.clone()),
                &owner,
                &key_object,
                &key_attrs,
                &HashSet::new(),
            )
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;

        let mut warned = std::collections::HashMap::new();

        // First call: warning must be emitted and recorded in `warned`.
        dispatch_renewal_warnings(&kms, &mut warned).await;
        assert_eq!(
            warned.get(uid.as_str()).copied(),
            Some(7),
            "warned map must record threshold 7 after the first call"
        );

        // Second call at the same threshold: must be deduplicated — `warned` stays unchanged.
        dispatch_renewal_warnings(&kms, &mut warned).await;
        assert_eq!(
            warned.get(uid.as_str()).copied(),
            Some(7),
            "warned map must remain at threshold 7 (dedup suppressed second warning)"
        );

        // Manually advance to within 1 day by updating initial_date.
        let owm = kms
            .database
            .retrieve_object(&uid)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("key must exist");
        let mut attrs_1d = owm.attributes().clone();
        attrs_1d.initial_date = Some(now - time::Duration::days(6)); // due in 1 day
        kms.database
            .update_object(&uid, owm.object(), &attrs_1d, None)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;

        // Third call: a more urgent threshold (1 day) must fire and update `warned`.
        dispatch_renewal_warnings(&kms, &mut warned).await;
        assert_eq!(
            warned.get(uid.as_str()).copied(),
            Some(1),
            "warned map must update to threshold 1 when a more urgent threshold fires"
        );

        Ok(())
    }

    /// Verify that the private key generated by the `Certify` operation (the "generate key pair
    /// and issue a certificate" path) has `initial_date` set so that the auto-rotation scheduler
    /// can compute the first rotation deadline after the user calls `SetAttribute RotateInterval`.
    ///
    /// Regression test: without the fix, `certify_op.rs` stored the generated key pair via
    /// `AtomicOperation::Upsert` without calling `setup_with_lifecycle()`, leaving
    /// `initial_date = None`.  `is_due_for_rotation` then returned `false` immediately because
    /// neither `rotate_date` nor `initial_date` was set, so the scheduler silently skipped the
    /// key forever.
    #[tokio::test]
    async fn test_auto_rotation_keypair_from_certify_flow() -> KResult<()> {
        use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
            kmip_attributes::Attribute,
            kmip_operations::Certify,
            kmip_types::{CertificateAttributes, CryptographicAlgorithm, LinkType},
        };

        let kms = test_kms().await?;
        let owner = UserId::from("certify_keypair_rotation_test@example.com");

        // Create a self-signed RSA certificate via Certify — this also creates a fresh RSA
        // keypair internally (the `Subject::KeypairAndSubjectName` code path).
        let certify_req = Certify {
            attributes: Some(Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: Some(2048),
                certificate_attributes: Some(CertificateAttributes::parse_subject_line(
                    "CN=keypair-rotation-test",
                )?),
                ..Attributes::default()
            }),
            ..Certify::default()
        };
        let cert_id = kms
            .certify(certify_req, &owner)
            .await?
            .unique_identifier
            .to_string();

        // Follow PrivateKeyLink to get the private key UID.
        let cert_owm = kms
            .database
            .retrieve_object(&cert_id)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("certificate must exist after Certify");
        let sk_uid = cert_owm
            .attributes()
            .link
            .as_deref()
            .unwrap_or_default()
            .iter()
            .find(|lnk| lnk.link_type == LinkType::PrivateKeyLink)
            .map(|lnk| lnk.linked_object_identifier.to_string())
            .expect("certificate must have a PrivateKeyLink");

        // Regression: the private key must have `initial_date` set so the scheduler can compute
        // the first rotation deadline without any manual override.
        let sk_owm = kms
            .database
            .retrieve_object(&sk_uid)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("private key must exist after Certify");
        assert!(
            sk_owm.attributes().initial_date.is_some(),
            "Certify must set initial_date on the generated private key so the scheduler can \
             compute the first rotation deadline (regression: setup_with_lifecycle was never \
             called in certify_op.rs)"
        );

        // Set RotateInterval on the private key — this implicitly enables auto-rotation
        // (rotate_automatic = true) and sets rotate_name.
        set_attribute(
            &kms,
            SetAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(sk_uid.clone())),
                new_attribute: Attribute::RotateInterval(3600),
            },
            &owner,
        )
        .await?;

        // Confirm the key appears in find_due_for_rotation at now + 2 h
        // (initial_date ≈ now, interval = 1 h → next rotation ≈ now + 1 h < now + 2 h).
        let horizon = time::OffsetDateTime::now_utc() + time::Duration::hours(2);
        let due = kms
            .database
            .find_due_for_rotation(horizon)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;
        assert!(
            due.iter().any(|(uid, _)| uid == &sk_uid),
            "private key from Certify flow must appear in find_due_for_rotation after \
             SetAttribute RotateInterval"
        );

        // Make the key immediately overdue so run_auto_rotation (which uses now internally)
        // will pick it up.  Backdate initial_date to 2 h ago — the same pattern used by
        // test_auto_rotation_rotates_due_certificate and similar tests.
        let sk_owm2 = kms
            .database
            .retrieve_object(&sk_uid)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("private key must still exist");
        let mut overdue_attrs = sk_owm2.attributes().clone();
        overdue_attrs.initial_date =
            Some(time::OffsetDateTime::now_utc() - time::Duration::hours(2));
        kms.database
            .update_object(&sk_uid, sk_owm2.object(), &overdue_attrs, None)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;

        // Trigger auto-rotation: the scheduler must issue a ReKeyKeyPair.
        run_auto_rotation(&kms).await;

        // The original private key must be Deactivated after rotation.
        let updated_sk = kms
            .database
            .retrieve_object(&sk_uid)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("private key must still exist after auto-rotation");
        assert_eq!(
            updated_sk.state(),
            State::Deactivated,
            "private key from Certify flow must be Deactivated after auto-rotation"
        );

        Ok(())
    }

    /// Verify that a certificate enrolled in a keyset follows the documented `@N` UID scheme
    /// (`cert-id@1`, `cert-id@2`, …) on each successive auto-rotation, matching the symmetric
    /// and key-pair keyset UID scheme.
    #[tokio::test]
    async fn test_recertify_keyset_uid_scheme() -> KResult<()> {
        use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
            kmip_operations::Certify,
            kmip_types::{
                CertificateAttributes, CryptographicDomainParameters, LinkType, RecommendedCurve,
            },
        };

        let kms = test_kms().await?;
        let owner = UserId::from("keyset_cert_uid_test@example.com");
        let now = time::OffsetDateTime::now_utc();

        // Issue a self-signed EC certificate; its auto-assigned UID becomes the keyset name.
        let certify_req = Certify {
            attributes: Some(Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                    recommended_curve: Some(RecommendedCurve::P256),
                    ..CryptographicDomainParameters::default()
                }),
                certificate_attributes: Some(CertificateAttributes::parse_subject_line(
                    "CN=keyset-uid-test",
                )?),
                ..Attributes::default()
            }),
            ..Certify::default()
        };
        let cert_id = kms
            .certify(certify_req, &owner)
            .await?
            .unique_identifier
            .to_string();

        // Enroll the certificate in a keyset and make it immediately overdue.
        let owm = kms
            .database
            .retrieve_object(&cert_id)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("certificate must exist after Certify");
        let mut attrs = owm.attributes().clone();
        attrs.rotate_name = Some(cert_id.clone()); // keyset name = cert UID (gen 0 invariant)
        attrs.rotate_automatic = Some(true);
        attrs.rotate_interval = Some(3600); // 1 hour
        attrs.initial_date = Some(now - time::Duration::hours(2)); // overdue
        kms.database
            .update_object(&cert_id, owm.object(), &attrs, None)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?;

        // First auto-rotation — new UID must be `{cert_id}@1`.
        run_auto_rotation(&kms).await;

        let gen0_owm = kms
            .database
            .retrieve_object(&cert_id)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("gen-0 cert must still exist after rotation");
        assert_eq!(
            gen0_owm.state(),
            State::Deactivated,
            "gen-0 certificate must be Deactivated after auto-rotation"
        );

        let gen1_uid = gen0_owm
            .attributes()
            .link
            .as_deref()
            .unwrap_or_default()
            .iter()
            .find(|lnk| lnk.link_type == LinkType::ReplacementObjectLink)
            .map(|lnk| lnk.linked_object_identifier.to_string())
            .expect("gen-0 cert must have a ReplacementObjectLink");
        assert_eq!(
            gen1_uid,
            format!("{cert_id}@1"),
            "first rotation must produce UID '{cert_id}@1'"
        );

        // Verify gen-1 attributes.
        let gen1_owm = kms
            .database
            .retrieve_object(&gen1_uid)
            .await
            .map_err(|e| crate::error::KmsError::ServerError(e.to_string()))?
            .expect("gen-1 cert must exist");
        let gen1_attrs = gen1_owm.attributes();
        assert_eq!(
            gen1_attrs.rotate_name.as_deref(),
            Some(cert_id.as_str()),
            "gen-1 cert must inherit rotate_name"
        );
        assert_eq!(
            gen1_attrs.rotate_generation,
            Some(1),
            "gen-1 cert must have rotate_generation = 1"
        );

        Ok(())
    }
}
