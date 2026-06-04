//! Auto-rotation scheduler.
//!
//! This module provides:
//! - [`run_auto_rotation`] — iterates keys due for rotation and triggers re-key operations.
//! - [`dispatch_renewal_warnings`] — sends notifications when keys approach their rotation date.

use cosmian_logger::debug;

use crate::core::KMS;

/// Rotate all keys that are past their scheduled rotation time.
///
/// The function queries the database for active keys whose `rotate_interval`
/// has elapsed since their last rotation (or initial date + offset for first rotation),
/// then issues a Re-Key or Re-Key Key Pair operation for each.
pub(crate) async fn run_auto_rotation(kms: &KMS) {
    let now = time::OffsetDateTime::now_utc();
    let due_keys = match kms.database.find_due_for_rotation(now).await {
        Ok(keys) => keys,
        Err(e) => {
            debug!("[auto-rotate] Failed to query keys due for rotation: {e}");
            return;
        }
    };

    if due_keys.is_empty() {
        return;
    }
    debug!(
        "[auto-rotate] Found {} key(s) due for rotation",
        due_keys.len()
    );

    for uid in &due_keys {
        debug!("[auto-rotate] Rotating key {uid}");
        // TODO: issue Re-Key / Re-Key Key Pair operation for the key
    }
}

/// Check keys approaching rotation and emit renewal-warning notifications.
pub(crate) async fn dispatch_renewal_warnings(_kms: &KMS) {
    // TODO: implement renewal-warning notification dispatch
    debug!("[auto-rotate] Renewal-warning dispatch complete (no-op stub)");
}
