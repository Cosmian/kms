use std::sync::Arc;

use cosmian_logger::debug;
use tokio::sync::oneshot;

use crate::core::KMS;

/// Spawn a background thread that periodically refreshes metrics.
/// Returns a oneshot Sender that, when sent, cleanly stops the cron thread.
///
/// # Errors
/// This function does not return errors; if the cron runtime cannot be built,
/// it logs the failure and no thread is spawned.
pub fn spawn_metrics_cron(kms: Arc<KMS>) -> oneshot::Sender<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    std::thread::spawn(move || {
        // Dedicated single-thread Tokio runtime for the cron loop
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                debug!("[metrics-cron] Failed to build runtime: {}", e);
                return; // Do not panic: skip spawning the cron loop
            }
        };

        rt.block_on(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            let mut uptime_interval = tokio::time::interval(std::time::Duration::from_secs(1));
            let mut reconcile_interval = tokio::time::interval(std::time::Duration::from_secs(300));
            let mut shutdown_rx = shutdown_rx;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Some(ref metrics) = kms.metrics {
                            // ── Non-destroyed key objects count ────────────────────────────────
                            // Privileged backend count: no ACL filtering, covers all backends.
                            match kms.database.count_non_destroyed_key_objects().await {
                                Ok(count) => {
                                    debug!(
                                        "[metrics-cron] kms.keys.active.count synced to {}",
                                        count
                                    );
                                    metrics.update_active_keys_count(
                                        i64::try_from(count).unwrap_or(i64::MAX),
                                    );
                                }
                                Err(e) => {
                                    debug!(
                                        "[metrics-cron] Failed to sync kms.keys.active.count: {}",
                                        e
                                    );
                                }
                            }

                            // ── Objects-total absolute sync ────────────────────────────────────
                            match kms.database.count_all_non_destroyed_objects().await {
                                Ok(count) => {
                                    debug!(
                                        "[metrics-cron] kms.objects.total synced to {}",
                                        count
                                    );
                                    metrics.update_objects_total(
                                        i64::try_from(count).unwrap_or(i64::MAX),
                                    );
                                }
                                Err(e) => {
                                    debug!(
                                        "[metrics-cron] Failed to sync kms.objects.total: {}",
                                        e
                                    );
                                }
                            }
                        }
                    }
                    _ = reconcile_interval.tick() => {
                        // Authoritative reconcile of Redis O(1) counters (no-op for SQL).
                        // Prevents permanent counter drift from partial failures.
                        if let Err(e) = kms.database.reconcile_all_object_counts().await {
                            debug!("[metrics-cron] reconcile_all_object_counts failed: {}", e);
                        }
                    }
                    _ = uptime_interval.tick() => {
                        if let Some(ref metrics) = kms.metrics {
                            metrics.update_uptime();
                        }
                    }
                    _ = &mut shutdown_rx => {
                        debug!("[metrics-cron] Shutdown signal received; stopping cron thread");
                        break;
                    }
                }
            }
        });
    });

    shutdown_tx
}
