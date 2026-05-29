use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{kmip_attributes::Attributes, kmip_operations::Locate},
};
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
            let mut shutdown_rx = shutdown_rx;
            loop {
                // TODO: this should better be deleted/updated because we are changing the approach
                tokio::select! {
                    _ = interval.tick() => {
                        // ── Active-keys refresh (via KMIP Locate) ─────────────────────────
                        // NOTE: this uses a KMIP Locate filtered to Active state, which is
                        // subject to the caller's ACL.  In multi-admin deployments this may
                        // undercount if the cron user does not own all keys.  A future task
                        // should replace this with a privileged SQL count, similar to the
                        // objects.total path below.
                        let request = Locate {
                            attributes: Attributes {
                                state: Some(State::Active),
                                ..Default::default()
                            },
                            ..Default::default()
                        };
                        let user = kms.params.hsm_instances.first()
                            .and_then(|inst| inst.admin.iter().find(|a| a.as_str() != "*").cloned())
                            .unwrap_or_else(|| kms.params.default_username.clone());
                        match kms.locate(request, &user,).await {
                            Ok(resp) => {
                                let count = resp.located_items.unwrap_or(0);
                                debug!("[metrics-cron] Active keys count refreshed to {}", count);
                                if let Some(ref metrics) = kms.metrics {
                                    metrics.update_active_keys_count(i64::from(count));
                                }
                            }
                            Err(e) => {
                                debug!("[metrics-cron] Failed to refresh active keys count: {}", e);
                            }
                        }

                        // ── Objects-total absolute sync ────────────────────────────────────
                        // The fast-path delta tracking (+1/-1 per operation) can accumulate
                        // drift over time because of the TOCTOU race in the Upsert pre-read
                        // and because the Redis backend always emits 0 from the fast path.
                        // Every 30 s we re-read the authoritative SQL count and correct the
                        // UpDownCounter via the mirror pattern (see OtelMetrics::update_objects_total).
                        if let Some(ref metrics) = kms.metrics {
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
