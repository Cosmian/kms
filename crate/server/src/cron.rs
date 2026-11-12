use std::{collections::HashMap, future::Future, sync::Arc};

use cosmian_logger::{debug, info, warn};
use tokio::sync::oneshot;

use crate::core::{
    KMS,
    operations::{dispatch_renewal_warnings, run_auto_rotation},
};

const CLUSTER_HEARTBEAT_INTERVAL_SECS: u64 = 5;
pub(crate) const CLUSTER_NODE_TIMEOUT_SECS: i64 = 15;

async fn run_with_cluster_lock<F, Fut>(kms: &Arc<KMS>, lock_name: &str, action: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    match kms.database.with_cron_lock(lock_name, action).await {
        Ok(true) => {}
        Ok(false) => debug!("[{lock_name}] Skipping scheduled work; another node holds the lock"),
        Err(e) => warn!("[{lock_name}] Failed to acquire or release cluster lock: {e}"),
    }
}

/// Publish this node's heartbeat and periodically elect a node for cluster-wide work.
pub fn spawn_cluster_heartbeat_cron(kms: Arc<KMS>) -> oneshot::Sender<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                warn!("[cluster-heartbeat] Failed to build runtime: {e}");
                return;
            }
        };

        rt.block_on(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                CLUSTER_HEARTBEAT_INTERVAL_SECS,
            ));
            let mut shutdown_rx = shutdown_rx;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        update_cluster_heartbeat(&kms).await;
                    }
                    _ = &mut shutdown_rx => {
                        debug!("[cluster-heartbeat] Shutdown signal received; stopping");
                        break;
                    }
                }
            }
        });
    });

    shutdown_tx
}

async fn update_cluster_heartbeat(kms: &Arc<KMS>) {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let stale_before = now.saturating_sub(CLUSTER_NODE_TIMEOUT_SECS);
    let node_id = &kms.node_id;
    let version = env!("CARGO_PKG_VERSION");
    let existing_nodes = match kms.database.list_cluster_nodes(stale_before).await {
        Ok(nodes) => nodes,
        Err(e) => {
            warn!("[cluster-heartbeat] Failed to list nodes before heartbeat: {e}");
            return;
        }
    };
    let is_leader = existing_nodes
        .iter()
        .any(|node| node.node_id == node_id.as_str() && node.is_leader);

    if let Err(e) = kms
        .database
        .record_cluster_heartbeat(node_id, version, now, is_leader, stale_before)
        .await
    {
        warn!("[cluster-heartbeat] Failed to persist node heartbeat: {e}");
        return;
    }

    if !is_leader
        && let Err(e) = kms
            .database
            .with_cron_lock("cluster-heartbeat-leader", || async {
                match kms.database.list_cluster_nodes(stale_before).await {
                    Ok(nodes) if nodes.iter().any(|node| node.is_leader) => {}
                    Ok(_) => {
                        if let Err(e) = kms
                            .database
                            .record_cluster_heartbeat(node_id, version, now, true, stale_before)
                            .await
                        {
                            warn!("[cluster-heartbeat] Failed to publish leader status: {e}");
                        }
                    }
                    Err(e) => {
                        warn!("[cluster-heartbeat] Failed to list nodes during election: {e}");
                    }
                }
            })
            .await
    {
        warn!("[cluster-heartbeat] Leader election failed: {e}");
    }

    match kms.database.list_cluster_nodes(stale_before).await {
        Ok(nodes) => {
            if let Some(metrics) = &kms.metrics {
                metrics.update_cluster_nodes_count(i64::try_from(nodes.len()).unwrap_or(i64::MAX));
            }
        }
        Err(e) => warn!("[cluster-heartbeat] Failed to list live nodes: {e}"),
    }
}

/// Spawn a background thread that periodically runs the key auto-rotation check.
/// The thread runs independently of the metrics cron and is spawned whenever
/// `auto_rotation_check_interval_secs > 0` in the server configuration.
///
/// Returns a `oneshot::Sender<()>` that cleanly stops the thread when sent.
pub fn spawn_auto_rotation_cron(kms: Arc<KMS>) -> oneshot::Sender<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let interval_secs = kms.params.auto_rotation_check_interval_secs;

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                debug!("[auto-rotate-cron] Failed to build runtime: {}", e);
                return;
            }
        };

        rt.block_on(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            let mut warned: HashMap<String, i64> = HashMap::new();
            let mut shutdown_rx = shutdown_rx;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        debug!("[auto-rotate-cron] Running scheduled key auto-rotation check");
                        run_with_cluster_lock(&kms, "auto-rotation", || async {
                            run_auto_rotation(&kms).await;
                            dispatch_renewal_warnings(&kms, &mut warned).await;
                        }).await;
                    }
                    _ = &mut shutdown_rx => {
                        debug!("[auto-rotate-cron] Shutdown signal received; stopping cron thread");
                        break;
                    }
                }
            }
        });
    });

    shutdown_tx
}

/// Spawn a background thread that periodically refreshes CRLs near their expiry.
///
/// The scheduler wakes up every `crl_refresh_check_hours` hours (from
/// [`ServerParams`]) and regenerates any stored CRL whose `nextUpdate`
/// timestamp is within `crl_refresh_overlap_hours` of the current time.
///
/// This prevents relying parties from seeing an expired CRL during the
/// window between expiry and the next revocation-triggered regeneration —
/// analogous to EJBCA's "CRL Overlap Time" and AWS PCA's 1-day overlap.
///
/// Returns a `oneshot::Sender<()>` that cleanly stops the thread when sent.
/// The scheduler is not spawned when `crl_refresh_check_hours == 0`.
pub fn spawn_crl_refresh_cron(kms: Arc<KMS>) -> oneshot::Sender<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let check_hours = u64::from(kms.params.crl_refresh_check_hours);
    let overlap_hours = i64::from(kms.params.crl_refresh_overlap_hours);

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                warn!("[crl-refresh-cron] Failed to build runtime: {e}");
                return;
            }
        };

        rt.block_on(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                check_hours.saturating_mul(3600),
            ));
            let mut shutdown_rx = shutdown_rx;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        debug!("[crl-refresh-cron] Running scheduled CRL refresh check");
                        run_with_cluster_lock(&kms, "crl-refresh", || async {
                            refresh_expiring_crls(&kms, overlap_hours).await;
                        }).await;
                    }
                    _ = &mut shutdown_rx => {
                        debug!("[crl-refresh-cron] Shutdown signal received; stopping");
                        break;
                    }
                }
            }
        });
    });

    shutdown_tx
}

/// Scan all stored CRLs and regenerate those expiring within `overlap_hours`.
async fn refresh_expiring_crls(kms: &Arc<KMS>, overlap_hours: i64) {
    // Enumerate all issuer IDs stored in the `crls` table.
    let issuers = match kms.database.list_crl_issuers().await {
        Ok(ids) => ids,
        Err(e) => {
            warn!("[crl-refresh-cron] Failed to list CRL issuers from DB: {e}");
            return;
        }
    };

    let now = time::OffsetDateTime::now_utc();
    let threshold = now + time::Duration::hours(overlap_hours);

    for (issuer_id, next_update_str) in issuers {
        let needs_refresh = time::OffsetDateTime::parse(
            &next_update_str,
            &time::format_description::well_known::Rfc3339,
        )
        .map_or(true, |next_update| next_update <= threshold); // stale if unparsable

        if !needs_refresh {
            continue;
        }

        info!(
            issuer_id = issuer_id.as_str(),
            "[crl-refresh-cron] Regenerating CRL for issuer '{issuer_id}' \
             (expires within {overlap_hours}h)"
        );

        // Server-triggered: `default_username` usually has no grant on the CA key.
        if let Err(e) = Box::pin(crate::core::operations::generate_crl::regenerate_crl(
            kms, &issuer_id,
        ))
        .await
        {
            warn!(
                issuer_id = issuer_id.as_str(),
                "[crl-refresh-cron] CRL refresh failed for '{issuer_id}': {e}"
            );
        }
    }
}
/// Spawns the metrics cron thread: refreshes the uptime gauge every second,
/// reconciles backend object counters every 5 minutes, and re-syncs the
/// `kms.keys.active.count` and `kms.objects.total` gauges every
/// `metrics_count_interval_secs`. The COUNT refresh is skipped entirely when
/// `metrics_count_interval_secs == 0`.
///
/// Returns a oneshot Sender that, when sent, cleanly stops the cron thread.
///
/// # Errors
/// This function does not return errors; if the cron runtime cannot be built,
/// it logs the failure and no thread is spawned.
pub fn spawn_metrics_cron(kms: Arc<KMS>) -> oneshot::Sender<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let count_interval_secs = kms.params.metrics_count_interval_secs;

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
            // `tokio::time::interval` panics on a zero period; the arm is disabled when 0.
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(count_interval_secs.max(1)));
            let mut uptime_interval = tokio::time::interval(std::time::Duration::from_secs(1));
            let mut reconcile_interval = tokio::time::interval(std::time::Duration::from_secs(300));
            let mut shutdown_rx = shutdown_rx;
            loop {
                tokio::select! {
                    _ = interval.tick(), if count_interval_secs > 0 => {
                        // Not cluster-locked: the gauges live in this process's OTel exporter.
                        if let Some(ref metrics) = kms.metrics {
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
                                        warn!(
                                            "[metrics-cron] Failed to sync kms.keys.active.count: {}",
                                            e
                                        );
                                    }
                                }

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
                        run_with_cluster_lock(&kms, "metrics-reconcile", || async {
                            if let Err(e) = kms.database.reconcile_all_object_counts().await {
                                debug!("[metrics-cron] reconcile_all_object_counts failed: {}", e);
                            }
                        }).await;
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
