//! Hot-reload watcher for local policy bundles.
//!
//! Uses the `notify` crate to watch the bundle directory for file changes.
//! On change: reloads all `.rego` files, validates, computes new hash,
//! and atomically swaps the evaluator's policy source via `PolicyEvaluator::reload()`.
//! Invalid bundles are rejected with a warning — the old policy remains active.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use cosmian_logger::{error, info, warn};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher, event::ModifyKind};
use tokio::sync::mpsc;

use super::{
    bundle_manager::{compute_bundle_hash, load_bundle_from_directory, validate_bundle},
    evaluator::PolicyEvaluator,
};

/// Debounce interval to avoid reloading multiple times for rapid file changes.
const DEBOUNCE_MS: u64 = 500;

/// Spawn a file watcher task that monitors the bundle directory and reloads
/// the policy evaluator when `.rego` files change.
///
/// Returns a `JoinHandle` for the watcher task. The task runs until the
/// server shuts down (it holds an `Arc` to the evaluator).
///
/// # Arguments
/// * `bundle_path` — Directory containing `.rego` files to watch.
/// * `evaluator` — The policy evaluator to reload on changes.
/// * `allowlists_json` — Serialized allowlists data to pass to the new engine.
pub fn spawn_bundle_watcher(
    bundle_path: PathBuf,
    evaluator: Arc<PolicyEvaluator>,
    allowlists_json: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run_watcher(&bundle_path, &evaluator, &allowlists_json).await {
            error!("RBAC bundle watcher failed: {e}");
        }
    })
}

/// Internal watcher loop.
async fn run_watcher(
    bundle_path: &Path,
    evaluator: &PolicyEvaluator,
    allowlists_json: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (tx, mut rx) = mpsc::channel(16);

    // Create the filesystem watcher
    let mut watcher = RecommendedWatcher::new(
        move |result: Result<Event, notify::Error>| {
            if let Ok(event) = result {
                // Only trigger on file modifications and creations
                let dominated_by_rego = event
                    .paths
                    .iter()
                    .any(|p| p.extension().is_some_and(|ext| ext == "rego"));
                let is_relevant = dominated_by_rego
                    && matches!(
                        event.kind,
                        notify::EventKind::Modify(ModifyKind::Data(_))
                            | notify::EventKind::Create(_)
                            | notify::EventKind::Remove(_)
                    );
                if is_relevant {
                    let _ = tx.blocking_send(());
                }
            }
        },
        notify::Config::default(),
    )?;

    watcher.watch(bundle_path, RecursiveMode::NonRecursive)?;
    info!("RBAC bundle watcher started on: {}", bundle_path.display());

    // Debounced reload loop
    loop {
        // Wait for a change notification
        if rx.recv().await.is_none() {
            break; // Channel closed, shutdown
        }

        // Debounce: drain any additional events within the window
        tokio::time::sleep(Duration::from_millis(DEBOUNCE_MS)).await;
        while rx.try_recv().is_ok() {}

        // Attempt reload
        info!("RBAC bundle change detected, reloading...");
        match reload_bundle(bundle_path, evaluator, allowlists_json) {
            Ok(hash) => {
                info!("RBAC bundle reloaded successfully (hash: {hash})");
            }
            Err(e) => {
                warn!("RBAC bundle reload failed (keeping old policy): {e}");
            }
        }
    }

    Ok(())
}

/// Load, validate, and reload the bundle into the evaluator.
fn reload_bundle(
    bundle_path: &Path,
    evaluator: &PolicyEvaluator,
    allowlists_json: &str,
) -> Result<String, String> {
    let metadata = load_bundle_from_directory(bundle_path).map_err(|e| e.to_string())?;
    validate_bundle(&metadata.files).map_err(|e| e.to_string())?;

    let new_hash = compute_bundle_hash(&metadata.files);

    // Skip reload if hash hasn't changed (e.g., editor save without modifications)
    if new_hash == evaluator.bundle_hash() {
        return Ok(new_hash);
    }

    evaluator
        .reload(&metadata.files, allowlists_json, new_hash.clone())
        .map_err(|e| e.to_string())?;

    Ok(new_hash)
}
