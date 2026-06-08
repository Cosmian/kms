//! Remote policy bundle polling.
//!
//! When `rbac_bundle_url` is configured, this module periodically downloads
//! the policy archive, unpacks it to a local cache directory, validates it,
//! and reloads the evaluator. On sustained unavailability, the cached bundle
//! is used with a warning (silent staleness — operator monitors via logs).

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use cosmian_logger::{info, warn};

use super::{
    bundle_manager::{compute_bundle_hash, load_bundle_from_directory, validate_bundle},
    evaluator::PolicyEvaluator,
};

/// Spawn a periodic polling task that fetches the remote bundle.
///
/// # Arguments
/// * `bundle_url` — URL to fetch the policy archive from.
/// * `cache_dir` — Local directory to cache/unpack the downloaded bundle.
/// * `poll_interval_secs` — Seconds between polling attempts.
/// * `evaluator` — The policy evaluator to reload on successful fetch.
/// * `allowlists_json` — Serialized allowlists data for the engine.
pub fn spawn_remote_poller(
    bundle_url: String,
    cache_dir: PathBuf,
    poll_interval_secs: u64,
    evaluator: Arc<PolicyEvaluator>,
    allowlists_json: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_poller(
            &bundle_url,
            &cache_dir,
            poll_interval_secs,
            &evaluator,
            &allowlists_json,
        )
        .await;
    })
}

/// Internal polling loop.
async fn run_poller(
    bundle_url: &str,
    cache_dir: &Path,
    poll_interval_secs: u64,
    evaluator: &PolicyEvaluator,
    allowlists_json: &str,
) {
    let interval = Duration::from_secs(poll_interval_secs);

    info!("RBAC remote bundle poller started (url={bundle_url}, interval={poll_interval_secs}s)");

    loop {
        tokio::time::sleep(interval).await;

        match fetch_and_reload(bundle_url, cache_dir, evaluator, allowlists_json).await {
            Ok(Some(hash)) => {
                info!("RBAC remote bundle updated successfully (hash: {hash})");
            }
            Ok(None) => {
                // Hash unchanged — no reload needed
            }
            Err(e) => {
                warn!("RBAC remote bundle poll failed (keeping cached policy): {e}");
            }
        }
    }
}

/// Fetch the remote bundle, unpack to cache, validate, and reload.
///
/// Returns `Ok(Some(hash))` if a new bundle was loaded, `Ok(None)` if unchanged,
/// or `Err` if the fetch/validation failed.
async fn fetch_and_reload(
    bundle_url: &str,
    cache_dir: &Path,
    evaluator: &PolicyEvaluator,
    allowlists_json: &str,
) -> Result<Option<String>, String> {
    // Download the bundle archive
    let response = reqwest::get(bundle_url)
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("Remote returned HTTP {}", response.status()));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response body: {e}"))?;

    // Ensure cache directory exists
    fs::create_dir_all(cache_dir)
        .map_err(|e| format!("Failed to create cache dir {}: {e}", cache_dir.display()))?;

    // Unpack: for simplicity, treat the response as a tar.gz or as raw .rego files.
    // If it's a single .rego file, write directly. If tar.gz, unpack.
    // For this implementation, we support a simple directory-of-files approach:
    // the remote serves a JSON manifest or we write the body as authz.rego.
    unpack_bundle(&bytes, cache_dir)?;

    // Load from the cache directory (same as local bundle loading)
    let metadata = load_bundle_from_directory(cache_dir).map_err(|e| e.to_string())?;
    validate_bundle(&metadata.files).map_err(|e| e.to_string())?;

    let new_hash = compute_bundle_hash(&metadata.files);

    // Skip if hash unchanged
    if new_hash == evaluator.bundle_hash() {
        return Ok(None);
    }

    evaluator
        .reload(&metadata.files, allowlists_json, new_hash.clone())
        .map_err(|e| e.to_string())?;

    Ok(Some(new_hash))
}

/// Unpack bundle bytes into the cache directory.
///
/// The remote server should serve the bundle as a single `.rego` file (written as `authz.rego`)
/// or as a JSON object mapping filenames to content:
/// ```json
/// {"authz.rego": "package kms.authz\n...", "helpers.rego": "package kms.helpers\n..."}
/// ```
fn unpack_bundle(bytes: &[u8], cache_dir: &Path) -> Result<(), String> {
    let content = std::str::from_utf8(bytes)
        .map_err(|e| format!("Bundle content is not valid UTF-8: {e}"))?;

    // Try parsing as JSON manifest (multi-file bundle)
    if let Ok(manifest) = serde_json::from_str::<std::collections::HashMap<String, String>>(content)
    {
        // Clear existing .rego files before writing new ones
        if let Ok(entries) = fs::read_dir(cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("rego"))
                {
                    drop(fs::remove_file(&path));
                }
            }
        }

        for (filename, file_content) in &manifest {
            if Path::new(filename)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("rego"))
            {
                let dest = cache_dir.join(filename);
                fs::write(&dest, file_content)
                    .map_err(|e| format!("Failed to write {filename}: {e}"))?;
            }
        }
    } else {
        // Treat as raw .rego content (single-file bundle)
        let dest = cache_dir.join("authz.rego");
        fs::write(&dest, content)
            .map_err(|e| format!("Failed to write bundle to {}: {e}", dest.display()))?;
    }

    Ok(())
}
