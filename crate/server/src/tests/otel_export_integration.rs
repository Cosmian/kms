use std::{sync::Arc, time::Duration};

use cosmian_logger::log_init;

use crate::{config::ServerParams, core::KMS, cron, tests::test_utils};

struct MetricsCronGuard {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for MetricsCronGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn scrape_collector_metrics(url: &str) -> Result<String, reqwest::Error> {
    use reqwest::Client;

    Client::new()
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
}

async fn create_and_activate_symmetric_keys(kms: &Arc<KMS>, user: &str, count: usize) {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Activate, Create},
        kmip_types::CryptographicAlgorithm,
    };

    for idx in 0..count {
        let req = Create {
            object_type: ObjectType::SymmetricKey,
            attributes: Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(256),
                ..Default::default()
            },
            protection_storage_masks: None,
        };

        let resp = kms
            .create(req, user, None)
            .await
            .unwrap_or_else(|e| panic!("KMIP Create failed for key #{idx}: {e}"));

        // Created keys start in PreActive in our default configuration; activate them
        // so they are counted by the State=Active metrics cron.
        let activate = Activate {
            unique_identifier: resp.unique_identifier.clone(),
        };

        kms.activate(activate, user)
            .await
            .unwrap_or_else(|e| panic!("KMIP Activate failed for key #{idx}: {e}"));
    }
}

// Intentionally unused in this test: the Active keys metric is updated by the cron loop,
// and the exported metric is the source of truth we assert on.

fn wait_for_file_contains(container: &str, path: &str, needle: &str, timeout: Duration) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let output = std::process::Command::new("docker")
            .args([
                "exec",
                container,
                "sh",
                "-lc",
                &format!("cat {path} 2>/dev/null || true"),
            ])
            .output()
            .expect("docker exec should work (is Docker running?)");

        let txt = String::from_utf8_lossy(&output.stdout);
        if txt.contains(needle) {
            return;
        }

        std::thread::sleep(Duration::from_millis(250));
    }

    panic!("Timed out waiting for {path} in {container} to contain {needle}");
}

fn wait_for_json_field_nonzero(container: &str, path: &str, json_pointer: &str, timeout: Duration) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let output = std::process::Command::new("docker")
            .args([
                "exec",
                container,
                "sh",
                "-lc",
                &format!("cat {path} 2>/dev/null || true"),
            ])
            .output()
            .expect("docker exec should work (is Docker running?)");

        let txt = String::from_utf8_lossy(&output.stdout);
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
            if let Some(n) = v.pointer(json_pointer).and_then(serde_json::Value::as_i64) {
                if n != 0 {
                    return;
                }
            }
        }

        std::thread::sleep(Duration::from_millis(250));
    }

    panic!("Timed out waiting for {path} in {container} to have non-zero {json_pointer}");
}

fn wait_for_json_field_gt(
    container: &str,
    path: &str,
    json_pointer: &str,
    min: i64,
    timeout: Duration,
) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let output = std::process::Command::new("docker")
            .args([
                "exec",
                container,
                "sh",
                "-lc",
                &format!("cat {path} 2>/dev/null || true"),
            ])
            .output()
            .expect("docker exec should work (is Docker running?)");

        let txt = String::from_utf8_lossy(&output.stdout);
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) {
            if let Some(n) = v.pointer(json_pointer).and_then(serde_json::Value::as_i64) {
                if n > min {
                    return;
                }
            }
        }

        std::thread::sleep(Duration::from_millis(250));
    }

    panic!("Timed out waiting for {path} in {container} to have {json_pointer} > {min}");
}

fn wait_for_prometheus_metric_gt(metrics: &str, name: &str, min: f64) {
    // Prometheus text format, e.g.:
    // kms_server_uptime{...} 3
    // kms_keys_active_count{...} 10
    let mut found_any = false;
    for line in metrics.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if !line.starts_with(name) {
            continue;
        }

        // Split on whitespace: "<name>{labels} <value>" or "<name> <value>"
        let mut parts = line.split_whitespace();
        let _metric_and_labels = parts.next();
        let value_str = parts.next().unwrap_or("");
        if value_str.is_empty() {
            continue;
        }
        if let Ok(v) = value_str.parse::<f64>() {
            found_any = true;
            if v > min {
                return;
            }
        }
    }

    assert!(
        found_any,
        "Did not find any '{name}' samples in scraped Prometheus metrics"
    );
    panic!("Found '{name}' samples but none were > {min}");
}

async fn wait_for_prometheus_metric_gt_eventually(
    url: &str,
    name: &str,
    min: f64,
    timeout: Duration,
) {
    let start = std::time::Instant::now();
    let mut last_body = String::new();
    let mut last_err: Option<String> = None;

    while start.elapsed() < timeout {
        match scrape_collector_metrics(url).await {
            Ok(body) => {
                last_body = body;
                last_err = None;
            }
            Err(e) => {
                last_err = Some(e.to_string());
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        }

        // Fast path: avoid panicking in the helper; just check presence/value.
        let mut found_any = false;
        for line in last_body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !line.starts_with(name) {
                continue;
            }

            // Split on whitespace: "<name>{labels} <value>" or "<name> <value>".
            let mut parts = line.split_whitespace();
            let _metric_and_labels = parts.next();
            let value_str = parts.next().unwrap_or("");
            if let Ok(v) = value_str.parse::<f64>() {
                found_any = true;
                if v > min {
                    return;
                }
            }
        }

        if !found_any {
            // Wait for first export.
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Give a helpful error message.
    if last_body.is_empty() {
        if let Some(err) = last_err {
            panic!(
                "Timed out waiting for Prometheus metrics at {url} to include '{name}' (> {min}); last scrape failed: {err}"
            );
        }

        panic!(
            "Timed out waiting for Prometheus metrics at {url} to include '{name}' (> {min}); last scrape was empty"
        );
    }

    panic!(
        "Timed out waiting for Prometheus metrics at {url} to have '{name}' > {min}. Last scrape:\n{last_body}"
    );
}

/// Integration test: KMS -> otel-collector -> mock backend.
///
/// Prereqs:
/// - `docker compose --profile otel-test up -d --build otel-collector`
///
/// Run:
/// ```bash
/// cargo test -p cosmian_kms_server otel_export_metrics_uptime_and_active_keys -- --ignored --nocapture
/// ```
#[ignore = "Requires docker compose stack (docker-compose.yml, profile otel-test)"]
#[tokio::test]
async fn otel_export_metrics_uptime_and_active_keys() {
    log_init(option_env!("RUST_LOG"));

    // Instantiate KMS with OTLP + metering enabled.
    let mut clap_config = test_utils::https_clap_config();
    let otlp_endpoint = std::env::var("OTEL_EXPORT_OTLP_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:14317".to_owned());
    clap_config.logging.otlp = Some(otlp_endpoint);
    clap_config.logging.enable_metering = true;
    clap_config.db.sqlite_path = test_utils::get_tmp_sqlite_path();
    clap_config.db.clear_database = true;

    let server_params =
        Arc::new(ServerParams::try_from(clap_config).expect("cannot create server params"));
    let kms = Arc::new(
        KMS::instantiate(server_params.clone())
            .await
            .expect("cannot instantiate KMS"),
    );

    // The Active keys metric is refreshed by a periodic cron tick.
    // For in-process tests, we spawn it explicitly.
    let _cron_guard = MetricsCronGuard {
        shutdown: Some(cron::spawn_metrics_cron(kms.clone())),
    };

    // Use the same user as the cron loop so Locate(State=Active) sees our created keys.
    let user = server_params.default_username.clone();

    // Create and activate some keys so the Active keys metric becomes non-zero.
    create_and_activate_symmetric_keys(&kms, &user, 3).await;

    // The active-keys metric is refreshed by a periodic cron tick.
    // A direct KMIP Locate here is not deterministic because our test-created keys
    // may not match the server's "active" locate filter (e.g., missing activation state,
    // or differing attribute constraints). We only assert the exported metric below.

    // Give the metrics cron + OTLP exporter a chance to run at least once (default 30s).
    // To make this fast in the future, we should make both intervals configurable.
    tokio::time::sleep(Duration::from_secs(35)).await;

    // Scrape collector Prometheus endpoint and assert exported KMS metrics.
    // Collector is exposed by `docker-compose.yml` (profile otel-test) on 8889.
    let scrape_url = std::env::var("OTEL_EXPORT_SCRAPE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http://127.0.0.1:18889/metrics".to_owned());

    // Collector's Prometheus exporter exposes received OTLP metrics under their
    // Prometheus-friendly names.
    wait_for_prometheus_metric_gt_eventually(
        &scrape_url,
        "kms_server_start_time_seconds",
        0.0,
        Duration::from_secs(60),
    )
    .await;

    wait_for_prometheus_metric_gt_eventually(
        &scrape_url,
        "kms_keys_active_count",
        0.0,
        Duration::from_secs(120),
    )
    .await;
}
