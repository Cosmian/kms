//! Writes `load_pkcs11.json` and `criterion.json` for the PKCS#11 benchmark.
//!
//! Reuses the shared `crate::actions::bench::load::generate_load_json_output` and
//! `crate::actions::bench::output::collect_json_output` helpers for writing the
//! load and criterion reports, and provides the differential overhead reporting
//! specific to PKCS#11 Ed25519 signing.

use std::{
    fs::{self, OpenOptions},
    io::Write,
};

use super::{
    error::{BenchError, BenchResult},
    load::LoadResult,
};
use crate::actions::bench::{
    load as bench_load,
    output::{collect_json_output, criterion_home},
};

const OVERHEAD_GROUP: &str = "pkcs11-overhead_eddsa-ed25519/";

/// Non-timing metadata recorded alongside the Criterion overhead tiers.
pub(crate) struct OverheadMetadata {
    pub(crate) algorithm: &'static str,
    pub(crate) payload_bytes: usize,
    pub(crate) request_bytes: usize,
    pub(crate) response_bytes: usize,
    pub(crate) binary_request_bytes: usize,
    pub(crate) binary_response_bytes: usize,
    pub(crate) varying_payload: bool,
    pub(crate) phases: Vec<OverheadPhase>,
}

/// One feature-gated internal PKCS#11 Sign phase summary.
pub(crate) struct OverheadPhase {
    pub(crate) name: &'static str,
    pub(crate) count: u64,
    pub(crate) mean_ns: f64,
    pub(crate) p50_ns: u64,
    pub(crate) p95_ns: u64,
    pub(crate) p99_ns: u64,
    pub(crate) max_ns: u64,
}

/// Writes `$CRITERION_HOME/load_pkcs11.json` — one JSON object per line, matching
/// `mise bench:load`'s `load_{protocol_slug}.json` schema exactly.
pub(crate) fn write_load_json(results: &[LoadResult]) -> BenchResult<()> {
    let mapped: Vec<bench_load::LoadResult> = results
        .iter()
        .map(|r| bench_load::LoadResult {
            operation: r.operation.clone(),
            concurrency: r.concurrency,
            throughput_rps: r.throughput_ops,
            p50_ms: r.p50_ms,
            p95_ms: r.p95_ms,
            p99_ms: r.p99_ms,
            samples: r.samples,
        })
        .collect();

    bench_load::generate_load_json_output(&mapped, "pkcs11")
        .map_err(|e| BenchError::Report(e.to_string()))?;

    let json_path = criterion_home().join("load_pkcs11.json");
    eprintln!("[bench:load-pkcs11] JSON report → {}", json_path.display());
    Ok(())
}

fn average_est_val(left: &serde_json::Value, right: &serde_json::Value) -> serde_json::Value {
    let est = f64::midpoint(
        left.get("estimate")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0),
        right
            .get("estimate")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0),
    );
    let lower = f64::midpoint(
        left.get("lower_bound")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0),
        right
            .get("lower_bound")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0),
    );
    let upper = f64::midpoint(
        left.get("upper_bound")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0),
        right
            .get("upper_bound")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0),
    );
    serde_json::json!({
        "estimate": est,
        "lower_bound": lower,
        "upper_bound": upper,
        "unit": "ns",
    })
}

fn average_entry_val(
    entries: &[serde_json::Value],
    first_id: &str,
    second_id: &str,
    output_id: &str,
) -> Option<serde_json::Value> {
    let first = entries
        .iter()
        .find(|e| e.get("id").and_then(serde_json::Value::as_str) == Some(first_id))?;
    let second = entries
        .iter()
        .find(|e| e.get("id").and_then(serde_json::Value::as_str) == Some(second_id))?;

    let typical = match (first.get("typical"), second.get("typical")) {
        (Some(l), Some(r)) => average_est_val(l, r),
        _ => serde_json::Value::Null,
    };
    let mean = match (first.get("mean"), second.get("mean")) {
        (Some(l), Some(r)) => average_est_val(l, r),
        _ => serde_json::Value::Null,
    };
    let median = match (first.get("median"), second.get("median")) {
        (Some(l), Some(r)) => average_est_val(l, r),
        _ => serde_json::Value::Null,
    };
    let median_abs_dev = match (first.get("median_abs_dev"), second.get("median_abs_dev")) {
        (Some(l), Some(r)) => average_est_val(l, r),
        _ => serde_json::Value::Null,
    };

    Some(serde_json::json!({
        "reason": "benchmark-complete",
        "id": output_id,
        "report_directory": "",
        "iteration_count": [],
        "measured_values": [],
        "unit": "ns",
        "throughput": [],
        "typical": typical,
        "mean": mean,
        "median": median,
        "median_abs_dev": median_abs_dev,
        "slope": serde_json::Value::Null,
        "change": serde_json::Value::Null,
    }))
}

/// Appends synthetic bracket-averaged entries to `$CRITERION_HOME/criterion.json`
/// for differential overhead analysis.
pub(crate) fn append_bracket_averaged_entries() -> BenchResult<()> {
    let home = criterion_home();
    let criterion_json = home.join("criterion.json");
    if !criterion_json.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(&criterion_json)
        .map_err(|e| BenchError::Report(format!("read {}: {e}", criterion_json.display())))?;
    let entries: Vec<serde_json::Value> = content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    let mut new_entries = Vec::new();
    for (before, after, output) in [
        (
            "pkcs11-overhead_eddsa-ed25519/typed-binary-message-sign-before",
            "pkcs11-overhead_eddsa-ed25519/typed-binary-message-sign-after",
            "pkcs11-overhead_eddsa-ed25519/typed-binary-message-sign-bracketed",
        ),
        (
            "pkcs11-overhead_eddsa-ed25519/pkcs11-one-call-before",
            "pkcs11-overhead_eddsa-ed25519/pkcs11-one-call-after",
            "pkcs11-overhead_eddsa-ed25519/pkcs11-one-call-bracketed",
        ),
    ] {
        if let Some(entry) = average_entry_val(&entries, before, after, output) {
            new_entries.push(entry);
        }
    }

    if !entries.iter().any(|entry| {
        entry.get("id").and_then(serde_json::Value::as_str)
            == Some("pkcs11_sign-verify_eddsa-ed25519/sign")
    }) && let Some(overhead) = new_entries
        .iter()
        .find(|entry| {
            entry.get("id").and_then(serde_json::Value::as_str)
                == Some("pkcs11-overhead_eddsa-ed25519/pkcs11-one-call-bracketed")
        })
        .cloned()
    {
        let mut alias = overhead;
        if let Some(map) = alias.as_object_mut() {
            map.insert(
                "id".to_owned(),
                serde_json::Value::String("pkcs11_sign-verify_eddsa-ed25519/sign".to_owned()),
            );
            new_entries.push(alias);
        }
    }

    if !new_entries.is_empty() {
        let mut file = OpenOptions::new()
            .append(true)
            .open(&criterion_json)
            .map_err(|e| BenchError::Report(format!("append {}: {e}", criterion_json.display())))?;
        for entry in new_entries {
            let line = serde_json::to_string(&entry)
                .map_err(|e| BenchError::Report(format!("JSON serialization: {e}")))?;
            writeln!(file, "{line}").map_err(|e| {
                BenchError::Report(format!("write {}: {e}", criterion_json.display()))
            })?;
        }
    }

    Ok(())
}

/// Runs the standard `collect_json_output` from `actions::bench::output`.
pub(crate) fn write_criterion_json() -> BenchResult<()> {
    collect_json_output(None, "pkcs11").map_err(|e| BenchError::Report(e.to_string()))
}

/// Writes the explicit PKCS#11 overhead schema consumed by
/// `.mise/scripts/bench/plot_version_compare.py`.
pub(crate) fn write_overhead_json(metadata: &OverheadMetadata) -> BenchResult<()> {
    let home = criterion_home();
    let criterion_json = home.join("criterion.json");
    let content = fs::read_to_string(&criterion_json)
        .map_err(|e| BenchError::Report(format!("read {}: {e}", criterion_json.display())))?;
    let mut entries: Vec<serde_json::Value> = content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    entries.sort_by(|a, b| {
        let id_a = a
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let id_b = b
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        id_a.cmp(id_b)
    });

    let tiers: Vec<serde_json::Value> = entries
        .iter()
        .filter_map(|entry| {
            let id = entry.get("id").and_then(serde_json::Value::as_str)?;
            let name = id.strip_prefix(OVERHEAD_GROUP)?;
            let mean = entry.get("mean")?;
            let median = entry.get("median")?;
            Some(serde_json::json!({
                "name": name,
                "mean_ns": mean.get("estimate").and_then(serde_json::Value::as_f64).unwrap_or(0.0),
                "median_ns": median.get("estimate").and_then(serde_json::Value::as_f64).unwrap_or(0.0),
                "lower_ns": mean.get("lower_bound").and_then(serde_json::Value::as_f64).unwrap_or(0.0),
                "upper_ns": mean.get("upper_bound").and_then(serde_json::Value::as_f64).unwrap_or(0.0),
            }))
        })
        .collect();

    if tiers.is_empty() {
        return Err(BenchError::Report(format!(
            "no Criterion tiers found with prefix {OVERHEAD_GROUP}"
        )));
    }

    let output = serde_json::json!({
        "schema_version": 1,
        "algorithm": metadata.algorithm,
        "payload_bytes": metadata.payload_bytes,
        "request_bytes": metadata.request_bytes,
        "response_bytes": metadata.response_bytes,
        "binary_request_bytes": metadata.binary_request_bytes,
        "binary_response_bytes": metadata.binary_response_bytes,
        "varying_payload": metadata.varying_payload,
        "tiers": tiers,
        "phases": metadata.phases.iter().map(|phase| serde_json::json!({
            "name": phase.name,
            "count": phase.count,
            "mean_ns": phase.mean_ns,
            "p50_ns": phase.p50_ns,
            "p95_ns": phase.p95_ns,
            "p99_ns": phase.p99_ns,
            "max_ns": phase.max_ns,
        })).collect::<Vec<_>>(),
    });
    let json_path = home.join("pkcs11_overhead.json");
    let content = serde_json::to_vec_pretty(&output)
        .map_err(|e| BenchError::Report(format!("JSON serialization: {e}")))?;
    fs::write(&json_path, content)
        .map_err(|e| BenchError::Report(format!("write {}: {e}", json_path.display())))?;
    eprintln!(
        "[bench:load-pkcs11] overhead JSON report → {}",
        json_path.display()
    );
    Ok(())
}
