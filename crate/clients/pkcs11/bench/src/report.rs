//! Writes `load_pkcs11.json` in the exact schema `mise bench:load` uses
//! (`crate/clients/clap/src/actions/bench/load.rs::generate_load_json_output`), so the
//! shared `bench_generate_report`/`plot_version_compare.py` report pipeline
//! (`.mise/lib/bench_helpers.sh`) can pick it up with zero changes to its JSON
//! parsing: one JSON object per line, `{"protocol":"pkcs11","operation":"…",
//! "concurrency":N,"throughput_rps":…,"p50_ms":…,"p95_ms":…,"p99_ms":…}`.
//!
//! Also writes `criterion.json` in the same JSONL schema
//! `crate/clients/clap/src/actions/bench/output.rs::collect_json_output` produces
//! for `mise bench:load --criterion`, by walking the real `criterion` crate's own
//! `new/estimates.json` output files — so `bench_generate_report` picks up
//! single-operation statistical micro-benchmarks with zero changes to its parsing
//! either. That collector is `pub(super)`-private to the `clap` bench module (not
//! designed for cross-crate reuse), hence the small, self-contained duplicate below
//! rather than an import.

use std::{fs, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{error::BenchResult, load::LoadResult};

/// Protocol label written into every record — the report pipeline groups results by
/// this field to build report chart legends and table columns.
const PROTOCOL: &str = "pkcs11";
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

/// Resolves the criterion/report data directory, mirroring
/// `crate/clients/clap/src/actions/bench/output.rs::criterion_home`: `$CRITERION_HOME`
/// > `$CARGO_TARGET_DIR/criterion` > `target/criterion`.
fn criterion_home() -> PathBuf {
    std::env::var("CRITERION_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("CARGO_TARGET_DIR").map(|p| PathBuf::from(p).join("criterion")))
        .unwrap_or_else(|_| PathBuf::from("target/criterion"))
}

/// Writes `$CRITERION_HOME/load_pkcs11.json` — one JSON object per line, matching
/// `mise bench:load`'s `load_{protocol_slug}.json` schema exactly.
pub(crate) fn write_load_json(results: &[LoadResult]) -> BenchResult<()> {
    if results.is_empty() {
        return Ok(());
    }
    let home = criterion_home();
    fs::create_dir_all(&home)
        .map_err(|e| crate::error::BenchError::Report(format!("create {}: {e}", home.display())))?;

    let mut lines = String::new();
    for r in results {
        lines.push_str(&format!(
            "{{\"protocol\":\"{PROTOCOL}\",\"operation\":\"{}\",\
             \"concurrency\":{},\"throughput_rps\":{:.2},\
             \"p50_ms\":{:.3},\"p95_ms\":{:.3},\"p99_ms\":{:.3}}}\n",
            r.operation, r.concurrency, r.throughput_ops, r.p50_ms, r.p95_ms, r.p99_ms,
        ));
    }

    let json_path = home.join(format!("load_{PROTOCOL}.json"));
    fs::write(&json_path, &lines).map_err(|e| {
        crate::error::BenchError::Report(format!("write {}: {e}", json_path.display()))
    })?;
    eprintln!("[bench:load-pkcs11] JSON report → {}", json_path.display());
    Ok(())
}

// --- criterion's own on-disk estimates format (read-only, not written by us) ---

#[derive(Deserialize)]
struct CriterionEstimates {
    mean: CriterionEstimate,
    median: CriterionEstimate,
    median_abs_dev: Option<CriterionEstimate>,
}

#[derive(Deserialize)]
struct CriterionEstimate {
    point_estimate: f64,
    confidence_interval: CriterionCi,
}

#[derive(Deserialize)]
struct CriterionCi {
    lower_bound: f64,
    upper_bound: f64,
}

// --- criterion-table-compatible output format, mirroring
// crate/clients/clap/src/actions/bench/output.rs's `Ct*` structs exactly (same field
// names/shapes) so `plot_version_compare.py::parse_criterion_json` needs no changes.

#[derive(Clone, Serialize)]
struct CtEst {
    estimate: f64,
    lower_bound: f64,
    upper_bound: f64,
    unit: &'static str,
}

#[derive(Clone, Serialize)]
struct CtBenchmarkComplete {
    reason: &'static str,
    id: String,
    report_directory: &'static str,
    iteration_count: Vec<u64>,
    measured_values: Vec<f64>,
    unit: &'static str,
    throughput: Vec<serde_json::Value>,
    typical: CtEst,
    mean: CtEst,
    median: CtEst,
    median_abs_dev: CtEst,
    slope: Option<CtEst>,
    change: Option<serde_json::Value>,
}

const fn make_ct_est(est: &CriterionEstimate) -> CtEst {
    CtEst {
        estimate: est.point_estimate,
        lower_bound: est.confidence_interval.lower_bound,
        upper_bound: est.confidence_interval.upper_bound,
        unit: "ns",
    }
}

const fn average_estimate(left: &CtEst, right: &CtEst) -> CtEst {
    CtEst {
        estimate: f64::midpoint(left.estimate, right.estimate),
        lower_bound: f64::midpoint(left.lower_bound, right.lower_bound),
        upper_bound: f64::midpoint(left.upper_bound, right.upper_bound),
        unit: "ns",
    }
}

fn average_entry(
    entries: &[CtBenchmarkComplete],
    first_id: &str,
    second_id: &str,
    output_id: &str,
) -> Option<CtBenchmarkComplete> {
    let first = entries.iter().find(|entry| entry.id == first_id)?;
    let second = entries.iter().find(|entry| entry.id == second_id)?;
    Some(CtBenchmarkComplete {
        reason: "benchmark-complete",
        id: output_id.to_owned(),
        report_directory: "",
        iteration_count: vec![],
        measured_values: vec![],
        unit: "ns",
        throughput: vec![],
        typical: average_estimate(&first.typical, &second.typical),
        mean: average_estimate(&first.mean, &second.mean),
        median: average_estimate(&first.median, &second.median),
        median_abs_dev: average_estimate(&first.median_abs_dev, &second.median_abs_dev),
        slope: None,
        change: None,
    })
}

fn append_bracketed_entries(entries: &mut Vec<CtBenchmarkComplete>) {
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
        if let Some(entry) = average_entry(entries, before, after, output) {
            entries.push(entry);
        }
    }
}

/// Recursively walks `dir` for `new/estimates.json` files (criterion's per-benchmark
/// output directory), appending one [`CtBenchmarkComplete`] per benchmark found.
///
/// Mirrors `collect_estimates_recursive` in
/// `crate/clients/clap/src/actions/bench/output.rs`: the benchmark `id` is the path
/// from `base` (the criterion home) to the containing directory. In practice
/// `criterion` sanitizes a `bench_function` id like `"sign/eddsa-ed25519"` into a
/// single flat directory (`sign_eddsa-ed25519`, `/` becomes `_`), but this walk
/// makes no assumption either way — it reconstructs the `id` from whatever
/// directory structure is actually on disk, so it would also handle a benchmark
/// group/`BenchmarkId` that *does* nest directories.
fn collect_estimates_recursive(
    base: &std::path::Path,
    dir: &std::path::Path,
    results: &mut Vec<CtBenchmarkComplete>,
) -> BenchResult<()> {
    let estimates_path = dir.join("new").join("estimates.json");
    if estimates_path.exists() {
        let content = fs::read_to_string(&estimates_path).map_err(|e| {
            crate::error::BenchError::Report(format!("read {}: {e}", estimates_path.display()))
        })?;
        if let Ok(estimates) = serde_json::from_str::<CriterionEstimates>(&content) {
            let id = dir
                .strip_prefix(base)
                .unwrap_or(dir)
                .to_string_lossy()
                .to_string();
            let median_abs_dev = estimates.median_abs_dev.as_ref().map_or(
                CtEst {
                    estimate: 0.0,
                    lower_bound: 0.0,
                    upper_bound: 0.0,
                    unit: "ns",
                },
                make_ct_est,
            );
            results.push(CtBenchmarkComplete {
                reason: "benchmark-complete",
                id,
                report_directory: "",
                iteration_count: vec![],
                measured_values: vec![],
                unit: "ns",
                throughput: vec![],
                typical: make_ct_est(&estimates.mean),
                mean: make_ct_est(&estimates.mean),
                median: make_ct_est(&estimates.median),
                median_abs_dev,
                slope: None,
                change: None,
            });
        }
    }
    if let Ok(dir_entries) = fs::read_dir(dir) {
        for entry in dir_entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir())
                && entry.file_name() != "new"
                && entry.file_name() != "base"
                && entry.file_name() != "change"
            {
                collect_estimates_recursive(base, &entry.path(), results)?;
            }
        }
    }
    Ok(())
}

/// Walks `$CRITERION_HOME` for every benchmark the just-completed criterion run
/// produced and writes `$CRITERION_HOME/criterion.json` — the same JSONL schema
/// `mise bench:load --criterion` writes, so `bench_generate_report` picks it up
/// unchanged (see the module doc comment).
pub(crate) fn write_criterion_json() -> BenchResult<()> {
    let home = criterion_home();
    let mut entries = Vec::new();
    if home.exists() {
        collect_estimates_recursive(&home, &home, &mut entries)?;
    }
    append_bracketed_entries(&mut entries);
    if !entries
        .iter()
        .any(|entry| entry.id == "pkcs11_sign-verify_eddsa-ed25519/sign")
        && let Some(overhead) = entries
            .iter()
            .find(|entry| entry.id == "pkcs11-overhead_eddsa-ed25519/pkcs11-one-call-bracketed")
            .cloned()
    {
        entries.push(CtBenchmarkComplete {
            id: "pkcs11_sign-verify_eddsa-ed25519/sign".to_owned(),
            ..overhead
        });
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));

    if entries.is_empty() {
        eprintln!(
            "[bench:load-pkcs11] WARNING: no criterion benchmark data found under {}",
            home.display()
        );
        return Ok(());
    }

    let mut jsonl = String::new();
    for entry in &entries {
        let line = serde_json::to_string(entry)
            .map_err(|e| crate::error::BenchError::Report(format!("JSON serialization: {e}")))?;
        jsonl.push_str(&line);
        jsonl.push('\n');
    }

    let json_path = home.join("criterion.json");
    fs::write(&json_path, &jsonl).map_err(|e| {
        crate::error::BenchError::Report(format!("write {}: {e}", json_path.display()))
    })?;
    eprintln!(
        "[bench:load-pkcs11] criterion JSON report → {}",
        json_path.display()
    );
    Ok(())
}

/// Writes the explicit PKCS#11 overhead schema consumed by
/// `.mise/scripts/bench/plot_version_compare.py`.
pub(crate) fn write_overhead_json(metadata: &OverheadMetadata) -> BenchResult<()> {
    let home = criterion_home();
    let mut entries = Vec::new();
    collect_estimates_recursive(&home, &home, &mut entries)?;
    append_bracketed_entries(&mut entries);
    entries.sort_by(|a, b| a.id.cmp(&b.id));

    let tiers: Vec<serde_json::Value> = entries
        .iter()
        .filter_map(|entry| {
            let name = entry.id.strip_prefix(OVERHEAD_GROUP)?;
            Some(serde_json::json!({
                "name": name,
                "mean_ns": entry.mean.estimate,
                "median_ns": entry.median.estimate,
                "lower_ns": entry.mean.lower_bound,
                "upper_ns": entry.mean.upper_bound,
            }))
        })
        .collect();
    if tiers.is_empty() {
        return Err(crate::error::BenchError::Report(format!(
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
        .map_err(|e| crate::error::BenchError::Report(format!("JSON serialization: {e}")))?;
    fs::write(&json_path, content).map_err(|e| {
        crate::error::BenchError::Report(format!("write {}: {e}", json_path.display()))
    })?;
    eprintln!(
        "[bench:load-pkcs11] overhead JSON report → {}",
        json_path.display()
    );
    Ok(())
}
