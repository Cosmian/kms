//! Writes `load_pkcs11.json` and `criterion.json` for the PKCS#11 benchmark.
//!
//! Reuses the shared `crate::actions::bench::load::generate_load_json_output` and
//! `crate::actions::bench::output::collect_json_output` helpers for writing the
//! load and criterion reports.

use super::{
    error::{BenchError, BenchResult},
    load::LoadResult,
};
use crate::actions::bench::{
    load as bench_load,
    output::{collect_json_output, criterion_home},
};

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
            errors: 0, // In pkcs11/bench/load.rs `run_for`, any op(session)? error aborts the sweep, so only completed runs are reported
        })
        .collect();

    bench_load::generate_load_json_output(&mapped, "pkcs11")
        .map_err(|e| BenchError::Report(e.to_string()))?;

    let json_path = criterion_home().join("load_pkcs11.json");
    eprintln!("[bench:pkcs11] JSON report → {}", json_path.display());
    Ok(())
}

/// Runs the standard `collect_json_output` from `actions::bench::output`.
pub(crate) fn write_criterion_json() -> BenchResult<()> {
    collect_json_output(None, "pkcs11").map_err(|e| BenchError::Report(e.to_string()))
}
