//! Writes `load_pkcs11.json` in the exact schema `mise bench:load` uses
//! (`crate/clients/clap/src/actions/bench/load.rs::generate_load_json_output`), so the
//! shared `bench_generate_report`/`plot_version_compare.py` report pipeline
//! (`.mise/lib/bench_helpers.sh`) can pick it up with zero changes to its JSON
//! parsing: one JSON object per line, `{"protocol":"pkcs11","operation":"…",
//! "concurrency":N,"throughput_rps":…,"p50_ms":…,"p95_ms":…,"p99_ms":…}`.

use std::{fs, path::PathBuf};

use crate::{error::BenchResult, load::LoadResult};

/// Protocol label written into every record — the report pipeline groups results by
/// this field to build report chart legends and table columns.
const PROTOCOL: &str = "pkcs11";

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
