use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::types::BENCH_KO;
use crate::error::{KmsCliError, result::KmsCliResult};

// --- Criterion internal deserialization structs ---

#[derive(Deserialize)]
struct CriterionEstimates {
    mean: CriterionEstimate,
    median: CriterionEstimate,
    #[allow(dead_code)]
    std_dev: CriterionEstimate,
    median_abs_dev: Option<CriterionEstimate>,
}

#[derive(Deserialize)]
struct CriterionEstimate {
    point_estimate: f64,
    #[allow(dead_code)]
    standard_error: f64,
    confidence_interval: CriterionCI,
}

#[derive(Deserialize)]
struct CriterionCI {
    #[allow(dead_code)]
    confidence_level: f64,
    lower_bound: f64,
    upper_bound: f64,
}

// --- criterion-table output format (cargo-criterion --message-format=json schema) ---

#[derive(Serialize)]
struct CtEst {
    estimate: f64,
    lower_bound: f64,
    upper_bound: f64,
    unit: &'static str, // "ns"
}

#[derive(Serialize)]
struct CtBenchmarkComplete {
    reason: &'static str, /* "benchmark-complete" (cargo-criterion compat; ignored by criterion-table) */
    id: String,
    report_directory: &'static str, // "" — criterion-table requires a string, not null
    iteration_count: Vec<u64>,      // [] — required non-null array
    measured_values: Vec<f64>,      // [] — required non-null array
    unit: &'static str,             // "ns" — required top-level time unit
    throughput: Vec<serde_json::Value>, // [] — required non-null array
    typical: CtEst,
    mean: CtEst,
    median: CtEst,
    median_abs_dev: CtEst,
    slope: Option<CtEst>,
    change: Option<serde_json::Value>, // always null; version comparison done via ID structure
}

pub(super) fn count_baseline_files(home: &Path, baseline: &str) -> usize {
    let mut count = 0;
    if let Ok(walker) = fs::read_dir(home) {
        count_baseline_recursive(walker, baseline, &mut count);
    }
    count
}

fn count_baseline_recursive(dir: fs::ReadDir, baseline: &str, count: &mut usize) {
    for entry in dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some(baseline) {
                let estimates = path.join("estimates.json");
                if estimates.exists() {
                    *count += 1;
                }
            } else if let Ok(sub) = fs::read_dir(&path) {
                count_baseline_recursive(sub, baseline, count);
            }
        }
    }
}

pub(super) fn criterion_home() -> PathBuf {
    std::env::var("CRITERION_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("CARGO_TARGET_DIR").map(|p| PathBuf::from(p).join("criterion")))
        .unwrap_or_else(|_| PathBuf::from("target/criterion"))
}

pub(super) fn collect_json_output(
    version_label: Option<&str>,
    protocol_slug: &str,
) -> KmsCliResult<()> {
    let home = criterion_home();
    let mut entries: Vec<CtBenchmarkComplete> = Vec::new();
    if home.exists() {
        collect_estimates_recursive(&home, &home, version_label, &mut entries)?;
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));

    // Emit one JSON line per benchmark to stdout (criterion-table format).
    for entry in &entries {
        let line = serde_json::to_string(entry)
            .map_err(|e| KmsCliError::Default(format!("JSON serialization: {e}")))?;
        #[allow(clippy::print_stdout)]
        {
            println!("{line}");
        }
    }

    // Write protocol-specific JSON file (pretty, for criterion-table compatibility).
    let json_path = home.join(format!("benchmarks_{protocol_slug}.json"));
    let compat = serde_json::json!({ "benchmarks": entries });
    let content = serde_json::to_string_pretty(&compat)
        .map_err(|e| KmsCliError::Default(format!("JSON serialization: {e}")))?;
    fs::write(&json_path, &content)
        .map_err(|e| KmsCliError::Default(format!("Write {}: {e}", json_path.display())))?;
    eprintln!("[bench] JSON results written to {}", json_path.display());

    // Write criterion.json JSONL file (one line per benchmark, same format as stdout)
    // so that plot_version_compare.py can read it directly.
    let jsonl_path = home.join("criterion.json");
    let mut jsonl = String::new();
    for entry in &entries {
        let line = serde_json::to_string(entry)
            .map_err(|e| KmsCliError::Default(format!("JSON serialization: {e}")))?;
        jsonl.push_str(&line);
        jsonl.push('\n');
    }
    fs::write(&jsonl_path, &jsonl)
        .map_err(|e| KmsCliError::Default(format!("Write {}: {e}", jsonl_path.display())))?;
    eprintln!("[bench] JSONL results written to {}", jsonl_path.display());
    Ok(())
}

const fn make_ct_est(est: &CriterionEstimate) -> CtEst {
    CtEst {
        estimate: est.point_estimate,
        lower_bound: est.confidence_interval.lower_bound,
        upper_bound: est.confidence_interval.upper_bound,
        unit: "ns",
    }
}

/// Transform a raw criterion path ID for version comparison.
///
/// When `version_label` is set, inserts the label as the second-to-last
/// segment so criterion-table renders versions as columns:
/// - `"A/B/C"` → `"A/{label}/B - C"` (section=A, col=label, row="B - C")
/// - `"A/B"`   → `"A/{label}/B"`      (section=A, col=label, row=B)
/// - `"A"`     → `"A/{label}"`        (section=A, col=label, no row)
fn apply_version_label(raw_id: &str, label: &str) -> String {
    if let Some((section, rest)) = raw_id.split_once('/') {
        let row = rest.replace('/', " - ");
        format!("{section}/{label}/{row}")
    } else {
        format!("{raw_id}/{label}")
    }
}

fn collect_estimates_recursive(
    base: &Path,
    dir: &Path,
    version_label: Option<&str>,
    results: &mut Vec<CtBenchmarkComplete>,
) -> KmsCliResult<()> {
    let estimates_path = dir.join("new").join("estimates.json");
    if estimates_path.exists() {
        let content = fs::read_to_string(&estimates_path)
            .map_err(|e| KmsCliError::Default(format!("Read {}: {e}", estimates_path.display())))?;
        if let Ok(estimates) = serde_json::from_str::<CriterionEstimates>(&content) {
            let raw_id = dir
                .strip_prefix(base)
                .unwrap_or(dir)
                .to_string_lossy()
                .to_string();
            let id = version_label.map_or_else(
                || raw_id.clone(),
                |label| apply_version_label(&raw_id, label),
            );
            let mean = make_ct_est(&estimates.mean);
            let median = make_ct_est(&estimates.median);
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
                mean,
                median,
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
                collect_estimates_recursive(base, &entry.path(), version_label, results)?;
            }
        }
    }
    Ok(())
}

// =============================================================================
// MARKDOWN TABLE GENERATION (embedded criterion-table)
// =============================================================================

/// Metadata from criterion's `benchmark.json`.
#[derive(Deserialize)]
struct BenchmarkMeta {
    group_id: String,
    function_id: Option<String>,
    value_str: Option<String>,
    #[allow(dead_code)]
    full_id: String,
    #[allow(dead_code)]
    directory_name: String,
}

/// Slope estimate from criterion's `estimates.json`.
#[derive(Deserialize)]
struct SlopeEstimates {
    slope: Option<SlopeEstimate>,
    mean: CriterionEstimate,
}

#[derive(Deserialize)]
struct SlopeEstimate {
    point_estimate: f64,
}

/// One benchmark data point for table rendering.
struct BenchPoint {
    function_id: String,
    value_str: String,
    time_ns: f64,
}

/// Format nanoseconds as human-readable time.
fn format_time(ns: f64) -> String {
    if ns < 1_000.0 {
        format!("{ns:.2} ns")
    } else if ns < 1_000_000.0 {
        format!("{:.2} µs", ns / 1_000.0)
    } else if ns < 1_000_000_000.0 {
        format!("{:.2} ms", ns / 1_000_000.0)
    } else {
        format!("{:.2} s", ns / 1_000_000_000.0)
    }
}

/// Descriptions for groups (matches tables.toml [`top_comments`]).
fn group_description(group_id: &str) -> Option<&'static str> {
    match group_id {
        // Encryption
        "encrypt/aes-gcm" => {
            Some("AES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).")
        }
        "encrypt/aes-xts" => {
            Some("AES-XTS encrypt and decrypt (128/256-bit AES, 64-byte plaintext).")
        }
        "encrypt/aes-gcm-siv" => {
            Some("AES-GCM-SIV encrypt and decrypt (128/256-bit keys, 64-byte plaintext). Non-FIPS.")
        }
        "encrypt/chacha20-poly1305" => Some(
            "ChaCha20-Poly1305 encrypt and decrypt (256-bit key, 64-byte plaintext). Non-FIPS.",
        ),
        "encrypt/rsa-oaep" => {
            Some("RSA-OAEP encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).")
        }
        "encrypt/rsa-pkcs1v15" => Some(
            "RSA PKCS#1 v1.5 encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).",
        ),
        "encrypt/ecies" => {
            Some("ECIES encrypt and decrypt on NIST curves (P-256/P-384/P-521). Non-FIPS.")
        }
        "encrypt/salsa-sealed-box" => {
            Some("Salsa Sealed Box (X25519) encrypt and decrypt. Non-FIPS.")
        }
        "encrypt/covercrypt" => Some("Covercrypt attribute-based encrypt and decrypt. Non-FIPS."),
        // KEM
        "kem/configurable" => Some(
            "Configurable KEM encapsulate and decapsulate (ML-KEM, hybrid variants). Non-FIPS.",
        ),
        "kem/pqc" => Some(
            "Standard PQC KEM encapsulate and decapsulate (ML-KEM, X25519MLKEM768, X448MLKEM1024). Non-FIPS.",
        ),
        // Key creation
        "key-creation/symmetric" => Some("AES (and ChaCha20 in non-FIPS) symmetric key creation."),
        "key-creation/rsa" => Some("RSA key pair generation (2048/3072/4096-bit)."),
        "key-creation/ec" => Some("Elliptic curve key pair generation (NIST and non-FIPS curves)."),
        "key-creation/covercrypt" => Some("Covercrypt master key pair generation. Non-FIPS."),
        "key-creation/kem" => {
            Some("Configurable KEM key pair generation (ML-KEM, hybrid variants). Non-FIPS.")
        }
        "key-creation/pqc" => {
            Some("PQC key pair generation (ML-KEM, ML-DSA, SLH-DSA, hybrid KEM). Non-FIPS.")
        }
        // Sign / verify
        "sign-verify/ecdsa-p256" | "sign-verify/ecdsa-p384" | "sign-verify/ecdsa-p521" => {
            Some("ECDSA sign and verify on NIST curves.")
        }
        "sign-verify/ecdsa-secp256k1" | "sign-verify/eddsa-ed25519" | "sign-verify/eddsa-ed448" => {
            Some("Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).")
        }
        "sign-verify/rsa-pss" => Some("RSA-PSS sign and verify (SHA-256, 2048/3072/4096-bit)."),
        "sign-verify/ml-dsa" => Some("ML-DSA sign and verify (ML-DSA-44/65/87). Non-FIPS."),
        "sign-verify/slh-dsa" => Some(
            "SLH-DSA (stateless hash-based) sign and verify (SHA2/SHAKE, 128/192/256). Non-FIPS.",
        ),
        // Batch
        "batch/aes-gcm" => {
            Some("AES-GCM batch — encrypt/decrypt N items in a single BulkData call.")
        }
        "batch/rsa-pkcs1v15" => {
            Some("RSA PKCS#1 v1.5 batch — encrypt/decrypt N items in a single KMIP message.")
        }
        "batch/rsa-oaep" => {
            Some("RSA-OAEP batch — encrypt/decrypt N items in a single KMIP message.")
        }
        "batch/rsa-aes-kwp" => {
            Some("RSA AES Key Wrap batch — encrypt/decrypt N items in a single KMIP message.")
        }
        // JOSE
        "jose/encrypt" => Some(
            "JOSE JWE symmetric encrypt/decrypt via /v1/crypto/ (dir + A*GCM, 64-byte plaintext).",
        ),
        "jose/encrypt/rsa-oaep" => Some(
            "JOSE JWE asymmetric encrypt/decrypt via /v1/crypto/ (RSA-OAEP + A256GCM, 2048/4096-bit, 64-byte plaintext).",
        ),
        "jose/sign-verify/ecdsa-p256" | "jose/sign-verify/ecdsa-p384" => {
            Some("JOSE JWS ECDSA sign/verify via /v1/crypto/ (ES256/ES384, 32-byte payload).")
        }
        "jose/sign-verify/rsa-pkcs1v15" => {
            Some("JOSE JWS RS256 sign/verify via /v1/crypto/ (RSASSA-PKCS1-v1_5, 2048-bit).")
        }
        "jose/sign-verify/rsa-pss" => {
            Some("JOSE JWS PS256 sign/verify via /v1/crypto/ (RSASSA-PSS, 2048-bit).")
        }
        "jose/sign-verify/eddsa-ed25519" => {
            Some("JOSE JWS EdDSA sign/verify via /v1/crypto/ (Ed25519). Non-FIPS.")
        }
        "jose/mac" => Some("JOSE HMAC compute/verify via /v1/crypto/ (HS256, HS384, HS512)."),
        "jose/key-creation" => Some("JOSE key creation via /v1/crypto/keys (oct, EC, RSA)."),
        "jose/batch" => Some("JOSE batch — N sequential encrypt requests via /v1/crypto/encrypt."),
        // Wire (binary TTLV)
        "wire/encrypt/aes-gcm" => {
            Some("AES-GCM encrypt/decrypt over binary TTLV wire format (128/256-bit).")
        }
        "wire/encrypt/rsa-oaep" => {
            Some("RSA-OAEP encrypt/decrypt over binary TTLV wire format (2048/4096-bit).")
        }
        "wire/sign-verify/ecdsa-p256" => {
            Some("ECDSA P-256 sign/verify over binary TTLV wire format.")
        }
        "wire/sign-verify/rsa-pss" => Some("RSA-PSS sign/verify over binary TTLV wire format."),
        "wire/key-creation" => Some("Key creation over binary TTLV wire format (AES, EC, RSA)."),
        "wire/batch/aes-gcm" => Some("AES-GCM batch encrypt over binary TTLV wire format."),
        _ => None,
    }
}

/// Walk `target/criterion/` and collect all benchmark data points.
fn collect_bench_points(home: &Path) -> KmsCliResult<BTreeMap<String, Vec<BenchPoint>>> {
    let mut groups: BTreeMap<String, Vec<BenchPoint>> = BTreeMap::new();
    collect_bench_points_recursive(home, home, &mut groups)?;
    Ok(groups)
}

fn collect_bench_points_recursive(
    home: &Path,
    dir: &Path,
    groups: &mut BTreeMap<String, Vec<BenchPoint>>,
) -> KmsCliResult<()> {
    let bm_path = dir.join("new").join("benchmark.json");
    let est_path = dir.join("new").join("estimates.json");
    if bm_path.exists() && est_path.exists() {
        let bm_content = fs::read_to_string(&bm_path)
            .map_err(|e| KmsCliError::Default(format!("Read {}: {e}", bm_path.display())))?;
        let est_content = fs::read_to_string(&est_path)
            .map_err(|e| KmsCliError::Default(format!("Read {}: {e}", est_path.display())))?;
        if let (Ok(meta), Ok(est)) = (
            serde_json::from_str::<BenchmarkMeta>(&bm_content),
            serde_json::from_str::<SlopeEstimates>(&est_content),
        ) {
            let time_ns = est
                .slope
                .map_or(est.mean.point_estimate, |s| s.point_estimate);
            let function_id = meta.function_id.unwrap_or_default();
            let value_str = meta.value_str.unwrap_or_default();
            groups.entry(meta.group_id).or_default().push(BenchPoint {
                function_id,
                value_str,
                time_ns,
            });
        }
    }
    if let Ok(entries) = fs::read_dir(dir) {
        let mut sorted: Vec<_> = entries.flatten().collect();
        sorted.sort_by_key(std::fs::DirEntry::file_name);
        for entry in sorted {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if entry.file_type().is_ok_and(|t| t.is_dir())
                && name_str != "new"
                && name_str != "base"
                && name_str != "change"
                && name_str != "report"
            {
                collect_bench_points_recursive(home, &entry.path(), groups)?;
            }
        }
    }
    Ok(())
}

/// Render a single group as a parametrized markdown table (criterion-table style).
///
/// If benchmarks have `value_str` (parameters), renders a pivot table with
/// `function_ids` as columns and parameters as rows. Otherwise renders a flat table.
fn render_group_table(group_id: &str, points: &[BenchPoint]) -> String {
    let mut out = String::new();

    // Group heading
    out.push_str(&format!("### {group_id}\n\n"));
    if let Some(desc) = group_description(group_id) {
        out.push_str(&format!("{desc}\n\n"));
    }

    // Collect unique function_ids and value_strs preserving insertion order
    let mut func_ids: Vec<String> = Vec::new();
    let mut param_strs: Vec<String> = Vec::new();
    for p in points {
        if !func_ids.contains(&p.function_id) {
            func_ids.push(p.function_id.clone());
        }
        if !p.value_str.is_empty() && !param_strs.contains(&p.value_str) {
            param_strs.push(p.value_str.clone());
        }
    }

    // Sort parameters numerically when they have a leading number (e.g. "1 request", "50 requests")
    param_strs.sort_by(|a, b| {
        let num_a = a
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<u64>().ok());
        let num_b = b
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<u64>().ok());
        match (num_a, num_b) {
            (Some(na), Some(nb)) => na.cmp(&nb),
            _ => a.cmp(b),
        }
    });

    if param_strs.is_empty() {
        // Flat table: one column per function_id
        out.push_str("| |");
        for fid in &func_ids {
            out.push_str(&format!(" `{fid}` |"));
        }
        out.push('\n');

        out.push_str("| :--- |");
        for _ in &func_ids {
            out.push_str(" :--- |");
        }
        out.push('\n');

        out.push_str("| |");
        for fid in &func_ids {
            let val = points
                .iter()
                .find(|p| p.function_id == *fid)
                .map_or_else(|| "N/A".to_owned(), |p| format_time(p.time_ns));
            out.push_str(&format!(" `{val}` |"));
        }
        out.push('\n');
    } else {
        // Pivot table: columns = function_ids, rows = parameters
        out.push_str("| |");
        for fid in &func_ids {
            out.push_str(&format!(" `{fid}` |"));
        }
        out.push('\n');

        out.push_str("| :--- |");
        for _ in &func_ids {
            out.push_str(" :--- |");
        }
        out.push('\n');

        for param in &param_strs {
            out.push_str(&format!("| **`{param}`** |"));
            for fid in &func_ids {
                let val = points
                    .iter()
                    .find(|p| p.function_id == *fid && p.value_str == *param)
                    .map_or_else(|| "N/A".to_owned(), |p| format_time(p.time_ns));
                out.push_str(&format!(" `{val}` |"));
            }
            out.push('\n');
        }
    }

    out
}

/// Generate markdown tables for all benchmark groups and write to file.
pub(super) fn generate_markdown_output(protocol_slug: &str) -> KmsCliResult<()> {
    let home = criterion_home();
    if !home.exists() {
        eprintln!("[bench] No criterion data found, skipping markdown generation");
        return Ok(());
    }

    let groups = collect_bench_points(&home)?;
    if groups.is_empty() {
        eprintln!("[bench] No benchmark results found, skipping markdown generation");
        return Ok(());
    }

    let mut md = String::from("## Benchmark Results\n\n");
    for (group_id, points) in &groups {
        md.push_str(&render_group_table(group_id, points));
        md.push('\n');
    }

    let md_path = home.join(format!("benchmarks_{protocol_slug}.md"));
    fs::write(&md_path, &md)
        .map_err(|e| KmsCliError::Default(format!("Write {}: {e}", md_path.display())))?;
    eprintln!("[bench] Markdown report written to {}", md_path.display());

    Ok(())
}

/// Return true if any `estimates.json` inside `dir` (recursively) was written
/// at or after `since`. Used to distinguish current-run criterion data from
/// stale data left by previous runs.
fn group_updated_since(dir: &Path, since: std::time::SystemTime) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if group_updated_since(&path, since) {
                return true;
            }
        } else if path.file_name().is_some_and(|n| n == "estimates.json")
            && path
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|t| t >= since)
        {
            return true;
        }
    }
    false
}

pub(super) fn generate_compact_output(run_start: std::time::SystemTime) -> KmsCliResult<()> {
    let home = criterion_home();
    let mut results: BTreeMap<String, bool> = BTreeMap::new();

    // ── OK: criterion groups updated during the current run ───────────────
    // Filtering by mtime prevents stale data from previous runs (against a
    // different server version) from producing false-positive OKs.
    if home.exists() {
        let points = collect_bench_points(&home)?;
        for group_id in points.keys() {
            // Criterion 0.6 stores group "a/b" as directory target/criterion/a_b/
            // (slashes replaced by underscores, not nested directories).
            let dir_name = group_id.replace('/', "_");
            let group_dir = home.join(&dir_name);
            if group_updated_since(&group_dir, run_start) {
                results.insert(group_id.clone(), true);
            }
        }
    }

    // ── KO: groups that were fully skipped (inserted only if not already OK)
    BENCH_KO.with(|r| {
        for name in r.borrow().iter() {
            results.entry(name.clone()).or_insert(false);
        }
    });

    if results.is_empty() {
        eprintln!("[bench] compact: no results collected");
        return Ok(());
    }

    // ── Print aligned list ────────────────────────────────────────────────
    let width = results.keys().map(String::len).max().unwrap_or(40) + 2;
    for (name, ok) in &results {
        let status = if *ok { "OK" } else { "KO" };
        #[allow(clippy::print_stdout)]
        {
            println!("{name:<width$} {status}");
        }
    }

    let total = results.len();
    let ok_cnt = results.values().filter(|&&v| v).count();
    eprintln!(
        "[bench] compact summary: {ok_cnt}/{total} OK, {} KO",
        total - ok_cnt
    );

    Ok(())
}

// =============================================================================
