use std::{
    fs,
    time::{Duration, Instant},
};

use cosmian_kms_client::{
    KmsClient,
    jose::{JoseEncReq, JoseSignReq, b64url},
    kmip_2_1::{
        extra::BulkData,
        kmip_operations::{Encrypt, Operation, Sign},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
            RecommendedCurve,
        },
        requests::{encrypt_request, symmetric_key_create_request},
    },
};
use serde::Serialize;
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

use super::{
    helpers::{aes_gcm_params, create_sym_key, try_create_ec_kp},
    jose::{jose_create_sym_key, jose_try_create_ec_kp},
    output::criterion_home,
    transport::{make_wire_request, to_wire_bytes, wire_response_ok},
    types::{BenchMode, BenchProtocol},
};
use crate::error::{KmsCliError, result::KmsCliResult};

// LOAD TESTING
// =============================================================================

/// Throughput and latency percentiles for one operation at one concurrency level.
#[derive(Debug, Serialize)]
pub(super) struct LoadResult {
    /// Operation name (mirrors criterion group IDs where applicable).
    pub operation: String,
    /// Number of concurrent tasks that were sending requests simultaneously.
    pub concurrency: usize,
    /// Achieved throughput in requests per second.
    pub throughput_rps: f64,
    /// 50th-percentile (median) round-trip latency in milliseconds.
    pub p50_ms: f64,
    /// 95th-percentile round-trip latency in milliseconds.
    pub p95_ms: f64,
    /// 99th-percentile round-trip latency in milliseconds.
    pub p99_ms: f64,
    /// Total requests completed during the measurement window.
    pub samples: usize,
}

/// A pre-built KMIP request ready for the load test hot loop.
///
/// For operations with a fixed request body (encrypt, sign, batch), the TTLV
/// JSON bytes are serialized **once** at preparation time and reused on every
/// iteration.  This eliminates per-request `to_ttlv()`, `serde_json::to_vec()`,
/// `Encrypt::clone()`, `format!()` for the URL, and `from_ttlv()` for the
/// response — cutting client-side CPU per request ~80% and freeing CPU cycles
/// for the server on the same machine.
#[derive(Clone)]
enum PreparedLoadOp {
    /// Pre-serialized KMIP operation (encrypt, sign, batch).
    /// The raw JSON bytes are sent directly; only the HTTP status code is
    /// checked (response body is consumed but not parsed).
    PreSerialized {
        name: &'static str,
        url: String,
        body: Vec<u8>,
    },
    /// Pre-serialized binary TTLV (wire format).
    /// Sent with `application/octet-stream` content-type to POST /kmip.
    PreSerializedBinary {
        name: &'static str,
        url: String,
        body: Vec<u8>,
    },
    /// AES-256 symmetric key creation.  Cannot be pre-serialized because each
    /// invocation must allocate a distinct key object on the server.
    AesSymCreate { name: &'static str, vid: String },
}

impl PreparedLoadOp {
    const fn name(&self) -> &'static str {
        match self {
            Self::PreSerialized { name, .. }
            | Self::PreSerializedBinary { name, .. }
            | Self::AesSymCreate { name, .. } => name,
        }
    }

    /// Execute the operation once, returning `true` on success.
    ///
    /// For `PreSerialized` ops the request bytes are sent without any
    /// serialization, and the response body is consumed (for connection reuse)
    /// without parsing — only the status code is checked.
    async fn execute(&self, client: &KmsClient) -> bool {
        match self {
            Self::PreSerialized { url, body, .. } => {
                match client
                    .client
                    .post_bytes(url, body.clone(), "application/json")
                    .await
                {
                    Ok(resp) => resp.status.is_success(),
                    Err(_) => false,
                }
            }
            Self::PreSerializedBinary { url, body, .. } => client
                .client
                .post_bytes(url, body.clone(), "application/octet-stream")
                .await
                .is_ok_and(|resp| wire_response_ok(resp.bytes())),
            Self::AesSymCreate { vid, .. } => {
                let Ok(req) = symmetric_key_create_request(
                    vid,
                    None,
                    256,
                    CryptographicAlgorithm::AES,
                    ["load"],
                    false,
                    None,
                ) else {
                    return false;
                };
                client.create(req).await.is_ok()
            }
        }
    }
}

/// Serialize a KMIP operation to TTLV JSON bytes (one-time cost at preparation).
///
/// Wraps the operation in a `RequestMessage` — the same envelope used by the
/// binary wire path — so both protocols exercise the same server-side code path
/// (`from_ttlv::<RequestMessage>` + `message()` dispatch) and the load numbers
/// are directly comparable.
fn preserialized_op(name: &'static str, client: &KmsClient, op: Operation) -> PreparedLoadOp {
    use cosmian_kms_client::cosmian_kmip::ttlv::to_ttlv;
    let req = make_wire_request(op);
    let ttlv = to_ttlv(&req).expect("TTLV serialization");
    let body = serde_json::to_vec(&ttlv).expect("JSON serialization");
    let url = format!("{}/kmip/2_1", client.client.server_url);
    PreparedLoadOp::PreSerialized { name, url, body }
}

/// Serialize a KMIP operation to binary TTLV wire bytes (one-time cost at preparation).
/// Wraps the operation in a `RequestMessage` as required by the binary wire endpoint.
fn preserialized_wire_op(name: &'static str, client: &KmsClient, op: Operation) -> PreparedLoadOp {
    let body = to_wire_bytes(&make_wire_request(op));
    let url = format!("{}/kmip", client.client.server_url);
    PreparedLoadOp::PreSerializedBinary { name, url, body }
}

fn load_percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

pub(super) fn parse_concurrency_levels(s: &str) -> KmsCliResult<Vec<usize>> {
    s.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| {
            t.parse::<usize>()
                .map_err(|e| KmsCliError::Default(format!("Invalid concurrency level '{t}': {e}")))
        })
        .collect()
}

/// Prepare one representative operation per applicable mode category.
fn prepare_load_ops(
    rt: &Runtime,
    client: &KmsClient,
    mode: &BenchMode,
    protocol: &BenchProtocol,
    plaintext_size: usize,
) -> Vec<PreparedLoadOp> {
    let mut ops = Vec::new();
    let needs_encrypt = matches!(mode, BenchMode::Encrypt | BenchMode::All);
    let needs_key_create = matches!(mode, BenchMode::KeyCreation | BenchMode::All);
    let needs_sign = matches!(mode, BenchMode::SignVerify | BenchMode::All);
    let needs_batch = matches!(mode, BenchMode::Batch | BenchMode::All);

    let run_json = matches!(protocol, BenchProtocol::All | BenchProtocol::TtlvJson);
    let run_wire = matches!(protocol, BenchProtocol::All | BenchProtocol::TtlvBytes);
    let run_jose = matches!(protocol, BenchProtocol::All | BenchProtocol::Jose);

    // ── TTLV JSON load ops ───────────────────────────────────────────────
    if run_json && needs_encrypt {
        let key_id = create_sym_key(rt, client, 128, CryptographicAlgorithm::AES);
        let req = Encrypt {
            unique_identifier: Some(key_id),
            cryptographic_parameters: Some(aes_gcm_params()),
            data: Some(Zeroizing::new(vec![1_u8; plaintext_size])),
            ..Default::default()
        };
        ops.push(preserialized_op(
            "ttlv-json/encrypt/aes-gcm",
            client,
            Operation::Encrypt(Box::new(req)),
        ));
    }

    if run_json && needs_key_create {
        ops.push(PreparedLoadOp::AesSymCreate {
            name: "ttlv-json/key-creation/aes-sym",
            vid: client.config.vendor_id.clone(),
        });
    }

    if run_json && needs_sign {
        if let Some((_, priv_id)) = try_create_ec_kp(rt, client, RecommendedCurve::P256) {
            let req = Sign {
                unique_identifier: Some(priv_id),
                cryptographic_parameters: Some(CryptographicParameters {
                    digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                    ..Default::default()
                }),
                data: Some(Zeroizing::new(vec![0x42_u8; 32])),
                ..Default::default()
            };
            ops.push(preserialized_op(
                "ttlv-json/sign-verify/ecdsa-p256",
                client,
                Operation::Sign(req),
            ));
        } else {
            eprintln!("[load] ECDSA P-256 key creation failed, skipping sign load test");
        }
    }

    if run_json && needs_batch {
        let key_id = create_sym_key(rt, client, 128, CryptographicAlgorithm::AES);
        let key_str = key_id.to_string();
        let data = BulkData::new(vec![Zeroizing::new(vec![1_u8; plaintext_size]); 10])
            .serialize()
            .expect("BulkData serialize");
        let req = encrypt_request(
            &key_str,
            None,
            data.to_vec(),
            None,
            None,
            Some(aes_gcm_params()),
        )
        .expect("batch encrypt request");
        ops.push(preserialized_op(
            "ttlv-json/batch/aes-gcm-10",
            client,
            Operation::Encrypt(Box::new(req)),
        ));
    }

    // ── TTLV Bytes load ops ───────────────────────────────────────────────
    if run_wire && needs_encrypt {
        let key_id = create_sym_key(rt, client, 128, CryptographicAlgorithm::AES);
        let req = Encrypt {
            unique_identifier: Some(key_id),
            cryptographic_parameters: Some(aes_gcm_params()),
            data: Some(Zeroizing::new(vec![1_u8; plaintext_size])),
            ..Default::default()
        };
        ops.push(preserialized_wire_op(
            "ttlv-bytes/encrypt/aes-gcm",
            client,
            Operation::Encrypt(Box::new(req)),
        ));
    }

    if run_wire && needs_sign {
        if let Some((_, priv_id)) = try_create_ec_kp(rt, client, RecommendedCurve::P256) {
            let req = Sign {
                unique_identifier: Some(priv_id),
                cryptographic_parameters: Some(CryptographicParameters {
                    digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                    ..Default::default()
                }),
                data: Some(Zeroizing::new(vec![0x42_u8; 32])),
                ..Default::default()
            };
            ops.push(preserialized_wire_op(
                "ttlv-bytes/sign-verify/ecdsa-p256",
                client,
                Operation::Sign(req),
            ));
        }
    }

    // ── JOSE load ops ────────────────────────────────────────────────────
    if run_jose && needs_encrypt {
        if let Some(kid) = jose_create_sym_key(rt, client, "A256GCM") {
            let jose_enc_req = JoseEncReq {
                kid,
                alg: "dir",
                enc: "A256GCM",
                data: b64url(&vec![1_u8; plaintext_size]),
                aad: None,
            };
            let body = serde_json::to_vec(&jose_enc_req).expect("JOSE encrypt JSON serialization");
            let url = format!("{}/v1/crypto/encrypt", client.client.server_url);
            ops.push(PreparedLoadOp::PreSerialized {
                name: "jose/encrypt/a256gcm",
                url,
                body,
            });
        } else {
            eprintln!("[load] JOSE A256GCM key creation failed, skipping JOSE encrypt load test");
        }
    }

    if run_jose && needs_sign {
        if let Some((priv_kid, _pub_kid)) = jose_try_create_ec_kp(rt, client, "ES256", "P-256") {
            let jose_sign_req = JoseSignReq {
                kid: priv_kid,
                alg: "ES256",
                data: b64url(&[0x42_u8; 32]),
            };
            let body = serde_json::to_vec(&jose_sign_req).expect("JOSE sign JSON serialization");
            let url = format!("{}/v1/crypto/sign", client.client.server_url);
            ops.push(PreparedLoadOp::PreSerialized {
                name: "jose/sign-verify/ecdsa-p256",
                url,
                body,
            });
        } else {
            eprintln!("[load] JOSE ES256 key creation failed, skipping JOSE sign load test");
        }
    }

    ops
}

/// Spawn `concurrency` OS threads, each with a dedicated single-threaded tokio
/// runtime but all sharing a single `KmsClient` (and its underlying HTTP
/// connection pool). Each thread runs the exact same operation for `warmup`
/// duration (warming connections + server caches at target concurrency), then all
/// threads cooldown together (letting the server drain), then a `Barrier`
/// synchronizes before the timed measurement phase.
///
/// Key design choices:
/// - **Per-thread `KmsClient`**: each thread creates its own `KmsClient` (and
///   thus its own `reqwest::Client` connection pool) to avoid cross-reactor
///   connection sharing deadlocks between independent current-thread runtimes.
/// - **Per-thread single-threaded runtime**: avoids tokio multi-thread scheduler
///   overhead while preserving natural OS-thread parallelism for CPU-bound
///   crypto operations.
/// - **`Arc<PreparedLoadOp>`**: the immutable operation is shared instead of
///   cloned per thread.
fn run_load_level(
    client: &KmsClient,
    op: &PreparedLoadOp,
    concurrency: usize,
    warmup: Duration,
    cooldown: Duration,
    duration: Duration,
) -> LoadResult {
    if concurrency == 0 {
        return LoadResult {
            operation: op.name().to_owned(),
            concurrency: 0,
            throughput_rps: 0.0,
            p50_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            samples: 0,
        };
    }

    // Share the operation across threads (immutable, avoids per-thread clone).
    let shared_op = std::sync::Arc::new(op.clone());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(concurrency));

    let handles: Vec<_> = (0..concurrency)
        .map(|_| {
            // Each thread creates its own KmsClient (and thus its own reqwest
            // connection pool).  This is critical because each thread runs its
            // own single-threaded tokio runtime: connections are tied to their
            // creating runtime's I/O reactor, so sharing a pool across runtimes
            // causes deadlocks when one runtime blocks (e.g. at a Barrier).
            let client_config = client.config.clone();
            let op = shared_op.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("per-thread runtime");
                let task_client =
                    KmsClient::new_with_config(client_config).expect("per-thread KmsClient");

                // Warmup: run the exact same operation at target concurrency.
                // This warms HTTP/TLS connections AND server-side caches.
                let warmup_start = Instant::now();
                while warmup_start.elapsed() < warmup {
                    rt.block_on(async {
                        let _ = op.execute(&task_client).await;
                    });
                }

                // All threads synchronize after warmup, then cooldown together
                // to let the server drain before measurement.
                barrier.wait();
                std::thread::sleep(cooldown);
                // Second sync: all threads start the timed measurement phase together,
                // minimising clock-skew between workers.
                barrier.wait();

                // Measurement loop
                let mut timings = Vec::new();
                let task_start = Instant::now();
                while task_start.elapsed() < duration {
                    let t0 = Instant::now();
                    rt.block_on(async {
                        let _ = op.execute(&task_client).await;
                    });
                    timings.push(t0.elapsed().as_secs_f64() * 1_000.0); // ms
                }
                timings
            })
        })
        .collect();

    let mut all_timings: Vec<f64> = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok(timings) => all_timings.extend(timings),
            Err(_) => {
                eprintln!(
                    "[load] Warning: a worker thread panicked; benchmark results may be incomplete"
                );
            }
        }
    }

    let samples = all_timings.len();
    let throughput_rps = if duration.as_secs_f64() > 0.0 {
        #[allow(clippy::cast_precision_loss)]
        let s = samples as f64;
        s / duration.as_secs_f64()
    } else {
        0.0
    };
    all_timings.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    LoadResult {
        operation: op.name().to_owned(),
        concurrency,
        throughput_rps,
        p50_ms: load_percentile(&all_timings, 0.50),
        p95_ms: load_percentile(&all_timings, 0.95),
        p99_ms: load_percentile(&all_timings, 0.99),
        samples,
    }
}

/// Run each prepared operation across all concurrency levels sequentially.
#[allow(clippy::too_many_arguments)]
pub(super) fn bench_load(
    rt: &Runtime,
    client: &KmsClient,
    mode: &BenchMode,
    protocol: &BenchProtocol,
    concurrency_levels: &[usize],
    warmup: Duration,
    duration: Duration,
    cooldown: Duration,
    plaintext_size: usize,
) -> Vec<LoadResult> {
    let ops = prepare_load_ops(rt, client, mode, protocol, plaintext_size);
    if ops.is_empty() {
        eprintln!("[load] No operations prepared for mode {mode:?}");
        return Vec::new();
    }

    let mut results = Vec::new();
    for op in ops {
        eprintln!(
            "[load] '{}' — sweep {:?} × {:.0}s",
            op.name(),
            concurrency_levels,
            duration.as_secs_f64()
        );
        for &concurrency in concurrency_levels {
            eprint!(
                "[load]   concurrency={concurrency:>3} (warmup {:.0}s + cooldown {:.0}s) … ",
                warmup.as_secs_f64(),
                cooldown.as_secs_f64()
            );
            let result = run_load_level(client, &op, concurrency, warmup, cooldown, duration);
            eprintln!(
                "rps={:>8.1}  p50={:>6.1}ms  p95={:>6.1}ms  p99={:>6.1}ms  n={}",
                result.throughput_rps, result.p50_ms, result.p95_ms, result.p99_ms, result.samples
            );
            results.push(result);
        }
    }
    results
}

#[allow(clippy::print_stdout)]
pub(super) fn print_load_results(results: &[LoadResult]) {
    if results.is_empty() {
        return;
    }
    let mut seen: Vec<&str> = Vec::new();
    for r in results {
        if !seen.contains(&r.operation.as_str()) {
            seen.push(&r.operation);
        }
    }
    for op in seen {
        let op_rows: Vec<&LoadResult> = results.iter().filter(|r| r.operation == op).collect();
        println!("\n── {op} ──");
        println!(
            "{:<14} {:>12}  {:>10} {:>10} {:>10}  {:>8}",
            "Concurrency", "Throughput", "p50", "p95", "p99", "Samples"
        );
        println!("{}", "─".repeat(70));
        for r in op_rows {
            println!(
                "{:<14} {:>10.1}/s  {:>8.1}ms {:>8.1}ms {:>8.1}ms  {:>8}",
                r.concurrency, r.throughput_rps, r.p50_ms, r.p95_ms, r.p99_ms, r.samples
            );
        }
    }
}

/// Write `target/criterion/load_{protocol_slug}.json` — one JSON object per line.
///
/// Each line: `{"protocol":"…","operation":"…","concurrency":N,"throughput_rps":…,
/// "p50_ms":…,"p95_ms":…,"p99_ms":…}`
///
/// The `operation` field strips the protocol prefix so it is protocol-neutral
/// (e.g. `"ttlv-json/encrypt/aes-gcm"` → `"encrypt/aes-gcm"`).
pub(super) fn generate_load_json_output(
    results: &[LoadResult],
    protocol_slug: &str,
) -> KmsCliResult<()> {
    if results.is_empty() {
        return Ok(());
    }
    let home = criterion_home();
    fs::create_dir_all(&home)
        .map_err(|e| KmsCliError::Default(format!("Create criterion dir: {e}")))?;

    let prefix = format!("{protocol_slug}/");
    let mut lines = String::new();
    for r in results {
        let operation = r
            .operation
            .strip_prefix(&prefix)
            .unwrap_or(&r.operation)
            .to_owned();
        lines.push_str(&format!(
            "{{\"protocol\":\"{protocol_slug}\",\"operation\":\"{operation}\",\
             \"concurrency\":{},\"throughput_rps\":{:.2},\
             \"p50_ms\":{:.3},\"p95_ms\":{:.3},\"p99_ms\":{:.3}}}\n",
            r.concurrency, r.throughput_rps, r.p50_ms, r.p95_ms, r.p99_ms,
        ));
    }

    let json_path = home.join(format!("load_{protocol_slug}.json"));
    fs::write(&json_path, &lines)
        .map_err(|e| KmsCliError::Default(format!("Write {}: {e}", json_path.display())))?;
    eprintln!("[load] JSON report → {}", json_path.display());
    Ok(())
}

/// Write `target/criterion/load.md` — one combined table per operation with
/// one column per protocol (ttlv-json, ttlv-bytes, jose).
///
/// `proto_results` is a slice of `(protocol_slug, results)` pairs.
pub(super) fn generate_markdown_load_output_combined(
    proto_results: &[(&str, Vec<LoadResult>)],
) -> KmsCliResult<()> {
    if proto_results.is_empty() {
        return Ok(());
    }
    let home = criterion_home();
    fs::create_dir_all(&home)
        .map_err(|e| KmsCliError::Default(format!("Create criterion dir: {e}")))?;

    // Collect ordered list of operation suffixes across all protocols.
    let mut ops: Vec<String> = Vec::new();
    for (slug, results) in proto_results {
        let prefix = format!("{slug}/");
        for r in results {
            let op = r
                .operation
                .strip_prefix(&prefix)
                .unwrap_or(&r.operation)
                .to_owned();
            if !ops.contains(&op) {
                ops.push(op);
            }
        }
    }

    // Collect all concurrency levels (sorted).
    let mut concurrencies: Vec<usize> = Vec::new();
    for (_, results) in proto_results {
        for r in results {
            if !concurrencies.contains(&r.concurrency) {
                concurrencies.push(r.concurrency);
            }
        }
    }
    concurrencies.sort_unstable();

    let slugs: Vec<&str> = proto_results.iter().map(|(s, _)| *s).collect();
    let sep_line = {
        let mut sep = "|-------------|".to_owned();
        for _ in &slugs {
            sep.push_str("-----------------|");
        }
        sep
    };

    let mut md = String::new();
    for op in &ops {
        md.push_str(&format!("### {op}\n\n"));
        let mut header = "| Concurrency |".to_owned();
        for slug in &slugs {
            header.push_str(&format!(" {slug} (req/s) |"));
        }
        md.push_str(&header);
        md.push('\n');
        md.push_str(&sep_line);
        md.push('\n');

        for &conc in &concurrencies {
            let mut row = format!("| {conc:<11} |");
            for (slug, results) in proto_results {
                let prefix = format!("{slug}/");
                let rps = results
                    .iter()
                    .find(|r| {
                        r.concurrency == conc
                            && r.operation.strip_prefix(&prefix).unwrap_or(&r.operation) == op
                    })
                    .map_or_else(|| "-".to_owned(), |r| format!("{:.1}", r.throughput_rps));
                row.push_str(&format!(" {rps:<15} |"));
            }
            md.push_str(&row);
            md.push('\n');
        }
        md.push('\n');
    }

    let md_path = home.join("load.md");
    fs::write(&md_path, &md)
        .map_err(|e| KmsCliError::Default(format!("Write {}: {e}", md_path.display())))?;
    eprintln!("[load] Combined markdown report → {}", md_path.display());
    Ok(())
}

/// Generate `target/criterion/load-report/index.html` with gnuplot SVG charts.
///
/// If `gnuplot` is not on PATH, the HTML is still written but without charts.
pub(super) fn generate_html_output(results: &[LoadResult]) -> KmsCliResult<()> {
    let home = criterion_home();
    let report_dir = home.join("load-report");
    fs::create_dir_all(&report_dir)
        .map_err(|e| KmsCliError::Default(format!("Create report dir: {e}")))?;

    let mut ops: Vec<String> = Vec::new();
    for r in results {
        if !ops.contains(&r.operation) {
            ops.push(r.operation.clone());
        }
    }

    let gnuplot_ok = std::process::Command::new("gnuplot")
        .arg("--version")
        .output()
        .is_ok();
    if !gnuplot_ok {
        eprintln!("[load] gnuplot not found — SVG charts will be omitted from HTML report");
    }

    let mut sections = String::new();
    for op in &ops {
        let safe = op.replace('/', "_").replace(' ', "-");
        let op_rows: Vec<&LoadResult> = results.iter().filter(|r| &r.operation == op).collect();

        // ── .dat file ────────────────────────────────────────────────────
        let dat_name = format!("{safe}.dat");
        let dat_path = report_dir.join(&dat_name);
        let mut dat =
            String::from("# concurrency  throughput_rps  p50_ms  p95_ms  p99_ms  samples\n");
        for r in &op_rows {
            dat.push_str(&format!(
                "{:<14} {:<15.2} {:<8.2} {:<8.2} {:<8.2} {}\n",
                r.concurrency, r.throughput_rps, r.p50_ms, r.p95_ms, r.p99_ms, r.samples
            ));
        }
        fs::write(&dat_path, &dat)
            .map_err(|e| KmsCliError::Default(format!("Write {}: {e}", dat_path.display())))?;

        // ── gnuplot charts ────────────────────────────────────────────────
        let tp_svg = format!("{safe}-throughput.svg");
        let lat_svg = format!("{safe}-latency.svg");
        if gnuplot_ok {
            let run_gnuplot = |script: &str, label: &str| {
                let script_name = format!("{safe}-{label}.gnuplot");
                let script_path = report_dir.join(&script_name);
                if fs::write(&script_path, script).is_ok() {
                    let status = std::process::Command::new("gnuplot")
                        .arg(&script_name)
                        .current_dir(&report_dir)
                        .status();
                    if status.map_or(true, |s| !s.success()) {
                        eprintln!("[load] gnuplot {label} chart failed for {op}");
                    }
                }
            };

            run_gnuplot(
                &format!(
                    "set terminal svg size 800,400 enhanced font 'Helvetica,12'\n\
                     set output '{tp_svg}'\n\
                     set title 'Throughput — {op}'\n\
                     set xlabel 'Concurrency'\n\
                     set ylabel 'req/s'\n\
                     set grid\nset key top left\n\
                     plot '{dat_name}' using 1:2 with linespoints lw 2 pt 7 title 'throughput'\n"
                ),
                "throughput",
            );

            run_gnuplot(
                &format!(
                    "set terminal svg size 800,400 enhanced font 'Helvetica,12'\n\
                     set output '{lat_svg}'\n\
                     set title 'Latency — {op}'\n\
                     set xlabel 'Concurrency'\n\
                     set ylabel 'Latency (ms)'\n\
                     set grid\nset key top left\n\
                     plot '{dat_name}' using 1:3 with linespoints lw 2 pt 7 title 'p50', \\\n\
                          '{dat_name}' using 1:4 with linespoints lw 2 pt 5 title 'p95', \\\n\
                          '{dat_name}' using 1:5 with linespoints lw 2 pt 9 title 'p99'\n"
                ),
                "latency",
            );
        }

        // ── HTML section ──────────────────────────────────────────────────
        sections.push_str(&format!("<section>\n<h2>{op}</h2>\n"));
        if gnuplot_ok {
            sections.push_str(&format!(
                "<div class=\"charts\">\
                 <img src=\"{tp_svg}\" alt=\"Throughput\">\
                 <img src=\"{lat_svg}\" alt=\"Latency\">\
                 </div>\n"
            ));
        }
        sections.push_str(
            "<table>\n<tr><th>Concurrency</th><th>Throughput (req/s)</th>\
             <th>p50 (ms)</th><th>p95 (ms)</th><th>p99 (ms)</th><th>Samples</th></tr>\n",
        );
        for r in &op_rows {
            sections.push_str(&format!(
                "<tr><td>{}</td><td>{:.1}</td><td>{:.1}</td>\
                 <td>{:.1}</td><td>{:.1}</td><td>{}</td></tr>\n",
                r.concurrency, r.throughput_rps, r.p50_ms, r.p95_ms, r.p99_ms, r.samples
            ));
        }
        sections.push_str("</table>\n</section>\n");
    }

    let gnuplot_notice = if gnuplot_ok {
        String::new()
    } else {
        String::from(
            "<p class=\"warn\">⚠ <code>gnuplot</code> not found — charts were not generated. \
             Install gnuplot and re-run <code>ckms bench --load --format html</code>.</p>\n",
        )
    };

    let html = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <title>KMS Load Test Report</title>\n<style>\n\
         body{{font-family:sans-serif;max-width:1400px;margin:0 auto;padding:1em 2em}}\n\
         h1{{border-bottom:2px solid #333;padding-bottom:.3em}}\n\
         h2{{border-bottom:1px solid #ccc;margin-top:2em;color:#222}}\n\
         table{{border-collapse:collapse;margin:1em 0}}\n\
         th,td{{border:1px solid #bbb;padding:.35em .75em}}\n\
         th{{background:#f4f4f4;text-align:center;font-weight:600}}\n\
         td{{text-align:right}}\n\
         td:first-child{{text-align:center}}\n\
         .charts{{display:flex;gap:1em;flex-wrap:wrap;margin:.5em 0}}\n\
         .charts img{{max-width:49%;min-width:280px;border:1px solid #ddd}}\n\
         pre{{background:#f8f8f8;padding:1em;overflow-x:auto;font-size:.85em}}\n\
         .warn{{background:#fff3cd;border:1px solid #ffc107;padding:.5em 1em;border-radius:4px}}\n\
         section{{margin-bottom:2em}}\n\
         </style>\n</head>\n<body>\n\
         <h1>KMS Load Test Report</h1>\n\
         {gnuplot_notice}\
         {sections}\
         </body>\n</html>\n"
    );

    let html_path = report_dir.join("index.html");
    fs::write(&html_path, &html)
        .map_err(|e| KmsCliError::Default(format!("Write {}: {e}", html_path.display())))?;
    eprintln!("[load] HTML report → {}", html_path.display());
    Ok(())
}

// =============================================================================
