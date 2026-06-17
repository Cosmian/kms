#![allow(clippy::format_push_string)]

use std::cell::RefCell;

use clap::{Parser, ValueEnum};

thread_local! {
    /// Benchmarks that were skipped (server does not support the algorithm).
    /// Only KO events need explicit tracking; OKs are read from criterion output.
    pub(super) static BENCH_KO: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Record a benchmark name as skipped/unsupported (for compact output).
pub(super) fn bench_ko(name: impl Into<String>) {
    BENCH_KO.with(|r| r.borrow_mut().push(name.into()));
}

/// Reset the KO accumulator before a new benchmark run.
pub(super) fn bench_ko_reset() {
    BENCH_KO.with(|r| r.borrow_mut().clear());
}

/// Output format for benchmark results (aligned with cargo-criterion).
#[derive(Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum BenchFormat {
    /// Criterion console output with HTML reports in target/criterion/
    #[default]
    Text,
    /// Collect criterion estimates and write JSON to target/criterion/benchmarks.json
    Json,
    /// Generate markdown tables from criterion estimates (embedded criterion-table)
    Markdown,
    /// One line per benchmark: name + OK/KO. Criterion output is suppressed.
    /// Automatically selected when --sanity is used without an explicit --format.
    Compact,
    /// Produce a unified HTML report with gnuplot SVG charts for load tests and
    /// embedded criterion markdown tables for statistical benchmarks.
    /// Requires `gnuplot` on PATH; falls back to a data table if not found.
    /// Primarily useful with `--load`.
    Html,
}

/// Benchmark speed / sampling mode.
#[derive(Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum BenchSpeed {
    /// 100 samples, configurable measurement time (--time), 3 s warmup.
    #[default]
    Normal,
    /// 10 samples, 1 s measurement, 0.5 s warmup.
    Quick,
    /// Smoke-test: 10 samples (criterion minimum), 1 ms measurement, 1 ms warmup.
    /// Automatically selects --format compact when no explicit format is given.
    Sanity,
}

/// Benchmark mode selection (operation category).
#[derive(Clone, Debug, Default, ValueEnum)]
pub(crate) enum BenchMode {
    /// Run ALL benchmark categories in order
    #[default]
    All,
    /// Encrypt/decrypt: AES-GCM, `ChaCha20` (non-FIPS), RSA-OAEP, RSA-AES-KWP, RSA-PKCS1v15 (non-FIPS)
    Encrypt,
    /// Key creation: symmetric, RSA, EC key pairs
    KeyCreation,
    /// Sign/verify: ECDSA, `EdDSA` (non-FIPS), RSA-PSS, ML-DSA, SLH-DSA (non-FIPS)
    SignVerify,
    /// KMIP Message batch: AES `BulkData`, RSA KMIP Message
    Batch,
}

/// Benchmark protocol / transport selection.
#[derive(Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
pub(crate) enum BenchProtocol {
    /// Run all protocols: TTLV JSON + TTLV Bytes + JOSE
    #[default]
    All,
    /// KMIP over JSON-serialized TTLV (`POST /kmip/2_1`, `application/json`)
    TtlvJson,
    /// KMIP over binary TTLV wire format (`POST /kmip`, `application/octet-stream`)
    TtlvBytes,
    /// REST JOSE endpoints (`POST /v1/crypto/*`, `application/json`)
    Jose,
}

impl BenchProtocol {
    /// Return the individual protocols to iterate when generating per-protocol reports.
    pub(super) const fn protocols(&self) -> &[Self] {
        match self {
            Self::All => &[Self::TtlvJson, Self::TtlvBytes, Self::Jose],
            _ => std::slice::from_ref(self),
        }
    }

    /// Filename-safe slug for output files (e.g. `"benchmarks_kmip-json.json"`).
    pub(super) const fn slug(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::TtlvJson => "ttlv-json",
            Self::TtlvBytes => "ttlv-bytes",
            Self::Jose => "jose",
        }
    }
}

/// Run benchmarks using criterion for statistical analysis.
///
/// Connects to an external KMS server and runs criterion benchmarks.
/// Results include mean, median, standard deviation, and confidence intervals.
/// HTML reports are generated in `target/criterion/`.
///
/// Examples:
///   ckms bench                                        # all modes + all protocols
///   ckms bench --mode encrypt                         # encrypt mode only (all protocols)
///   ckms bench --mode encrypt --protocol jose         # JOSE encrypt only
///   ckms bench --protocol ttlv-bytes                  # all modes over binary TTLV
///   ckms bench --speed sanity                         # smoke-test: compact output
///   ckms bench --mode key-creation --speed quick      # quick run
///   ckms bench --format json                          # also write JSON results
///   ckms bench --load                                 # load test all ops, concurrency 1-32
///   ckms bench --mode encrypt --load                  # load test encrypt only
///   ckms bench --protocol jose --load                 # JOSE load test
///   ckms bench --load --format html                   # gnuplot HTML report
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct BenchAction {
    /// Benchmark category (default: all)
    #[clap(long = "mode", short = 'm', default_value = "all")]
    pub(super) mode: BenchMode,

    /// Protocol / transport to benchmark (default: all).
    /// - `ttlv-json`: KMIP over JSON TTLV (`POST /kmip/2_1`)
    /// - `ttlv-bytes`: KMIP over binary TTLV (`POST /kmip`)
    /// - `jose`: REST JOSE endpoints (`POST /v1/crypto/*`)
    #[clap(long = "protocol", short = 'p', default_value = "all")]
    pub(super) protocol: BenchProtocol,

    /// Output format
    #[clap(long = "format", short = 'f', default_value = "text")]
    pub(super) format: BenchFormat,

    /// Benchmark speed mode: normal (default), quick, or sanity.
    /// Sanity auto-selects --format compact when no explicit format is given.
    #[clap(long = "speed", short = 's', default_value = "normal")]
    pub(super) speed: BenchSpeed,

    /// Maximum measurement time per benchmark in seconds (default: 10).
    /// Caps how long criterion spends on each benchmark function.
    /// Ignored in quick and sanity speed modes.
    #[clap(long = "time", short = 't', default_value = "10")]
    pub(super) time: u64,

    /// Save results under a named baseline in target/criterion/<bench>/<name>/.
    /// Use this to snapshot a run before a change. To compare, run again with
    /// --load-baseline <name> (or without any flag to diff against "base").
    /// Example: --save-baseline before-my-change
    #[clap(long = "save-baseline")]
    pub(super) save_baseline: Option<String>,

    /// Compare results against a previously saved baseline.
    /// Prints change% in console output for each benchmark.
    /// Example: --load-baseline before-my-change
    #[clap(long = "load-baseline")]
    pub(super) load_baseline: Option<String>,

    /// When emitting --format json, insert this label as the version column so
    /// that criterion-table renders versions as columns for proper comparison.
    /// Run baseline first, compare second, then combine:
    ///   cat v5.12.json v5.17.json | criterion-table > diff.md
    #[clap(long = "version-label")]
    pub(super) version_label: Option<String>,

    /// Run concurrent load tests instead of criterion statistical benchmarks.
    /// Measures throughput (req/s) and latency percentiles (p50/p95/p99) at
    /// increasing concurrency levels. Can be combined with --mode to focus on
    /// specific operations. Use --format html to produce a gnuplot HTML report.
    #[clap(long = "load", default_value = "false")]
    pub(super) load: bool,

    /// Comma-separated concurrency levels for load testing.
    /// Only used when --load is set.
    #[clap(long = "load-concurrency", default_value = "1,2,4,8,16,32")]
    pub(super) load_concurrency: String,

    /// Warmup time in seconds before benchmarking starts.
    /// Sends requests for this duration to warm HTTP connection pools,
    /// TLS sessions, and server-side caches. Set to 0 to skip.
    #[clap(long = "warmup-time", default_value = "20")]
    pub(super) warmup_time: u64,

    /// Cooldown time in seconds between load-test concurrency levels.
    /// Lets the server drain TCP `TIME_WAIT` sockets, checkpoint `SQLite` WAL,
    /// and release memory before the next level starts fresh.
    #[clap(long = "cooldown-time", default_value = "20")]
    pub(super) cooldown_time: u64,
}
