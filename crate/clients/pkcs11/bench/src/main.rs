//! `pkcs11_bench` — real `dlopen()`-based load benchmark for the `cosmian_pkcs11`
//! PKCS#11 provider.
//!
//! Unlike `mise bench:load` (which load-tests the KMIP REST API directly through
//! `KmsClient`), this binary drives the *actual* Cryptoki C API of the built
//! `cosmian_pkcs11` shared library — the same call path real-world consumers
//! (Oracle TDE, OpenSSH, disk-encryption tools, ...) use.

// This entire binary exists to call raw Cryptoki C functions through a `dlopen()`ed
// function-pointer table (see `loader.rs`), matching the same crate-level allowance
// used by `cosmian_pkcs11_module` (`crate/clients/pkcs11/module/src/lib.rs`) for the
// same reason. Every individual `unsafe` block still carries its own `// SAFETY:`
// comment per the cardinal rule.
//
// The remaining allows mirror `crate/clients/clap/src/actions/bench/mod.rs`'s own
// benchmark-module allow list: statistics/timing/FFI code in a load-sweep benchmark
// is inherently full of numeric casts, direct indexing after an explicit bounds
// check, and stdout table printing.
#![allow(
    unsafe_code,
    non_snake_case,
    clippy::as_conversions,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::format_push_string
)]

mod error;
mod load;
mod loader;
mod report;
mod setup;

use std::time::Duration;

use clap::Parser;
use error::BenchResult;
use load::{BenchMode, LoadResult, SweepConfig, run_all};
use loader::{Pkcs11Lib, Pkcs11Session};

/// Real PKCS#11 (`dlopen()`) load benchmark for the `cosmian_pkcs11` provider.
#[derive(Parser, Debug)]
#[command(name = "pkcs11_bench", version, about)]
struct Cli {
    /// Path to the built `cosmian_pkcs11` shared library
    /// (`libcosmian_pkcs11.so` / `.dylib`).
    #[arg(long)]
    pkcs11_lib: String,

    /// URL of a running KMS server, used only to provision the benchmark keys
    /// before the Cryptoki hot loop starts.
    #[arg(long, default_value = "http://127.0.0.1:9998")]
    kms_url: String,

    /// Which operation family to benchmark.
    #[arg(long, value_enum, default_value_t = BenchMode::All)]
    mode: BenchMode,

    /// Comma-separated concurrency levels to sweep, e.g. "1,2,4,8,16".
    #[arg(long, default_value = "1,2,4,8,16")]
    concurrency: String,

    /// Measurement time per concurrency level, in seconds.
    #[arg(long, default_value_t = 20)]
    time: u64,

    /// Warmup time before each concurrency level's measurement, in seconds.
    #[arg(long, default_value_t = 5)]
    warmup: u64,

    /// Cooldown time between concurrency levels, in seconds.
    #[arg(long, default_value_t = 2)]
    cooldown: u64,

    /// Quick smoke test: 2s/level, concurrency=1,2, no warmup/cooldown,
    /// mode=encrypt (unless `--mode` was explicitly overridden).
    #[arg(long)]
    sanity: bool,
}

fn parse_concurrency(spec: &str) -> BenchResult<Vec<usize>> {
    spec.split(',')
        .map(|s| {
            s.trim()
                .parse::<usize>()
                .map_err(|e| error::BenchError::Setup(format!("invalid --concurrency value: {e}")))
        })
        .collect()
}

#[allow(clippy::print_stdout)]
fn print_results(results: &[LoadResult]) {
    println!(
        "{:<18} {:>12} {:>14} {:>10} {:>10} {:>10} {:>10}",
        "operation", "concurrency", "throughput/s", "p50 (ms)", "p95 (ms)", "p99 (ms)", "samples"
    );
    for r in results {
        println!(
            "{:<18} {:>12} {:>14.1} {:>10.3} {:>10.3} {:>10.3} {:>10}",
            r.operation, r.concurrency, r.throughput_ops, r.p50_ms, r.p95_ms, r.p99_ms, r.samples
        );
    }
}

fn main() -> BenchResult<()> {
    cosmian_logger::log_init(None);
    let mut cli = Cli::parse();

    let concurrency_levels = if cli.sanity {
        cli.time = 2;
        cli.warmup = 0;
        cli.cooldown = 0;
        vec![1, 2]
    } else {
        parse_concurrency(&cli.concurrency)?
    };

    let config = SweepConfig {
        concurrency_levels,
        measure_time: Duration::from_secs(cli.time),
        warmup_time: Duration::from_secs(cli.warmup),
        cooldown_time: Duration::from_secs(cli.cooldown),
    };

    // Provision the benchmark keys via the KMS REST API before opening the
    // Cryptoki session — needs its own (short-lived) Tokio runtime since the rest
    // of this binary is a plain synchronous FFI hot loop.
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| error::BenchError::Setup(format!("failed to start Tokio runtime: {e}")))?;
    runtime.block_on(setup::provision_bench_keys(&cli.kms_url))?;

    let lib = Pkcs11Lib::load(&cli.pkcs11_lib)?;
    let session = Pkcs11Session::open(&lib)?;

    let modes = cli.mode.expand();
    let results = run_all(modes, &session, &config)?;

    print_results(&results);
    report::write_load_json(&results)?;
    Ok(())
}
