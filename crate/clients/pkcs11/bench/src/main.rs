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

mod criterion_bench;
mod error;
mod load;
mod loader;
mod overhead;
mod report;
mod setup;

use std::time::Duration;

use clap::Parser;
use criterion_bench::{BenchSpeed, CriterionRunConfig, PayloadMode, run_criterion};
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

    /// Force every concurrent worker thread to share a **single** Cryptoki session
    /// (the pre-fix behavior) instead of giving each thread its own dedicated
    /// session (the default). Since
    /// `crate/clients/pkcs11/module/src/sessions.rs` now locks each session
    /// independently rather than behind one process-wide lock, this flag exists
    /// purely to reproduce the old single-session-contention numbers for direct
    /// before/after comparison — it does not reflect how a well-behaved,
    /// high-concurrency PKCS#11 consumer would actually use the provider.
    #[arg(long)]
    shared_session: bool,

    /// Run real `criterion`-crate single-operation micro-benchmarks instead of the
    /// concurrency sweep — much faster to iterate on (no warmup/cooldown per
    /// concurrency level) and gives statistically rigorous per-call latency
    /// (mean/median/CI), at the cost of not measuring concurrent-load behavior.
    /// Writes `criterion.json`, not `load_pkcs11.json`, so the generated report
    /// contains only the "Criterion data" section.
    #[arg(long)]
    criterion: bool,

    /// Criterion speed preset (only used with `--criterion`).
    #[arg(long, value_enum, default_value_t = BenchSpeed::Quick)]
    speed: BenchSpeed,

    /// Ed25519 payload size for differential Criterion tiers.
    #[arg(long, default_value_t = 32)]
    overhead_payload_size: usize,

    /// Payload selection for typed and PKCS#11 overhead tiers.
    #[arg(long, value_enum, default_value_t = PayloadMode::Fixed)]
    overhead_payload_mode: PayloadMode,
}

fn parse_concurrency(spec: &str) -> BenchResult<Vec<usize>> {
    spec.split(',')
        .map(|s| {
            let value = s.trim().parse::<usize>().map_err(|e| {
                error::BenchError::Setup(format!("invalid --concurrency value: {e}"))
            })?;
            if value == 0 {
                return Err(error::BenchError::Setup(
                    "--concurrency values must be at least 1".to_owned(),
                ));
            }
            Ok(value)
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
    let modes = cli.mode.expand();
    if modes.is_empty() {
        return Err(error::BenchError::Setup(
            "EdDSA benchmark modes require the non-fips feature".to_owned(),
        ));
    }
    let provision_ed25519 = modes.iter().any(|mode| {
        matches!(
            mode,
            load::ConcreteMode::SignEdDsa | load::ConcreteMode::VerifyEdDsa
        )
    });

    // Provision the benchmark keys via the KMS REST API before opening the
    // Cryptoki session — needs its own (short-lived) Tokio runtime since the rest
    // of this binary is a plain synchronous FFI hot loop.
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| error::BenchError::Setup(format!("failed to start Tokio runtime: {e}")))?;
    let setup = runtime.block_on(setup::provision_bench_keys(&cli.kms_url, provision_ed25519))?;

    let lib = Pkcs11Lib::load(&cli.pkcs11_lib)?;

    // One dedicated session per worker thread the sweep will ever spawn (the
    // highest requested concurrency level), so no thread ever waits on another
    // thread's session lock — unless `--shared-session` asks to reproduce the old
    // everyone-shares-one-handle model instead. `--criterion` only ever uses one
    // session (see `criterion_bench::run_criterion`), so a single-session pool is
    // sufficient there too. `Pkcs11Session::open` is cheap (no network I/O;
    // `C_Initialize` itself only actually runs once, see its own doc comment) and
    // all opened here sequentially on this thread, before any worker thread exists.
    let pool_size = if cli.shared_session || cli.criterion {
        1
    } else {
        config.concurrency_levels.iter().copied().max().unwrap_or(1)
    };
    let pool = (0..pool_size)
        .map(|_| Pkcs11Session::open(&lib))
        .collect::<BenchResult<Vec<_>>>()?;

    if cli.criterion {
        // `--criterion` measures single-operation latency only — no load sweep, no
        // `load_pkcs11.json`, so the generated report contains only the "Criterion
        // data" section (see `mise bench:load-pkcs11 --criterion --help`).
        return run_criterion(
            modes,
            &pool,
            &runtime,
            &setup.client,
            setup.ed25519_private_key_id.as_ref(),
            &CriterionRunConfig {
                speed: cli.speed,
                measurement_time: config.measure_time,
                overhead_payload_size: cli.overhead_payload_size,
                overhead_payload_mode: cli.overhead_payload_mode,
            },
        );
    }

    let results = run_all(modes, &pool, &config)?;

    print_results(&results);
    report::write_load_json(&results)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_concurrency;

    #[test]
    fn rejects_zero_concurrency() {
        for input in ["0", "1,0,2"] {
            assert_eq!(
                parse_concurrency(input)
                    .err()
                    .map(|error| error.to_string())
                    .as_deref(),
                Some("benchmark error: --concurrency values must be at least 1")
            );
        }
    }

    #[test]
    fn parses_positive_concurrency_levels() {
        assert_eq!(parse_concurrency("1, 2,8").ok(), Some(vec![1, 2, 8]));
    }
}
