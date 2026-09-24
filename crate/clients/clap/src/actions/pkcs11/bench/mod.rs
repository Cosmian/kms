//! `ckms pkcs11 bench` — real `dlopen()`-based load benchmark for the `cosmian_pkcs11`
//! PKCS#11 provider.
//!
//! Unlike `ckms bench` (which load-tests the KMIP REST API directly through
//! `KmsClient`), this command drives the *actual* Cryptoki C API of the built
//! `cosmian_pkcs11` shared library — the same call path real-world consumers
//! (Oracle TDE, OpenSSH, disk-encryption tools, ...) use.

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

pub(crate) mod criterion_bench;
pub(crate) mod error;
pub(crate) mod load;
pub(crate) mod loader;
pub(crate) mod overhead;
pub(crate) mod report;
pub(crate) mod setup;

use std::{
    env,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use clap::Parser;
use cosmian_kms_client::KmsClient;
use criterion_bench::{BenchSpeed, CriterionRunConfig, PayloadMode, run_criterion};
pub(crate) use error::{BenchError, BenchResult};
use load::{LoadResult, SweepConfig, expand_bench_mode, run_all};
use loader::{Pkcs11Lib, Pkcs11Session};

use crate::{
    actions::bench::types::{BenchFilter, BenchMode},
    error::{KmsCliError, result::KmsCliResult},
};

// Thread-safe configuration for CKMS_CONF environment variable
static CKMS_CONF_LOCK: Mutex<()> = Mutex::new(());

/// Real PKCS#11 (`dlopen()`) load benchmark for the `cosmian_pkcs11` provider.
#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)] // CLI flag structs legitimately have many boolean flags
pub struct Pkcs11BenchAction {
    /// Path to the PKCS#11 shared library (`libcosmian_pkcs11.so` / `.dylib` / `.dll`).
    #[arg(long, value_name = "PATH")]
    pub(crate) dll: PathBuf,

    /// Explicit path to `ckms.toml`. When set, the `CKMS_CONF` environment
    /// variable is written before the library is loaded so that the provider
    /// picks up this configuration file.
    #[arg(long, value_name = "PATH")]
    pub(crate) conf: Option<PathBuf>,

    /// Bearer token (OIDC/JWT) to pass to `C_Login`.
    /// Required when `ckms.toml` has `pkcs11_use_pin_as_access_token = true`.
    /// Accepted for interface parity with other `ckms pkcs11` subcommands.
    #[arg(long, value_name = "JWT")]
    pub(crate) token: Option<String>,

    /// Which operation family to benchmark.
    #[arg(long, value_enum, default_value_t = BenchMode::All)]
    pub(crate) mode: BenchMode,
    /// Algorithm and key-size filtering options
    #[clap(flatten)]
    pub(crate) filter: BenchFilter,

    /// Benchmark crypto operations executed directly on the HSM (`CryptoOracle`)
    /// via HSM-resident keys (`hsm::<slot>::...`), instead of software keys.
    #[arg(long, short = 'd')]
    pub(crate) delegated: bool,

    /// HSM slot ID used to build `hsm::<slot>::` unique identifiers with `--delegated`.
    #[arg(long, default_value_t = 0)]
    pub(crate) hsm_slot: usize,

    /// Comma-separated concurrency levels to sweep, e.g. "1,2,4,8,16".
    #[arg(long, default_value = "1,2,4,8,16")]
    pub(crate) concurrency: String,

    /// Measurement time per concurrency level, in seconds.
    #[arg(long, default_value_t = 20)]
    pub(crate) time: u64,

    /// Warmup time before each concurrency level's measurement, in seconds.
    #[arg(long, default_value_t = 5)]
    pub(crate) warmup: u64,

    /// Cooldown time between concurrency levels, in seconds.
    #[arg(long, default_value_t = 2)]
    pub(crate) cooldown: u64,

    /// Quick smoke test: 2s/level, concurrency=1,2, no warmup/cooldown,
    /// mode=encrypt (unless `--mode` was explicitly overridden).
    #[arg(long)]
    pub(crate) sanity: bool,

    /// Force every concurrent worker thread to share a **single** Cryptoki session
    /// (the pre-fix behavior) instead of giving each thread its own dedicated
    /// session (the default). Since
    /// `crate/clients/pkcs11/module/src/sessions.rs` now locks each session
    /// independently rather than behind one process-wide lock, this flag exists
    /// purely to reproduce the old single-session-contention numbers for direct
    /// before/after comparison — it does not reflect how a well-behaved,
    /// high-concurrency PKCS#11 consumer would actually use the provider.
    #[arg(long)]
    pub(crate) shared_session: bool,

    /// Also run real `criterion`-crate single-operation micro-benchmarks, on top of
    /// the concurrency sweep that always runs — gives statistically rigorous
    /// per-call latency (mean/median/CI) in addition to the sweep's
    /// concurrent-load throughput/percentiles. Writes `criterion.json` alongside
    /// `load_pkcs11.json`, so the generated report gets both a "Load Tests" and a
    /// "Criterion Benchmarks" section from a single invocation.
    #[arg(long)]
    pub(crate) criterion: bool,

    /// Criterion speed preset (only used with `--criterion`).
    #[arg(long, value_enum, default_value_t = BenchSpeed::Quick)]
    pub(crate) speed: BenchSpeed,

    /// Also run the Ed25519-specific differential overhead ladder (request
    /// construction, TTLV serialization, raw HTTP tiers, PKCS#11 `C_SignMessage`,
    /// internal phase boundaries — see `overhead.rs`) and write
    /// `pkcs11_overhead.json`. Only used with `--criterion` and when an `EdDSA` sign
    /// mode is selected. This is a standalone local diagnostic for investigating
    /// Ed25519 signing overhead specifically — it is not part of the standard
    /// report pipeline and is never rendered into `report.md`.
    #[arg(long)]
    pub(crate) overhead: bool,

    /// Ed25519 payload size for differential Criterion tiers (only used with
    /// `--overhead`).
    #[arg(long, default_value_t = 32)]
    pub(crate) overhead_payload_size: usize,

    /// Payload selection for typed and PKCS#11 overhead tiers (only used with
    /// `--overhead`).
    #[arg(long, value_enum, default_value_t = PayloadMode::Fixed)]
    pub(crate) overhead_payload_mode: PayloadMode,
}

fn parse_concurrency(spec: &str) -> BenchResult<Vec<usize>> {
    spec.split(',')
        .map(|s| {
            let value = s
                .trim()
                .parse::<usize>()
                .map_err(|e| BenchError::Setup(format!("invalid --concurrency value: {e}")))?;
            if value == 0 {
                return Err(BenchError::Setup(
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

impl Pkcs11BenchAction {
    pub(crate) async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let config = kms_rest_client.config.clone();
        drop(kms_rest_client);

        let mut time = self.time;
        let mut warmup = self.warmup;
        let mut cooldown = self.cooldown;

        let concurrency_levels = if self.sanity {
            time = 2;
            warmup = 0;
            cooldown = 0;
            vec![1, 2]
        } else {
            parse_concurrency(&self.concurrency).map_err(|e| KmsCliError::Default(e.to_string()))?
        };

        let sweep_config = SweepConfig {
            concurrency_levels,
            measure_time: Duration::from_secs(time),
            warmup_time: Duration::from_secs(warmup),
            cooldown_time: Duration::from_secs(cooldown),
        };

        let modes = expand_bench_mode(self.mode, Some(&self.filter));
        if modes.is_empty() {
            return Err(KmsCliError::Default(
                "No benchmark operations matched the selected mode and filter".to_owned(),
            ));
        }

        let provision_ed25519 = modes.iter().any(|mode| {
            matches!(
                mode,
                load::ConcreteMode::SignEdDsa | load::ConcreteMode::VerifyEdDsa
            )
        });
        let provision_secp256k1 = modes.iter().any(|mode| {
            matches!(
                mode,
                load::ConcreteMode::SignSecp256k1 | load::ConcreteMode::VerifySecp256k1
            )
        });

        let dll = self.dll.clone();
        let conf = self.conf.clone();
        let _token = self.token.clone();
        let shared_session = self.shared_session;
        let criterion = self.criterion;
        let speed = self.speed;
        let overhead = self.overhead;
        let overhead_payload_size = self.overhead_payload_size;
        let overhead_payload_mode = self.overhead_payload_mode;
        let delegated = self.delegated;
        let hsm_slot = self.hsm_slot;

        tokio::task::spawn_blocking(move || -> KmsCliResult<()> {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| KmsCliError::Default(format!("failed to start Tokio runtime: {e}")))?;
            let client = KmsClient::new_with_config(config)
                .map_err(|e| KmsCliError::Default(e.to_string()))?;

            let setup = rt
                .block_on(setup::provision_bench_keys(
                    &client,
                    provision_ed25519,
                    provision_secp256k1,
                    delegated,
                    hsm_slot,
                ))
                .map_err(|e| KmsCliError::Default(e.to_string()))?;

            let _guard = CKMS_CONF_LOCK
                .lock()
                .map_err(|_lock_err| KmsCliError::Default("CKMS_CONF_LOCK poisoned".to_owned()))?;
            if let Some(conf_path) = conf {
                // SAFETY: protected by mutex to ensure exclusive access to environment variables
                unsafe { env::set_var("CKMS_CONF", conf_path) };
            }

            let dll_str = dll.to_str().ok_or_else(|| {
                KmsCliError::Default(format!("Invalid DLL path: {}", dll.display()))
            })?;
            let lib = Pkcs11Lib::load(dll_str).map_err(|e| KmsCliError::Default(e.to_string()))?;

            let pool_size = if shared_session {
                1
            } else {
                sweep_config
                    .concurrency_levels
                    .iter()
                    .copied()
                    .max()
                    .unwrap_or(1)
            };
            let hsm_prefix = delegated.then(|| Arc::<str>::from(format!("hsm::{hsm_slot}")));
            let pool = (0..pool_size)
                .map(|_| Pkcs11Session::open(&lib, hsm_prefix.clone()))
                .collect::<BenchResult<Vec<_>>>()
                .map_err(|e| KmsCliError::Default(e.to_string()))?;

            let results = run_all(&modes, &pool, &sweep_config)
                .map_err(|e| KmsCliError::Default(e.to_string()))?;
            print_results(&results);
            report::write_load_json(&results).map_err(|e| KmsCliError::Default(e.to_string()))?;

            if criterion {
                run_criterion(
                    &modes,
                    &pool,
                    &rt,
                    &client,
                    setup.ed25519_private_key_id.as_ref(),
                    &CriterionRunConfig {
                        speed,
                        measurement_time: sweep_config.measure_time,
                        overhead_payload_size,
                        overhead_payload_mode,
                        overhead,
                    },
                )
                .map_err(|e| KmsCliError::Default(e.to_string()))?;
            }

            Ok(())
        })
        .await
        .map_err(|e| KmsCliError::Default(format!("Benchmark task panicked: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Pkcs11BenchAction, parse_concurrency};

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

    #[test]
    fn parses_delegated_hsm_slot() {
        let action = Pkcs11BenchAction::try_parse_from([
            "bench",
            "--dll",
            "/tmp/libcosmian_pkcs11.so",
            "--delegated",
            "--hsm-slot",
            "42",
        ]);
        assert!(action.is_ok());
        let Ok(action) = action else {
            return;
        };
        assert!(action.delegated);
        assert_eq!(action.hsm_slot, 42);
    }
}
