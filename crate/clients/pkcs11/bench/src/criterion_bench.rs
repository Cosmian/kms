//! Real `criterion`-crate micro-benchmarks for the PKCS#11 provider, giving
//! single-operation statistical latency (mean/median/`CI`) for each mode — the fast
//! counterpart to `load.rs`'s concurrency sweep (`mise bench:load-pkcs11
//! --criterion` skips the sweep entirely and only runs these).
//!
//! Mirrors `mise bench:load --criterion`'s own `Criterion::default()` construction
//! (`crate/clients/clap/src/actions/bench/clap.rs`) so the two tools' `--speed`
//! presets mean the same thing.

use std::{cell::Cell, time::Duration};

use ckms::reexport::cosmian_kms_cli_actions::reexport::{
    cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier, cosmian_kms_client::KmsClient,
};
use criterion::Criterion;
use tokio::runtime::Runtime;

use crate::{
    error::BenchResult,
    load::{ConcreteMode, PreparedOp, prepare_ops},
    loader::Pkcs11Session,
    overhead::add_overhead_benchmarks,
    report,
};

/// How long/thorough a criterion run should be — identical semantics to
/// `crate/clients/clap/src/actions/bench/types.rs::BenchSpeed`.
#[derive(Clone, Copy, Debug, clap::ValueEnum, PartialEq, Eq)]
pub(crate) enum BenchSpeed {
    /// Smoke-test: 10 samples (criterion's minimum), 1 ms measurement/warmup.
    Sanity,
    /// 10 samples, 1 s measurement, 500 ms warmup — fast enough for interactive
    /// bottleneck-hunting.
    Quick,
    /// 100 samples, configurable measurement time, 3 s warmup — publishable
    /// precision for the checked-in report.
    Normal,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum, PartialEq, Eq)]
pub(crate) enum PayloadMode {
    Fixed,
    Varying,
}

pub(crate) struct CriterionRunConfig {
    pub(crate) speed: BenchSpeed,
    pub(crate) measurement_time: Duration,
    pub(crate) overhead_payload_size: usize,
    pub(crate) overhead_payload_mode: PayloadMode,
}

/// Runs every mode in `modes` as a single-operation criterion benchmark (using only
/// `pool`'s first session — these measure per-call latency, not concurrency, so a
/// session pool sized for the load sweep is unnecessary overkill here) and writes
/// `criterion.json` (see `report::write_criterion_json`).
///
/// Uses [`prepare_ops`] — the exact same setup/probe/closure-construction logic
/// `run_all` uses — so a mode measured here and in the load sweep can never silently
/// diverge in what it actually calls.
pub(crate) fn run_criterion(
    modes: &[ConcreteMode],
    pool: &[Pkcs11Session<'_>],
    runtime: &Runtime,
    client: &KmsClient,
    ed25519_private_key_id: Option<&UniqueIdentifier>,
    config: &CriterionRunConfig,
) -> BenchResult<()> {
    let session = pool
        .first()
        .ok_or_else(|| crate::error::BenchError::Setup("empty PKCS#11 session pool".to_owned()))?;

    let mut c = match config.speed {
        BenchSpeed::Sanity => Criterion::default()
            .sample_size(10)
            .measurement_time(Duration::from_millis(1))
            .warm_up_time(Duration::from_millis(1)),
        BenchSpeed::Quick => Criterion::default()
            .sample_size(10)
            .measurement_time(Duration::from_secs(1))
            .warm_up_time(Duration::from_millis(500)),
        BenchSpeed::Normal => Criterion::default()
            .sample_size(100)
            .measurement_time(config.measurement_time)
            .warm_up_time(Duration::from_secs(3)),
    };

    let overhead_metadata = if modes.contains(&ConcreteMode::SignEdDsa) {
        let private_key_id = ed25519_private_key_id.ok_or_else(|| {
            crate::error::BenchError::Setup(
                "Ed25519 overhead benchmark requires a provisioned private key".to_owned(),
            )
        })?;
        Some(add_overhead_benchmarks(
            &mut c,
            runtime,
            client,
            private_key_id,
            session,
            config.overhead_payload_size,
            config.overhead_payload_mode == PayloadMode::Varying,
        )?)
    } else {
        None
    };

    for PreparedOp { label, setup, op } in prepare_ops(modes, pool)? {
        if overhead_metadata.is_some() && label == "sign/eddsa-ed25519" {
            // `pkcs11-one-call` in the overhead group is this exact operation.
            // `write_criterion_json` aliases that estimate into the normal
            // Sign/Verify category, avoiding a duplicate run at a later (possibly
            // noisier) point in time.
            continue;
        }
        if let Some(setup) = setup {
            setup(pool)?;
        }
        eprintln!("[bench:load-pkcs11] criterion: {label}");
        // `label` is e.g. "encrypt/aes-cbc" or "sign/eddsa-ed25519" (see
        // `ConcreteMode::label`). A flat `c.bench_function(label, ...)` gets
        // criterion-sanitized into a single directory (`encrypt_aes-cbc`), which
        // `.mise/scripts/bench/plot_version_compare.py::bench_id_to_parts` then
        // splits on the first underscore into `(op_type, algorithm)` —
        // `("encrypt", "aes-cbc")`. That works for `encrypt`, but the report's
        // "Sign / Verify" category (`_criterion_category`) only recognizes the
        // combined op_type `"sign-verify"`, never bare `"sign"`/`"verify"` — so a
        // flat `sign/eddsa-ed25519` or `verify/rsa-pkcs-sha256` label would be
        // silently dropped from every chart/table. Route those two kinds through
        // a real criterion *group* instead (`sign-verify_<algo>/<sign|verify>`,
        // mirroring how `crate/clients/clap/src/actions/bench/transport.rs::bench_op`
        // benchmarks the KMIP path), which produces exactly the ID shape the
        // categorizer expects.
        if let Some((kind @ ("sign" | "verify"), algo)) = label.split_once('/') {
            let mut group = c.benchmark_group(format!("pkcs11_sign-verify_{algo}"));
            let failed = Cell::new(false);
            group.bench_function(kind, |b| {
                b.iter(|| {
                    // Errors surface as unusually fast/slow samples rather than a
                    // hard stop — matching `run_for`'s own tolerance for the
                    // occasional Cryptoki error under the load sweep. A mode that
                    // cannot run at all is filtered out by `prepare_ops` already.
                    if op(session).is_err() {
                        failed.set(true);
                    }
                });
            });
            group.finish();
            if failed.get() {
                return Err(crate::error::BenchError::Setup(format!(
                    "criterion benchmark {label} observed at least one failed operation"
                )));
            }
        } else {
            let benchmark_id = format!("pkcs11_{label}");
            let failed = Cell::new(false);
            c.bench_function(&benchmark_id, |b| {
                b.iter(|| {
                    if op(session).is_err() {
                        failed.set(true);
                    }
                });
            });
            if failed.get() {
                return Err(crate::error::BenchError::Setup(format!(
                    "criterion benchmark {label} observed at least one failed operation"
                )));
            }
        }
    }
    c.final_summary();

    report::write_criterion_json()?;
    if let Some(metadata) = overhead_metadata {
        report::write_overhead_json(&metadata)?;
    }
    Ok(())
}
