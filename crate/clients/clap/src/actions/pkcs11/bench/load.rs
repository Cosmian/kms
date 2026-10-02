//! Concurrency-sweep load engine for the PKCS#11 benchmark, mirroring the
//! vocabulary (concurrency levels, p50/p95/p99, throughput) of
//! `crate/clients/clap/src/actions/bench/load.rs`'s KMIP REST load sweep, but driving
//! the real Cryptoki C API over a pool of `cosmian_kms_base_hsm::Session`s (one per
//! concurrent worker thread, or a single shared one under `--shared-session`)
//! instead.

use std::{
    thread,
    time::{Duration, Instant},
};

use cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm;
use cosmian_kms_base_hsm::{HsmEncryptionAlgorithm, HsmSigningAlgorithm, Session};

use super::{
    error::{BenchError, BenchResult},
    ops,
    setup::BenchSetup,
};
use crate::actions::bench::types::{BenchFilter, BenchMode};

/// The concrete operation families `run_all` actually knows how to execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConcreteMode {
    EncryptAesCbc,
    EncryptAesGcm,
    EncryptRsaPkcs,
    EncryptRsaOaep,
    DecryptAesCbc,
    DecryptAesGcm,
    DecryptRsaPkcs,
    DecryptRsaOaep,
    SignRsaPkcs,
    SignRsaPss,
    VerifyRsaPkcs,
    VerifyRsaPss,
    SignEcdsaP256,
    VerifyEcdsaP256,
    SignEcdsaP384,
    VerifyEcdsaP384,
    #[cfg_attr(not(feature = "non-fips"), allow(dead_code))]
    SignSecp256k1,
    #[cfg_attr(not(feature = "non-fips"), allow(dead_code))]
    VerifySecp256k1,
    #[cfg_attr(not(feature = "non-fips"), allow(dead_code))]
    SignEdDsa,
    VerifyEdDsa,
    KeyCreation,
    Batch,
}

impl ConcreteMode {
    /// The operation name used in report output (also becomes the report's
    /// `### <label>` section heading and SVG chart file name).
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::EncryptAesCbc => "encrypt/aes-cbc",
            Self::EncryptAesGcm => "encrypt/aes-gcm",
            Self::EncryptRsaPkcs => "encrypt/rsa-pkcs",
            Self::EncryptRsaOaep => "encrypt/rsa-oaep",
            Self::DecryptAesCbc => "decrypt/aes-cbc",
            Self::DecryptAesGcm => "decrypt/aes-gcm",
            Self::DecryptRsaPkcs => "decrypt/rsa-pkcs",
            Self::DecryptRsaOaep => "decrypt/rsa-oaep",
            Self::SignRsaPkcs => "sign/rsa-pkcs-sha256",
            Self::SignRsaPss => "sign/rsa-pss-sha256",
            Self::VerifyRsaPkcs => "verify/rsa-pkcs-sha256",
            Self::VerifyRsaPss => "verify/rsa-pss-sha256",
            Self::SignEcdsaP256 => "sign/ecdsa-p256",
            Self::VerifyEcdsaP256 => "verify/ecdsa-p256",
            Self::SignEcdsaP384 => "sign/ecdsa-p384",
            Self::VerifyEcdsaP384 => "verify/ecdsa-p384",
            Self::SignSecp256k1 => "sign/ecdsa-secp256k1",
            Self::VerifySecp256k1 => "verify/ecdsa-secp256k1",
            Self::SignEdDsa => "sign/eddsa-ed25519",
            Self::VerifyEdDsa => "verify/eddsa-ed25519",
            Self::KeyCreation => "key-creation/aes",
            Self::Batch => "batch/aes-cbc",
        }
    }
}

/// Expands the `all` benchmark mode for a FIPS build.
#[cfg(not(feature = "non-fips"))]
fn all_modes() -> Vec<ConcreteMode> {
    vec![
        ConcreteMode::EncryptAesCbc,
        ConcreteMode::EncryptAesGcm,
        ConcreteMode::EncryptRsaPkcs,
        ConcreteMode::EncryptRsaOaep,
        ConcreteMode::DecryptAesCbc,
        ConcreteMode::DecryptAesGcm,
        ConcreteMode::DecryptRsaPkcs,
        ConcreteMode::DecryptRsaOaep,
        ConcreteMode::SignRsaPkcs,
        ConcreteMode::SignRsaPss,
        ConcreteMode::SignEcdsaP256,
        ConcreteMode::SignEcdsaP384,
        ConcreteMode::VerifyRsaPkcs,
        ConcreteMode::VerifyRsaPss,
        ConcreteMode::VerifyEcdsaP256,
        ConcreteMode::VerifyEcdsaP384,
        ConcreteMode::KeyCreation,
        ConcreteMode::Batch,
    ]
}

/// Expands the `all` benchmark mode for a non-FIPS build.
#[cfg(feature = "non-fips")]
fn all_modes() -> Vec<ConcreteMode> {
    vec![
        ConcreteMode::EncryptAesCbc,
        ConcreteMode::EncryptAesGcm,
        ConcreteMode::EncryptRsaPkcs,
        ConcreteMode::EncryptRsaOaep,
        ConcreteMode::DecryptAesCbc,
        ConcreteMode::DecryptAesGcm,
        ConcreteMode::DecryptRsaPkcs,
        ConcreteMode::DecryptRsaOaep,
        ConcreteMode::SignRsaPkcs,
        ConcreteMode::SignRsaPss,
        ConcreteMode::SignEcdsaP256,
        ConcreteMode::SignEcdsaP384,
        ConcreteMode::SignSecp256k1,
        ConcreteMode::SignEdDsa,
        ConcreteMode::VerifyRsaPkcs,
        ConcreteMode::VerifyRsaPss,
        ConcreteMode::VerifyEcdsaP256,
        ConcreteMode::VerifyEcdsaP384,
        ConcreteMode::VerifySecp256k1,
        ConcreteMode::VerifyEdDsa,
        ConcreteMode::KeyCreation,
        ConcreteMode::Batch,
    ]
}

/// Expands the `sign-verify` benchmark mode for a FIPS build.
#[cfg(not(feature = "non-fips"))]
fn sign_verify_modes() -> Vec<ConcreteMode> {
    vec![
        ConcreteMode::SignRsaPkcs,
        ConcreteMode::SignRsaPss,
        ConcreteMode::SignEcdsaP256,
        ConcreteMode::SignEcdsaP384,
        ConcreteMode::VerifyRsaPkcs,
        ConcreteMode::VerifyRsaPss,
        ConcreteMode::VerifyEcdsaP256,
        ConcreteMode::VerifyEcdsaP384,
    ]
}

/// Expands the `sign-verify` benchmark mode for a non-FIPS build.
#[cfg(feature = "non-fips")]
fn sign_verify_modes() -> Vec<ConcreteMode> {
    vec![
        ConcreteMode::SignRsaPkcs,
        ConcreteMode::SignRsaPss,
        ConcreteMode::SignEcdsaP256,
        ConcreteMode::SignEcdsaP384,
        ConcreteMode::SignSecp256k1,
        ConcreteMode::SignEdDsa,
        ConcreteMode::VerifyRsaPkcs,
        ConcreteMode::VerifyRsaPss,
        ConcreteMode::VerifyEcdsaP256,
        ConcreteMode::VerifyEcdsaP384,
        ConcreteMode::VerifySecp256k1,
        ConcreteMode::VerifyEdDsa,
    ]
}

/// Expands standard `BenchMode` to concrete PKCS#11 benchmark modes.
///
/// Delegated mode does not hard-code an HSM capability matrix. Every requested
/// operation is prepared and probed against the selected provider; unsupported
/// operations are skipped for that run only, while supported HSMs retain them.
#[must_use]
pub(crate) fn expand_bench_mode(
    mode: BenchMode,
    filter: Option<&BenchFilter>,
) -> Vec<ConcreteMode> {
    let modes = match mode {
        BenchMode::All => all_modes(),
        BenchMode::Encrypt => vec![
            ConcreteMode::EncryptAesCbc,
            ConcreteMode::EncryptAesGcm,
            ConcreteMode::EncryptRsaPkcs,
            ConcreteMode::EncryptRsaOaep,
            ConcreteMode::DecryptAesCbc,
            ConcreteMode::DecryptAesGcm,
            ConcreteMode::DecryptRsaPkcs,
            ConcreteMode::DecryptRsaOaep,
        ],
        BenchMode::SignVerify => sign_verify_modes(),
        BenchMode::KeyCreation => vec![ConcreteMode::KeyCreation],
        BenchMode::Batch => vec![ConcreteMode::Batch],
    };

    modes
        .into_iter()
        .filter(|m| filter.is_none_or(|f| f.matches(m.label(), None)))
        .collect()
}

/// Sweep parameters, mirroring `bench/load`'s CLI flags.
pub(crate) struct SweepConfig {
    pub concurrency_levels: Vec<usize>,
    pub measure_time: Duration,
    pub warmup_time: Duration,
    pub cooldown_time: Duration,
}

/// Throughput and latency percentiles for one operation at one concurrency level.
#[derive(Debug)]
pub(crate) struct LoadResult {
    pub operation: String,
    pub concurrency: usize,
    pub throughput_ops: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub samples: usize,
}

/// A single unit of work executed repeatedly by every worker thread.
///
/// Takes `&Session` because each worker thread gets its own dedicated session from
/// the pool built in `mod.rs` (see [`run_for`]), rather than every thread sharing
/// one handle.
pub(crate) type Op = dyn Fn(&Session) -> BenchResult<()> + Send + Sync;
pub(crate) type SetupOp = dyn Fn(&[Session]) -> BenchResult<()> + Send + Sync;

/// One mode's report label plus its ready-to-run [`Op`] closure, as produced by
/// [`prepare_ops`].
pub(crate) struct PreparedOp {
    pub(crate) label: &'static str,
    pub(crate) setup: Option<Box<SetupOp>>,
    pub(crate) op: Box<Op>,
}

/// Runs the full concurrency sweep for one named operation and returns one
/// [`LoadResult`] per concurrency level.
fn run_sweep(
    operation: &str,
    pool: &[Session],
    op: &Op,
    config: &SweepConfig,
) -> BenchResult<Vec<LoadResult>> {
    let mut results = Vec::with_capacity(config.concurrency_levels.len());

    for &concurrency in &config.concurrency_levels {
        if !config.warmup_time.is_zero() {
            run_for(pool, op, concurrency, config.warmup_time)?;
        }

        let (latencies, elapsed) = run_for(pool, op, concurrency, config.measure_time)?;
        results.push(summarize(operation, concurrency, &latencies, elapsed));

        if !config.cooldown_time.is_zero() {
            thread::sleep(config.cooldown_time);
        }
    }

    Ok(results)
}

/// Spawns `concurrency` threads — each driving `op` against its **own** dedicated
/// session from `pool` (`pool[i % pool.len()]`) for `duration` — and returns every
/// observed per-call latency plus the actual wall-clock time spent (used to compute
/// throughput).
///
/// Giving every thread its own session lets concurrent calls proceed in parallel:
/// `crate/clients/pkcs11/module/src/sessions.rs` locks each session independently
/// (not one process-wide lock shared by every session), so operations on *different*
/// sessions no longer block each other. Passing a single-session `pool` (see
/// `mod.rs`'s `--shared-session` flag) instead reproduces the old
/// every-thread-shares-one-handle model, for direct before/after comparison.
fn run_for(
    pool: &[Session],
    op: &Op,
    concurrency: usize,
    duration: Duration,
) -> BenchResult<(Vec<Duration>, Duration)> {
    let stop_after = Instant::now() + duration;

    let start = Instant::now();
    let per_thread_latencies: BenchResult<Vec<Vec<Duration>>> = thread::scope(|scope| {
        // `.collect()` here is required, not needless: every `scope.spawn` must run
        // before the `.join()` pass below, otherwise threads would be spawned and
        // joined one at a time — serializing the very concurrency this benchmark
        // measures.
        #[allow(clippy::needless_collect)]
        let handles: Vec<_> = (0..concurrency.max(1))
            .map(|i| {
                // `pool.len()` may be smaller than `concurrency` (e.g. a
                // single-session `pool` under `--shared-session`), hence the modulo
                // instead of a direct index.
                let session = &pool[i % pool.len()];
                scope.spawn(move || {
                    let mut latencies = Vec::new();
                    while Instant::now() < stop_after {
                        let call_start = Instant::now();
                        op(session)?;
                        let elapsed = call_start.elapsed();
                        latencies.push(elapsed);
                    }
                    Ok(latencies)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().map_err(|panic_payload| {
                    let detail = panic_payload
                        .downcast_ref::<&str>()
                        .map_or("unknown panic payload", |message| *message);
                    BenchError::Setup(format!("a benchmark worker thread panicked: {detail}"))
                })?
            })
            .collect()
    });
    let elapsed = start.elapsed();

    Ok((
        per_thread_latencies?.into_iter().flatten().collect(),
        elapsed,
    ))
}

/// Computes throughput and latency percentiles from a batch of samples.
fn summarize(
    operation: &str,
    concurrency: usize,
    latencies: &[Duration],
    elapsed: Duration,
) -> LoadResult {
    let mut sorted: Vec<Duration> = latencies.to_vec();
    sorted.sort_unstable();
    let samples = sorted.len();

    let percentile = |p: f64| -> f64 {
        if samples == 0 {
            return 0.0;
        }
        let idx = ((samples - 1) as f64 * p).round() as usize;
        sorted[idx.min(samples - 1)].as_secs_f64() * 1000.0
    };

    let throughput_ops = if elapsed.is_zero() {
        0.0
    } else {
        samples as f64 / elapsed.as_secs_f64()
    };

    LoadResult {
        operation: operation.to_owned(),
        concurrency,
        throughput_ops,
        p50_ms: percentile(0.50),
        p95_ms: percentile(0.95),
        p99_ms: percentile(0.99),
        samples,
    }
}

/// Resolves `modes` into runnable `(label, op)` pairs, performing every one-time
/// setup/object-discovery/probe call a mode's closure needs — shared by both
/// [`run_all`] (the concurrency-sweep load engine) and
/// `crate::criterion_bench::run_criterion` (single-operation statistical
/// micro-benchmarks), so the two entry points can never diverge on how a mode's
/// closure is built.
///
/// `VerifyRsa`/`VerifyEcdsa`/`VerifyEdDsa` are each probed once here; if the loaded
/// provider reports an error for the requested mechanism (e.g. `CKM_EDDSA` on a
/// v2.40-only library), the mode is skipped with a console notice and simply absent
/// from the returned list — mirroring `mise bench:load`'s own pattern of skipping a
/// benchmark it cannot prepare (e.g. a key-creation failure) rather than reporting
/// fabricated numbers.
pub(crate) fn prepare_ops(
    modes: &[ConcreteMode],
    pool: &[Session],
    setup: &BenchSetup,
    hsm_prefix: Option<&str>,
) -> BenchResult<Vec<PreparedOp>> {
    // Any pooled session works for one-time setup/object-discovery calls below:
    // `crate/clients/pkcs11/module/src/objects_store.rs`'s object store is global,
    // not scoped per session, so a handle found via one session remains valid when
    // used (e.g. in `C_SignInit`) via any other session in the pool.
    let setup_session = pool
        .first()
        .ok_or_else(|| BenchError::Setup("empty PKCS#11 session pool".to_owned()))?;

    // Owned copy for the `KeyCreation` closure (an `Op` is `'static`, so it cannot
    // borrow `hsm_prefix` directly).
    let key_creation_prefix = hsm_prefix.map(str::to_owned);

    let secret_key = if modes.iter().any(|mode| {
        matches!(
            mode,
            ConcreteMode::EncryptAesCbc
                | ConcreteMode::EncryptAesGcm
                | ConcreteMode::DecryptAesCbc
                | ConcreteMode::DecryptAesGcm
                | ConcreteMode::Batch
        )
    }) {
        Some(ops::find(setup_session, &setup.symmetric.to_string())?)
    } else {
        None
    };
    let rsa_public_key = if modes.iter().any(|mode| {
        matches!(
            mode,
            ConcreteMode::EncryptRsaPkcs
                | ConcreteMode::EncryptRsaOaep
                | ConcreteMode::VerifyRsaPkcs
                | ConcreteMode::VerifyRsaPss
        )
    }) {
        Some(ops::find(setup_session, &setup.rsa_public.to_string())?)
    } else {
        None
    };
    let rsa_private_key = if modes.iter().any(|mode| {
        matches!(
            mode,
            ConcreteMode::DecryptRsaPkcs
                | ConcreteMode::DecryptRsaOaep
                | ConcreteMode::SignRsaPkcs
                | ConcreteMode::SignRsaPss
        )
    }) {
        Some(ops::find(setup_session, &setup.rsa_private.to_string())?)
    } else {
        None
    };
    let ecdsa_private_key = if modes.iter().any(|mode| {
        matches!(
            mode,
            ConcreteMode::SignEcdsaP256 | ConcreteMode::VerifyEcdsaP256
        )
    }) {
        Some(ops::find(setup_session, &setup.ecdsa_private.to_string())?)
    } else {
        None
    };
    let ecdsa_p384_private_key = if modes.iter().any(|mode| {
        matches!(
            mode,
            ConcreteMode::SignEcdsaP384 | ConcreteMode::VerifyEcdsaP384
        )
    }) {
        Some(ops::find(
            setup_session,
            &setup.ecdsa_p384_private.to_string(),
        )?)
    } else {
        None
    };
    let secp256k1_private_key = if modes.iter().any(|mode| {
        matches!(
            mode,
            ConcreteMode::SignSecp256k1 | ConcreteMode::VerifySecp256k1
        )
    }) {
        match setup.secp256k1_private.as_ref() {
            Some(id) => Some(ops::find(setup_session, &id.to_string())?),
            None => None,
        }
    } else {
        None
    };
    let secp256k1_public_key = if modes.contains(&ConcreteMode::VerifySecp256k1) {
        match setup.secp256k1_public.as_ref() {
            Some(id) => Some(ops::find(setup_session, &id.to_string())?),
            None => None,
        }
    } else {
        None
    };
    let eddsa_private_key = if modes
        .iter()
        .any(|mode| matches!(mode, ConcreteMode::SignEdDsa | ConcreteMode::VerifyEdDsa))
    {
        match setup.ed25519_private.as_ref() {
            Some(id) => Some(ops::find(setup_session, &id.to_string())?),
            None => None,
        }
    } else {
        None
    };
    let eddsa_public_key = if modes.contains(&ConcreteMode::VerifyEdDsa) {
        match setup.ed25519_public.as_ref() {
            Some(id) => Some(ops::find(setup_session, &id.to_string())?),
            None => None,
        }
    } else {
        None
    };
    let plaintext = vec![0x42_u8; 4096];
    let message = vec![0x42_u8; 32];

    let ciphertext_cbc = if modes.contains(&ConcreteMode::DecryptAesCbc) {
        let key = secret_key.ok_or_else(|| {
            BenchError::Setup("DecryptAesCbc requires a provisioned secret key".to_owned())
        })?;
        let c = setup_session.encrypt(key, HsmEncryptionAlgorithm::AesCbc, &plaintext, None)?;
        Some([c.iv.unwrap_or_default(), c.ciphertext].concat())
    } else {
        None
    };
    let ciphertext_gcm: Option<Vec<u8>> = if modes.contains(&ConcreteMode::DecryptAesGcm) {
        let key = secret_key.ok_or_else(|| {
            BenchError::Setup("DecryptAesGcm requires a provisioned secret key".to_owned())
        })?;
        let c = setup_session.encrypt(key, HsmEncryptionAlgorithm::AesGcm, &plaintext, None)?;
        Some(
            [
                c.iv.unwrap_or_default(),
                c.ciphertext,
                c.tag.unwrap_or_default(),
            ]
            .concat(),
        )
    } else {
        None
    };
    let ciphertext_rsa = if modes.contains(&ConcreteMode::DecryptRsaPkcs) {
        let key = rsa_public_key.ok_or_else(|| {
            BenchError::Setup("DecryptRsaPkcs requires a provisioned RSA public key".to_owned())
        })?;
        Some(
            setup_session
                .encrypt(key, HsmEncryptionAlgorithm::RsaPkcsV15, &message, None)?
                .ciphertext,
        )
    } else {
        None
    };
    // `CKM_RSA_PKCS_OAEP` support is probed once here (rather than hard-failing),
    // since the server's HSM capability detection only checks that the HSM
    // advertises the `CKM_SHA256` digest mechanism generally — a false positive
    // on providers (e.g. SoftHSM2) whose OAEP implementation rejects SHA-256 as
    // the OAEP hash/MGF parameter specifically (documented in
    // `test_data/vectors/hsm/resident_rsa2048_encrypt_oaep_sha256`). A failed
    // probe here skips both `EncryptRsaOaep` and `DecryptRsaOaep` for this run.
    let rsa_oaep_probe = if modes.iter().any(|mode| {
        matches!(
            mode,
            ConcreteMode::EncryptRsaOaep | ConcreteMode::DecryptRsaOaep
        )
    }) {
        let key = rsa_public_key.ok_or_else(|| {
            BenchError::Setup(
                "EncryptRsaOaep/DecryptRsaOaep require a provisioned RSA public key".to_owned(),
            )
        })?;
        match setup_session.encrypt(key, HsmEncryptionAlgorithm::RsaOaepSha256, &message, None) {
            Ok(ciphertext) => Some(ciphertext.ciphertext),
            Err(error) => {
                eprintln!(
                    "[bench:pkcs11] 'encrypt/rsa-oaep'/'decrypt/rsa-oaep' unavailable, \
                     skipping: {error}"
                );
                None
            }
        }
    } else {
        None
    };
    let ciphertext_rsa_oaep = if modes.contains(&ConcreteMode::DecryptRsaOaep) {
        rsa_oaep_probe.clone()
    } else {
        None
    };
    let verify_rsa_signature = if modes.contains(&ConcreteMode::VerifyRsaPkcs) {
        let key = rsa_private_key.ok_or_else(|| {
            BenchError::Setup(
                "VerifyRsaPkcs mode requires a provisioned RSA private key".to_owned(),
            )
        })?;
        Some(setup_session.sign(key, HsmSigningAlgorithm::Sha256WithRsa, &message)?)
    } else {
        None
    };
    let verify_rsa_pss_signature = if modes.contains(&ConcreteMode::VerifyRsaPss) {
        let key = rsa_private_key.ok_or_else(|| {
            BenchError::Setup("VerifyRsaPss mode requires a provisioned RSA private key".to_owned())
        })?;
        Some(setup_session.sign(
            key,
            HsmSigningAlgorithm::RsaPss {
                hashing_algorithm: HashingAlgorithm::SHA256,
                mask_generator_hashing_algorithm: HashingAlgorithm::SHA256,
                salt_length: Some(32),
                prehashed: true,
            },
            &message,
        )?)
    } else {
        None
    };
    // Likewise for `VerifyEcdsa`, signing the same 32-byte digest used by `SignEcdsa`.
    let verify_ecdsa_signature = if modes.contains(&ConcreteMode::VerifyEcdsaP256) {
        let key = ecdsa_private_key.ok_or_else(|| {
            BenchError::Setup("VerifyEcdsaP256 mode requires a provisioned EC P-256 key".to_owned())
        })?;
        Some(setup_session.sign(
            key,
            HsmSigningAlgorithm::Ecdsa {
                hashing_algorithm: HashingAlgorithm::SHA256,
                prehashed: true,
            },
            &message,
        )?)
    } else {
        None
    };
    let verify_ecdsa_p384_signature = if modes.contains(&ConcreteMode::VerifyEcdsaP384) {
        let key = ecdsa_p384_private_key.ok_or_else(|| {
            BenchError::Setup("VerifyEcdsaP384 mode requires a provisioned EC P-384 key".to_owned())
        })?;
        Some(setup_session.sign(
            key,
            HsmSigningAlgorithm::Ecdsa {
                hashing_algorithm: HashingAlgorithm::SHA256,
                prehashed: true,
            },
            &message,
        )?)
    } else {
        None
    };
    // Likewise for `VerifySecp256k1`, signing the same 32-byte digest used by
    // `SignSecp256k1`.
    let verify_secp256k1_signature = if modes.contains(&ConcreteMode::VerifySecp256k1) {
        if let Some(key) = secp256k1_private_key {
            Some(setup_session.sign(
                key,
                HsmSigningAlgorithm::Ecdsa {
                    hashing_algorithm: HashingAlgorithm::SHA256,
                    prehashed: true,
                },
                &message,
            )?)
        } else {
            None
        }
    } else {
        None
    };
    let eddsa_verify_signature = if modes.contains(&ConcreteMode::VerifyEdDsa) {
        if let Some(key) = eddsa_private_key {
            setup_session.message_sign_init(key, HsmSigningAlgorithm::Eddsa)?;
            let signature = setup_session.sign_message(&message)?;
            setup_session.message_sign_final()?;
            Some(signature)
        } else {
            None
        }
    } else {
        None
    };

    let mut prepared = Vec::new();
    for mode in modes {
        let mut operation_setup: Option<Box<SetupOp>> = None;
        let op: Box<Op> = match mode {
            ConcreteMode::EncryptAesCbc => {
                let Some(secret_key) = secret_key else {
                    continue;
                };
                let plaintext = plaintext.clone();
                Box::new(move |session: &Session| {
                    session.encrypt(
                        secret_key,
                        HsmEncryptionAlgorithm::AesCbc,
                        &plaintext,
                        None,
                    )?;
                    Ok(())
                })
            }
            ConcreteMode::EncryptAesGcm => {
                let Some(secret_key) = secret_key else {
                    continue;
                };
                let plaintext = plaintext.clone();
                Box::new(move |session: &Session| {
                    session.encrypt(
                        secret_key,
                        HsmEncryptionAlgorithm::AesGcm,
                        &plaintext,
                        None,
                    )?;
                    Ok(())
                })
            }
            ConcreteMode::EncryptRsaPkcs => {
                let Some(rsa_public_key) = rsa_public_key else {
                    continue;
                };
                let message = message.clone();
                Box::new(move |session: &Session| {
                    session.encrypt(
                        rsa_public_key,
                        HsmEncryptionAlgorithm::RsaPkcsV15,
                        &message,
                        None,
                    )?;
                    Ok(())
                })
            }
            ConcreteMode::EncryptRsaOaep => {
                let Some(rsa_public_key) = rsa_public_key else {
                    continue;
                };
                if rsa_oaep_probe.is_none() {
                    // Probe already failed and printed a notice above; skip silently here.
                    continue;
                }
                let message = message.clone();
                Box::new(move |session: &Session| {
                    session.encrypt(
                        rsa_public_key,
                        HsmEncryptionAlgorithm::RsaOaepSha256,
                        &message,
                        None,
                    )?;
                    Ok(())
                })
            }
            ConcreteMode::DecryptAesCbc => {
                let Some(secret_key) = secret_key else {
                    continue;
                };
                let Some(ciphertext) = ciphertext_cbc.clone() else {
                    continue;
                };
                if let Err(error) =
                    setup_session.decrypt(secret_key, HsmEncryptionAlgorithm::AesCbc, &ciphertext)
                {
                    eprintln!(
                        "[bench:pkcs11] '{}' unavailable, skipping: {error}",
                        mode.label()
                    );
                    continue;
                }
                Box::new(move |session: &Session| {
                    session.decrypt(secret_key, HsmEncryptionAlgorithm::AesCbc, &ciphertext)?;
                    Ok(())
                })
            }
            ConcreteMode::DecryptAesGcm => {
                let Some(secret_key) = secret_key else {
                    continue;
                };
                let Some(ciphertext) = ciphertext_gcm.clone() else {
                    continue;
                };
                if let Err(error) =
                    setup_session.decrypt(secret_key, HsmEncryptionAlgorithm::AesGcm, &ciphertext)
                {
                    eprintln!(
                        "[bench:pkcs11] '{}' unavailable, skipping: {error}",
                        mode.label()
                    );
                    continue;
                }
                Box::new(move |session: &Session| {
                    session.decrypt(secret_key, HsmEncryptionAlgorithm::AesGcm, &ciphertext)?;
                    Ok(())
                })
            }
            ConcreteMode::DecryptRsaPkcs => {
                let Some(rsa_private_key) = rsa_private_key else {
                    continue;
                };
                let Some(ciphertext) = ciphertext_rsa.clone() else {
                    continue;
                };
                if let Err(error) = setup_session.decrypt(
                    rsa_private_key,
                    HsmEncryptionAlgorithm::RsaPkcsV15,
                    &ciphertext,
                ) {
                    eprintln!(
                        "[bench:pkcs11] '{}' unavailable, skipping: {error}",
                        mode.label()
                    );
                    continue;
                }
                Box::new(move |session: &Session| {
                    session.decrypt(
                        rsa_private_key,
                        HsmEncryptionAlgorithm::RsaPkcsV15,
                        &ciphertext,
                    )?;
                    Ok(())
                })
            }
            ConcreteMode::DecryptRsaOaep => {
                let Some(rsa_private_key) = rsa_private_key else {
                    continue;
                };
                let Some(ciphertext) = ciphertext_rsa_oaep.clone() else {
                    continue;
                };
                if let Err(error) = setup_session.decrypt(
                    rsa_private_key,
                    HsmEncryptionAlgorithm::RsaOaepSha256,
                    &ciphertext,
                ) {
                    eprintln!(
                        "[bench:pkcs11] '{}' unavailable, skipping: {error}",
                        mode.label()
                    );
                    continue;
                }
                Box::new(move |session: &Session| {
                    session.decrypt(
                        rsa_private_key,
                        HsmEncryptionAlgorithm::RsaOaepSha256,
                        &ciphertext,
                    )?;
                    Ok(())
                })
            }
            ConcreteMode::SignRsaPkcs => {
                let Some(private_key) = rsa_private_key else {
                    continue;
                };
                let message = message.clone();
                Box::new(move |session: &Session| {
                    session.sign(private_key, HsmSigningAlgorithm::Sha256WithRsa, &message)?;
                    Ok(())
                })
            }
            ConcreteMode::SignRsaPss => {
                let Some(private_key) = rsa_private_key else {
                    continue;
                };
                let message = message.clone();
                Box::new(move |session: &Session| {
                    session.sign(
                        private_key,
                        HsmSigningAlgorithm::RsaPss {
                            hashing_algorithm: HashingAlgorithm::SHA256,
                            mask_generator_hashing_algorithm: HashingAlgorithm::SHA256,
                            salt_length: Some(32),
                            prehashed: true,
                        },
                        &message,
                    )?;
                    Ok(())
                })
            }
            ConcreteMode::SignEcdsaP256 => {
                let Some(ecdsa_private_key) = ecdsa_private_key else {
                    continue;
                };
                let message = message.clone();
                Box::new(move |session: &Session| {
                    session.sign(
                        ecdsa_private_key,
                        HsmSigningAlgorithm::Ecdsa {
                            hashing_algorithm: HashingAlgorithm::SHA256,
                            prehashed: true,
                        },
                        &message,
                    )?;
                    Ok(())
                })
            }
            ConcreteMode::SignEcdsaP384 => {
                let Some(ecdsa_p384_private_key) = ecdsa_p384_private_key else {
                    continue;
                };
                let message = message.clone();
                Box::new(move |session: &Session| {
                    session.sign(
                        ecdsa_p384_private_key,
                        HsmSigningAlgorithm::Ecdsa {
                            hashing_algorithm: HashingAlgorithm::SHA256,
                            prehashed: true,
                        },
                        &message,
                    )?;
                    Ok(())
                })
            }
            ConcreteMode::SignSecp256k1 => {
                let Some(secp256k1_private_key) = secp256k1_private_key else {
                    continue;
                };
                let message = message.clone();
                Box::new(move |session: &Session| {
                    session.sign(
                        secp256k1_private_key,
                        HsmSigningAlgorithm::Ecdsa {
                            hashing_algorithm: HashingAlgorithm::SHA256,
                            prehashed: true,
                        },
                        &message,
                    )?;
                    Ok(())
                })
            }
            ConcreteMode::SignEdDsa => {
                let Some(eddsa_private_key) = eddsa_private_key else {
                    continue;
                };
                operation_setup = Some(Box::new(move |sessions: &[Session]| {
                    sessions.iter().try_for_each(|session| {
                        session
                            .message_sign_init(eddsa_private_key, HsmSigningAlgorithm::Eddsa)
                            .map_err(BenchError::from)
                    })
                }));
                let message = message.clone();
                Box::new(move |session: &Session| {
                    session.sign_message(&message)?;
                    Ok(())
                })
            }
            ConcreteMode::VerifyRsaPkcs => {
                let Some(signature) = verify_rsa_signature.clone() else {
                    continue;
                };
                let public_key = ops::find(setup_session, &setup.rsa_public.to_string())?;
                let label = mode.label();
                match setup_session.verify(
                    public_key,
                    HsmSigningAlgorithm::Sha256WithRsa,
                    &message,
                    &signature,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(BenchError::Setup(format!(
                            "{label}: signature verification failed"
                        )));
                    }
                    Err(e) => {
                        eprintln!("[bench:pkcs11] '{label}' unavailable, skipping: {e}");
                        continue;
                    }
                }
                let message = message.clone();
                Box::new(move |session: &Session| {
                    if session.verify(
                        public_key,
                        HsmSigningAlgorithm::Sha256WithRsa,
                        &message,
                        &signature,
                    )? {
                        Ok(())
                    } else {
                        Err(BenchError::Setup(format!(
                            "{label}: signature verification failed"
                        )))
                    }
                })
            }
            ConcreteMode::VerifyRsaPss => {
                let Some(signature) = verify_rsa_pss_signature.clone() else {
                    continue;
                };
                let public_key = ops::find(setup_session, &setup.rsa_public.to_string())?;
                let label = mode.label();
                let pss = HsmSigningAlgorithm::RsaPss {
                    hashing_algorithm: HashingAlgorithm::SHA256,
                    mask_generator_hashing_algorithm: HashingAlgorithm::SHA256,
                    salt_length: Some(32),
                    prehashed: true,
                };
                match setup_session.verify(public_key, pss, &message, &signature) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(BenchError::Setup(format!(
                            "{label}: signature verification failed"
                        )));
                    }
                    Err(e) => {
                        eprintln!("[bench:pkcs11] '{label}' unavailable, skipping: {e}");
                        continue;
                    }
                }
                let message = message.clone();
                Box::new(move |session: &Session| {
                    if session.verify(public_key, pss, &message, &signature)? {
                        Ok(())
                    } else {
                        Err(BenchError::Setup(format!(
                            "{label}: signature verification failed"
                        )))
                    }
                })
            }
            ConcreteMode::VerifyEcdsaP256 => {
                let Some(signature) = verify_ecdsa_signature.clone() else {
                    continue;
                };
                let public_key = ops::find(setup_session, &setup.ecdsa_public.to_string())?;
                let label = mode.label();
                let ecdsa = HsmSigningAlgorithm::Ecdsa {
                    hashing_algorithm: HashingAlgorithm::SHA256,
                    prehashed: true,
                };
                match setup_session.verify(public_key, ecdsa, &message, &signature) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(BenchError::Setup(format!(
                            "{label}: signature verification failed"
                        )));
                    }
                    Err(e) => {
                        eprintln!("[bench:pkcs11] '{label}' unavailable, skipping: {e}");
                        continue;
                    }
                }
                let message = message.clone();
                Box::new(move |session: &Session| {
                    if session.verify(public_key, ecdsa, &message, &signature)? {
                        Ok(())
                    } else {
                        Err(BenchError::Setup(format!(
                            "{label}: signature verification failed"
                        )))
                    }
                })
            }
            ConcreteMode::VerifyEcdsaP384 => {
                let Some(signature) = verify_ecdsa_p384_signature.clone() else {
                    continue;
                };
                let public_key = ops::find(setup_session, &setup.ecdsa_p384_public.to_string())?;
                let label = mode.label();
                let ecdsa = HsmSigningAlgorithm::Ecdsa {
                    hashing_algorithm: HashingAlgorithm::SHA256,
                    prehashed: true,
                };
                match setup_session.verify(public_key, ecdsa, &message, &signature) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(BenchError::Setup(format!(
                            "{label}: signature verification failed"
                        )));
                    }
                    Err(e) => {
                        eprintln!("[bench:pkcs11] '{label}' unavailable, skipping: {e}");
                        continue;
                    }
                }
                let message = message.clone();
                Box::new(move |session: &Session| {
                    if session.verify(public_key, ecdsa, &message, &signature)? {
                        Ok(())
                    } else {
                        Err(BenchError::Setup(format!(
                            "{label}: signature verification failed"
                        )))
                    }
                })
            }
            ConcreteMode::VerifySecp256k1 => {
                let Some(signature) = verify_secp256k1_signature.clone() else {
                    continue;
                };
                let Some(public_key) = secp256k1_public_key else {
                    continue;
                };
                let label = mode.label();
                let ecdsa = HsmSigningAlgorithm::Ecdsa {
                    hashing_algorithm: HashingAlgorithm::SHA256,
                    prehashed: true,
                };
                match setup_session.verify(public_key, ecdsa, &message, &signature) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(BenchError::Setup(format!(
                            "{label}: signature verification failed"
                        )));
                    }
                    Err(e) => {
                        eprintln!("[bench:pkcs11] '{label}' unavailable, skipping: {e}");
                        continue;
                    }
                }
                let message = message.clone();
                Box::new(move |session: &Session| {
                    if session.verify(public_key, ecdsa, &message, &signature)? {
                        Ok(())
                    } else {
                        Err(BenchError::Setup(format!(
                            "{label}: signature verification failed"
                        )))
                    }
                })
            }
            ConcreteMode::VerifyEdDsa => {
                let Some(signature) = eddsa_verify_signature.clone() else {
                    continue;
                };
                let Some(public_key) = eddsa_public_key else {
                    continue;
                };
                let label = mode.label();
                match setup_session.verify(
                    public_key,
                    HsmSigningAlgorithm::Eddsa,
                    &message,
                    &signature,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(BenchError::Setup(format!(
                            "{label}: signature verification failed"
                        )));
                    }
                    Err(e) => {
                        eprintln!("[bench:pkcs11] '{label}' unavailable, skipping: {e}");
                        continue;
                    }
                }
                let message = message.clone();
                Box::new(move |session: &Session| {
                    if session.verify(
                        public_key,
                        HsmSigningAlgorithm::Eddsa,
                        &message,
                        &signature,
                    )? {
                        Ok(())
                    } else {
                        Err(BenchError::Setup(format!(
                            "{label}: signature verification failed"
                        )))
                    }
                })
            }
            ConcreteMode::KeyCreation => {
                let key_creation_prefix = key_creation_prefix.clone();
                Box::new(move |session: &Session| {
                    ops::generate_and_destroy_key(session, key_creation_prefix.as_deref())
                })
            }
            ConcreteMode::Batch => {
                let Some(secret_key) = secret_key else {
                    continue;
                };
                let plaintext = plaintext.clone();
                Box::new(move |session: &Session| {
                    for _ in 0..10 {
                        session.encrypt(
                            secret_key,
                            HsmEncryptionAlgorithm::AesCbc,
                            &plaintext,
                            None,
                        )?;
                    }
                    Ok(())
                })
            }
        };
        prepared.push(PreparedOp {
            label: mode.label(),
            setup: operation_setup,
            op,
        });
    }
    Ok(prepared)
}

/// Runs every mode in `modes` through the full concurrency sweep and returns the
/// combined list of results, in order. See [`prepare_ops`] for how each mode's
/// closure is built and which modes may be silently skipped.
pub(crate) fn run_all(
    modes: &[ConcreteMode],
    pool: &[Session],
    setup: &BenchSetup,
    config: &SweepConfig,
    hsm_prefix: Option<&str>,
) -> BenchResult<Vec<LoadResult>> {
    let prepared = prepare_ops(modes, pool, setup, hsm_prefix)?;
    let mut all_results = Vec::with_capacity(prepared.len());
    for PreparedOp { label, setup, op } in prepared {
        if let Some(setup) = setup {
            setup(pool)?;
        }
        all_results.extend(run_sweep(label, pool, &*op, config)?);
        if label == "sign/eddsa-ed25519" {
            pool.iter()
                .try_for_each(|session| session.message_sign_final().map_err(BenchError::from))?;
        }
    }
    Ok(all_results)
}

#[cfg(test)]
mod tests {
    use super::{ConcreteMode, expand_bench_mode};
    use crate::actions::bench::types::BenchMode;

    #[test]
    fn delegated_encrypt_keeps_all_requested_modes_for_probing() {
        let modes = expand_bench_mode(BenchMode::Encrypt, None);

        assert!(modes.contains(&ConcreteMode::EncryptAesGcm));
        assert!(modes.contains(&ConcreteMode::DecryptAesGcm));
        assert!(modes.contains(&ConcreteMode::EncryptRsaOaep));
        assert!(modes.contains(&ConcreteMode::DecryptRsaOaep));
    }

    #[test]
    fn delegated_sign_verify_keeps_verification_for_capability_probe() {
        let modes = expand_bench_mode(BenchMode::SignVerify, None);

        assert!(modes.contains(&ConcreteMode::SignRsaPkcs));
        assert!(modes.contains(&ConcreteMode::SignEcdsaP384));
        assert!(modes.contains(&ConcreteMode::VerifyEcdsaP384));
        assert!(modes.iter().any(|mode| mode.label().starts_with("verify/")));
    }

    #[test]
    fn all_mode_covers_rsa_oaep_and_ecdsa_p384() {
        let modes = super::all_modes();

        assert!(modes.contains(&ConcreteMode::EncryptRsaOaep));
        assert!(modes.contains(&ConcreteMode::DecryptRsaOaep));
        assert!(modes.contains(&ConcreteMode::SignEcdsaP384));
        assert!(modes.contains(&ConcreteMode::VerifyEcdsaP384));
    }
}
