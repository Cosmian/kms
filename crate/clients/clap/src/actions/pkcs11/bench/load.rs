//! Concurrency-sweep load engine for the PKCS#11 benchmark, mirroring the
//! vocabulary (concurrency levels, p50/p95/p99, throughput) of
//! `crate/clients/clap/src/actions/bench/load.rs`'s KMIP REST load sweep, but driving
//! the real Cryptoki C API over a pool of dedicated `Pkcs11Session`s (one per
//! concurrent worker thread, or a single shared one under `--shared-session`)
//! instead.

use std::{
    thread,
    time::{Duration, Instant},
};

use pkcs11_sys::{
    CKK_EC, CKK_EC_EDWARDS, CKK_RSA, CKM_ECDSA, CKM_EDDSA, CKM_SHA256_RSA_PKCS, CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY, CKO_SECRET_KEY,
};

use super::{
    error::{BenchError, BenchResult},
    loader::Pkcs11Session,
};
use crate::actions::bench::types::{BenchFilter, BenchMode};

const ED25519_SIGNATURE_LEN: usize = 64;
const RSA_2048_SIGNATURE_LEN: usize = 256;
const ECDSA_P256_SIGNATURE_MAX_LEN: usize = 72;
const P256_EC_PARAMS_DER: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const SECP256K1_EC_PARAMS_DER: [u8; 7] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];
/// The concrete operation families `run_all` actually knows how to execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConcreteMode {
    EncryptAesCbc,
    EncryptAesGcm,
    EncryptRsaPkcs,
    DecryptAesCbc,
    DecryptAesGcm,
    DecryptRsaPkcs,
    SignRsaPkcs,
    SignRsaPss,
    VerifyRsaPkcs,
    VerifyRsaPss,
    SignEcdsaP256,
    VerifyEcdsaP256,
    #[cfg_attr(not(feature = "non-fips"), allow(dead_code))]
    SignSecp256k1,
    #[cfg_attr(not(feature = "non-fips"), allow(dead_code))]
    VerifySecp256k1,
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
            Self::DecryptAesCbc => "decrypt/aes-cbc",
            Self::DecryptAesGcm => "decrypt/aes-gcm",
            Self::DecryptRsaPkcs => "decrypt/rsa-pkcs",
            Self::SignRsaPkcs => "sign/rsa-pkcs-sha256",
            Self::SignRsaPss => "sign/rsa-pss-sha256",
            Self::VerifyRsaPkcs => "verify/rsa-pkcs-sha256",
            Self::VerifyRsaPss => "verify/rsa-pss-sha256",
            Self::SignEcdsaP256 => "sign/ecdsa-p256",
            Self::VerifyEcdsaP256 => "verify/ecdsa-p256",
            Self::SignSecp256k1 => "sign/ecdsa-secp256k1",
            Self::VerifySecp256k1 => "verify/ecdsa-secp256k1",
            Self::SignEdDsa => "sign/eddsa-ed25519",
            Self::VerifyEdDsa => "verify/eddsa-ed25519",
            Self::KeyCreation => "key-creation/aes",
            Self::Batch => "batch/aes-cbc",
        }
    }
}

/// Expands standard `BenchMode` to concrete PKCS#11 benchmark modes.
#[must_use]
pub(crate) fn expand_bench_mode(
    mode: BenchMode,
    filter: Option<&BenchFilter>,
) -> Vec<ConcreteMode> {
    let modes = match mode {
        BenchMode::All => {
            #[cfg(feature = "non-fips")]
            {
                vec![
                    ConcreteMode::EncryptAesCbc,
                    ConcreteMode::EncryptAesGcm,
                    ConcreteMode::EncryptRsaPkcs,
                    ConcreteMode::DecryptAesCbc,
                    ConcreteMode::DecryptAesGcm,
                    ConcreteMode::DecryptRsaPkcs,
                    ConcreteMode::SignRsaPkcs,
                    ConcreteMode::SignRsaPss,
                    ConcreteMode::SignEcdsaP256,
                    ConcreteMode::SignSecp256k1,
                    ConcreteMode::SignEdDsa,
                    ConcreteMode::VerifyRsaPkcs,
                    ConcreteMode::VerifyRsaPss,
                    ConcreteMode::VerifyEcdsaP256,
                    ConcreteMode::VerifySecp256k1,
                    ConcreteMode::VerifyEdDsa,
                    ConcreteMode::KeyCreation,
                    ConcreteMode::Batch,
                ]
            }
            #[cfg(not(feature = "non-fips"))]
            {
                vec![
                    ConcreteMode::EncryptAesCbc,
                    ConcreteMode::EncryptAesGcm,
                    ConcreteMode::EncryptRsaPkcs,
                    ConcreteMode::DecryptAesCbc,
                    ConcreteMode::DecryptAesGcm,
                    ConcreteMode::DecryptRsaPkcs,
                    ConcreteMode::SignRsaPkcs,
                    ConcreteMode::SignRsaPss,
                    ConcreteMode::SignEcdsaP256,
                    ConcreteMode::VerifyRsaPkcs,
                    ConcreteMode::VerifyRsaPss,
                    ConcreteMode::VerifyEcdsaP256,
                    ConcreteMode::KeyCreation,
                    ConcreteMode::Batch,
                ]
            }
        }
        BenchMode::Encrypt => vec![
            ConcreteMode::EncryptAesCbc,
            ConcreteMode::EncryptAesGcm,
            ConcreteMode::EncryptRsaPkcs,
            ConcreteMode::DecryptAesCbc,
            ConcreteMode::DecryptAesGcm,
            ConcreteMode::DecryptRsaPkcs,
        ],
        BenchMode::SignVerify => {
            #[cfg(feature = "non-fips")]
            {
                vec![
                    ConcreteMode::SignRsaPkcs,
                    ConcreteMode::SignRsaPss,
                    ConcreteMode::SignEcdsaP256,
                    ConcreteMode::SignSecp256k1,
                    ConcreteMode::SignEdDsa,
                    ConcreteMode::VerifyRsaPkcs,
                    ConcreteMode::VerifyRsaPss,
                    ConcreteMode::VerifyEcdsaP256,
                    ConcreteMode::VerifySecp256k1,
                    ConcreteMode::VerifyEdDsa,
                ]
            }
            #[cfg(not(feature = "non-fips"))]
            {
                vec![
                    ConcreteMode::SignRsaPkcs,
                    ConcreteMode::SignRsaPss,
                    ConcreteMode::SignEcdsaP256,
                    ConcreteMode::VerifyRsaPkcs,
                    ConcreteMode::VerifyRsaPss,
                    ConcreteMode::VerifyEcdsaP256,
                ]
            }
        }
        BenchMode::KeyCreation => vec![ConcreteMode::KeyCreation],
        BenchMode::Batch => vec![ConcreteMode::Batch],
    };

    if let Some(f) = filter {
        modes
            .into_iter()
            .filter(|m| f.matches(m.label(), None))
            .collect()
    } else {
        modes
    }
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
/// Takes `&Pkcs11Session` because each worker thread now gets its own dedicated
/// session from the pool built in `main.rs` (see [`run_for`]), rather than every
/// thread sharing one handle.
pub(crate) type Op<'a> = dyn Fn(&Pkcs11Session<'a>) -> BenchResult<()> + Send + Sync + 'a;
pub(crate) type SetupOp<'a> = dyn Fn(&[Pkcs11Session<'a>]) -> BenchResult<()> + Send + Sync + 'a;

/// One mode's report label plus its ready-to-run [`Op`] closure, as produced by
/// [`prepare_ops`].
pub(crate) struct PreparedOp<'a> {
    pub(crate) label: &'static str,
    pub(crate) setup: Option<Box<SetupOp<'a>>>,
    pub(crate) op: Box<Op<'a>>,
}

/// Runs the full concurrency sweep for one named operation and returns one
/// [`LoadResult`] per concurrency level.
fn run_sweep<'a>(
    operation: &str,
    pool: &[Pkcs11Session<'a>],
    op: &Op<'a>,
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
/// `main.rs`'s `--shared-session` flag) instead reproduces the old
/// every-thread-shares-one-handle model, for direct before/after comparison.
fn run_for<'a>(
    pool: &[Pkcs11Session<'a>],
    op: &Op<'a>,
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
/// `VerifyRsa`/`VerifyEcdsa`/`VerifyEdDsa` are each probed once here; if the loaded provider reports
/// `CKR_FUNCTION_NOT_SUPPORTED` (see [`Pkcs11Session::verify`]'s doc comment), the
/// mode is skipped with a console notice and simply absent from the returned list —
/// mirroring `mise bench:load`'s own pattern of skipping a benchmark it cannot
/// prepare (e.g. a key-creation failure) rather than reporting fabricated numbers.
pub(crate) fn prepare_ops<'a>(
    modes: &[ConcreteMode],
    pool: &[Pkcs11Session<'a>],
) -> BenchResult<Vec<PreparedOp<'a>>> {
    // Any pooled session works for one-time setup/object-discovery calls below:
    // `crate/clients/pkcs11/module/src/objects_store.rs`'s object store is global,
    // not scoped per session, so a handle found via one session remains valid when
    // used (e.g. in `C_SignInit`) via any other session in the pool.
    let setup_session = pool
        .first()
        .ok_or_else(|| BenchError::Setup("empty PKCS#11 session pool".to_owned()))?;

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
        Some(setup_session.find_first_by_class(CKO_SECRET_KEY)?)
    } else {
        None
    };
    let rsa_public_key = if modes.iter().any(|mode| {
        matches!(
            mode,
            ConcreteMode::EncryptRsaPkcs | ConcreteMode::VerifyRsaPkcs | ConcreteMode::VerifyRsaPss
        )
    }) {
        Some(setup_session.find_first_by_class_and_key_type(CKO_PUBLIC_KEY, CKK_RSA)?)
    } else {
        None
    };
    let rsa_private_key = if modes.iter().any(|mode| {
        matches!(
            mode,
            ConcreteMode::DecryptRsaPkcs | ConcreteMode::SignRsaPkcs | ConcreteMode::SignRsaPss
        )
    }) {
        Some(setup_session.find_first_by_class_and_key_type(CKO_PRIVATE_KEY, CKK_RSA)?)
    } else {
        None
    };
    let ecdsa_private_key = if modes.iter().any(|mode| {
        matches!(
            mode,
            ConcreteMode::SignEcdsaP256 | ConcreteMode::VerifyEcdsaP256
        )
    }) {
        Some(setup_session.find_first_by_class_key_type_and_ec_params(
            CKO_PRIVATE_KEY,
            CKK_EC,
            &P256_EC_PARAMS_DER,
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
        Some(setup_session.find_first_by_class_key_type_and_ec_params(
            CKO_PRIVATE_KEY,
            CKK_EC,
            &SECP256K1_EC_PARAMS_DER,
        )?)
    } else {
        None
    };
    let eddsa_private_key = if modes
        .iter()
        .any(|mode| matches!(mode, ConcreteMode::SignEdDsa | ConcreteMode::VerifyEdDsa))
    {
        Some(setup_session.find_first_by_class_and_key_type(CKO_PRIVATE_KEY, CKK_EC_EDWARDS)?)
    } else {
        None
    };
    let plaintext = vec![0x42_u8; 4096];
    let message = vec![0x42_u8; 32];

    let ciphertext_cbc = if modes.contains(&ConcreteMode::DecryptAesCbc) {
        let key = secret_key.ok_or_else(|| {
            BenchError::Setup("DecryptAesCbc requires a provisioned secret key".to_owned())
        })?;
        Some(setup_session.encrypt(key, &plaintext)?)
    } else {
        None
    };
    let ciphertext_gcm = if modes.contains(&ConcreteMode::DecryptAesGcm) {
        let key = secret_key.ok_or_else(|| {
            BenchError::Setup("DecryptAesGcm requires a provisioned secret key".to_owned())
        })?;
        Some(setup_session.encrypt_gcm(key, &plaintext)?)
    } else {
        None
    };
    let ciphertext_rsa = if modes.contains(&ConcreteMode::DecryptRsaPkcs) {
        let key = rsa_public_key.ok_or_else(|| {
            BenchError::Setup("DecryptRsaPkcs requires a provisioned RSA public key".to_owned())
        })?;
        Some(setup_session.encrypt_rsa(key, &message)?)
    } else {
        None
    };

    let verify_rsa_signature = if modes.contains(&ConcreteMode::VerifyRsaPkcs) {
        let key = rsa_private_key.ok_or_else(|| {
            BenchError::Setup(
                "VerifyRsaPkcs mode requires a provisioned RSA private key".to_owned(),
            )
        })?;
        Some(setup_session.sign(key, &message, CKM_SHA256_RSA_PKCS, RSA_2048_SIGNATURE_LEN)?)
    } else {
        None
    };
    let verify_rsa_pss_signature = if modes.contains(&ConcreteMode::VerifyRsaPss) {
        let key = rsa_private_key.ok_or_else(|| {
            BenchError::Setup("VerifyRsaPss mode requires a provisioned RSA private key".to_owned())
        })?;
        let mut sig = vec![0_u8; RSA_2048_SIGNATURE_LEN];
        setup_session.sign_pss_into(key, &message, &mut sig)?;
        Some(sig)
    } else {
        None
    };
    // Likewise for `VerifyEcdsa`, signing the same 32-byte digest used by `SignEcdsa`.
    let verify_ecdsa_signature = if modes.contains(&ConcreteMode::VerifyEcdsaP256) {
        let key = ecdsa_private_key.ok_or_else(|| {
            BenchError::Setup("VerifyEcdsaP256 mode requires a provisioned EC P-256 key".to_owned())
        })?;
        Some(setup_session.sign(key, &message, CKM_ECDSA, ECDSA_P256_SIGNATURE_MAX_LEN)?)
    } else {
        None
    };
    // Likewise for `VerifySecp256k1`, signing the same 32-byte digest used by
    // `SignSecp256k1`.
    let verify_secp256k1_signature = if modes.contains(&ConcreteMode::VerifySecp256k1) {
        let key = secp256k1_private_key.ok_or_else(|| {
            BenchError::Setup(
                "VerifySecp256k1 mode requires a provisioned secp256k1 key".to_owned(),
            )
        })?;
        Some(setup_session.sign(key, &message, CKM_ECDSA, ECDSA_P256_SIGNATURE_MAX_LEN)?)
    } else {
        None
    };
    let eddsa_verify_signature = if modes.contains(&ConcreteMode::VerifyEdDsa) {
        let key = eddsa_private_key.ok_or_else(|| {
            BenchError::Setup("VerifyEdDsa mode requires a provisioned Ed25519 key".to_owned())
        })?;
        setup_session.message_sign_init(key, CKM_EDDSA)?;
        let mut signature = vec![0_u8; ED25519_SIGNATURE_LEN];
        let signature_len = setup_session.sign_message_into(&message, &mut signature)?;
        setup_session.message_sign_final()?;
        signature.truncate(signature_len);
        Some(signature)
    } else {
        None
    };

    let mut prepared = Vec::new();
    for mode in modes {
        let mut setup: Option<Box<SetupOp<'a>>> = None;
        let op: Box<Op<'a>> = match mode {
            ConcreteMode::EncryptAesCbc => {
                let Some(secret_key) = secret_key else {
                    continue;
                };
                let plaintext = plaintext.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    session.encrypt(secret_key, &plaintext)?;
                    Ok(())
                })
            }
            ConcreteMode::EncryptAesGcm => {
                let Some(secret_key) = secret_key else {
                    continue;
                };
                let plaintext = plaintext.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    session.encrypt_gcm(secret_key, &plaintext)?;
                    Ok(())
                })
            }
            ConcreteMode::EncryptRsaPkcs => {
                let Some(rsa_public_key) = rsa_public_key else {
                    continue;
                };
                let message = message.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    session.encrypt_rsa(rsa_public_key, &message)?;
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
                Box::new(move |session: &Pkcs11Session<'a>| {
                    session.decrypt(secret_key, &ciphertext)?;
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
                Box::new(move |session: &Pkcs11Session<'a>| {
                    session.decrypt_gcm(secret_key, &ciphertext)?;
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
                Box::new(move |session: &Pkcs11Session<'a>| {
                    session.decrypt_rsa(rsa_private_key, &ciphertext)?;
                    Ok(())
                })
            }
            ConcreteMode::SignRsaPkcs => {
                let Some(private_key) = rsa_private_key else {
                    continue;
                };
                let message = message.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    let mut signature = [0_u8; RSA_2048_SIGNATURE_LEN];
                    session.sign_into(
                        private_key,
                        &message,
                        CKM_SHA256_RSA_PKCS,
                        &mut signature,
                    )?;
                    Ok(())
                })
            }
            ConcreteMode::SignRsaPss => {
                let Some(private_key) = rsa_private_key else {
                    continue;
                };
                let message = message.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    let mut signature = [0_u8; RSA_2048_SIGNATURE_LEN];
                    session.sign_pss_into(private_key, &message, &mut signature)?;
                    Ok(())
                })
            }
            ConcreteMode::SignEcdsaP256 => {
                let Some(ecdsa_private_key) = ecdsa_private_key else {
                    continue;
                };
                let message = message.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    let mut signature = [0_u8; ECDSA_P256_SIGNATURE_MAX_LEN];
                    session.sign_into(ecdsa_private_key, &message, CKM_ECDSA, &mut signature)?;
                    Ok(())
                })
            }
            ConcreteMode::SignSecp256k1 => {
                let Some(secp256k1_private_key) = secp256k1_private_key else {
                    continue;
                };
                let message = message.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    let mut signature = [0_u8; ECDSA_P256_SIGNATURE_MAX_LEN];
                    session.sign_into(
                        secp256k1_private_key,
                        &message,
                        CKM_ECDSA,
                        &mut signature,
                    )?;
                    Ok(())
                })
            }
            ConcreteMode::SignEdDsa => {
                let Some(eddsa_private_key) = eddsa_private_key else {
                    continue;
                };
                setup = Some(Box::new(move |sessions: &[Pkcs11Session<'a>]| {
                    sessions.iter().try_for_each(|session| {
                        session.message_sign_init(eddsa_private_key, CKM_EDDSA)
                    })
                }));
                let message = message.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    let mut signature = [0_u8; ED25519_SIGNATURE_LEN];
                    session.sign_message_into(&message, &mut signature)?;
                    Ok(())
                })
            }
            ConcreteMode::VerifyRsaPkcs => {
                let Some(signature) = verify_rsa_signature.clone() else {
                    continue;
                };
                let public_key =
                    setup_session.find_first_by_class_and_key_type(CKO_PUBLIC_KEY, CKK_RSA)?;
                match setup_session.verify(public_key, &message, &signature, CKM_SHA256_RSA_PKCS) {
                    Ok(()) => {}
                    Err(e) if e.is_function_not_supported() => {
                        eprintln!(
                            "[bench:load-pkcs11] '{}' — C_Verify is not implemented (CKR_FUNCTION_NOT_SUPPORTED); skipping",
                            mode.label()
                        );
                        continue;
                    }
                    Err(e) => return Err(e),
                }
                let message = message.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    session.verify(public_key, &message, &signature, CKM_SHA256_RSA_PKCS)
                })
            }
            ConcreteMode::VerifyRsaPss => {
                let Some(signature) = verify_rsa_pss_signature.clone() else {
                    continue;
                };
                let public_key =
                    setup_session.find_first_by_class_and_key_type(CKO_PUBLIC_KEY, CKK_RSA)?;
                let message = message.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    session.verify_pss(public_key, &message, &signature)
                })
            }
            ConcreteMode::VerifyEcdsaP256 => {
                let Some(signature) = verify_ecdsa_signature.clone() else {
                    continue;
                };
                let public_key = setup_session.find_first_by_class_key_type_and_ec_params(
                    CKO_PUBLIC_KEY,
                    CKK_EC,
                    &P256_EC_PARAMS_DER,
                )?;
                match setup_session.verify(public_key, &message, &signature, CKM_ECDSA) {
                    Ok(()) => {}
                    Err(e) if e.is_function_not_supported() => {
                        eprintln!(
                            "[bench:load-pkcs11] '{}' — C_Verify is not implemented (CKR_FUNCTION_NOT_SUPPORTED); skipping",
                            mode.label()
                        );
                        continue;
                    }
                    Err(e) => return Err(e),
                }
                let message = message.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    session.verify(public_key, &message, &signature, CKM_ECDSA)
                })
            }
            ConcreteMode::VerifySecp256k1 => {
                let Some(signature) = verify_secp256k1_signature.clone() else {
                    continue;
                };
                let public_key = setup_session.find_first_by_class_key_type_and_ec_params(
                    CKO_PUBLIC_KEY,
                    CKK_EC,
                    &SECP256K1_EC_PARAMS_DER,
                )?;
                match setup_session.verify(public_key, &message, &signature, CKM_ECDSA) {
                    Ok(()) => {}
                    Err(e) if e.is_function_not_supported() => {
                        eprintln!(
                            "[bench:load-pkcs11] '{}' — C_Verify is not implemented (CKR_FUNCTION_NOT_SUPPORTED); skipping",
                            mode.label()
                        );
                        continue;
                    }
                    Err(e) => return Err(e),
                }
                let message = message.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    session.verify(public_key, &message, &signature, CKM_ECDSA)
                })
            }
            ConcreteMode::VerifyEdDsa => {
                let Some(signature) = eddsa_verify_signature.clone() else {
                    continue;
                };
                let public_key = setup_session
                    .find_first_by_class_and_key_type(CKO_PUBLIC_KEY, CKK_EC_EDWARDS)?;
                match setup_session.verify(public_key, &message, &signature, CKM_EDDSA) {
                    Ok(()) => {}
                    Err(e) if e.is_function_not_supported() => {
                        eprintln!(
                            "[bench:load-pkcs11] '{}' — C_Verify is not implemented (CKR_FUNCTION_NOT_SUPPORTED); skipping",
                            mode.label()
                        );
                        continue;
                    }
                    Err(e) => return Err(e),
                }
                let message = message.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    session.verify(public_key, &message, &signature, CKM_EDDSA)
                })
            }
            ConcreteMode::KeyCreation => {
                Box::new(move |session: &Pkcs11Session<'a>| session.generate_and_destroy_key())
            }
            ConcreteMode::Batch => {
                let Some(secret_key) = secret_key else {
                    continue;
                };
                let plaintext = plaintext.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    for _ in 0..10 {
                        session.encrypt(secret_key, &plaintext)?;
                    }
                    Ok(())
                })
            }
        };
        prepared.push(PreparedOp {
            label: mode.label(),
            setup,
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
    pool: &[Pkcs11Session<'_>],
    config: &SweepConfig,
) -> BenchResult<Vec<LoadResult>> {
    let prepared = prepare_ops(modes, pool)?;
    let mut all_results = Vec::with_capacity(prepared.len());
    for PreparedOp { label, setup, op } in prepared {
        if let Some(setup) = setup {
            setup(pool)?;
        }
        all_results.extend(run_sweep(label, pool, &*op, config)?);
        if label == "sign/eddsa-ed25519" {
            pool.iter()
                .try_for_each(Pkcs11Session::message_sign_final)?;
        }
    }
    Ok(all_results)
}
