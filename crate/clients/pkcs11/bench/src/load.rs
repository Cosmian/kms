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

use crate::{
    error::{BenchError, BenchResult},
    loader::Pkcs11Session,
};

const ED25519_SIGNATURE_LEN: usize = 64;
const RSA_2048_SIGNATURE_LEN: usize = 256;
/// DER-encoded `SEQUENCE { INTEGER r, INTEGER s }` for a P-256 signature is at most
/// 2 (SEQUENCE tag+len) + 2 * (2 (INTEGER tag+len) + 33 (sign byte + 32-byte scalar))
/// = 72 bytes. The actual encoded length varies call-to-call (leading zero bytes are
/// stripped), so callers must size the buffer to this maximum and use the length
/// `C_Sign` actually returns, not this constant, when reading the result.
const ECDSA_P256_SIGNATURE_MAX_LEN: usize = 72;

/// Which Cryptoki operation family to load-test (CLI-facing; `All` expands to every
/// [`ConcreteMode`] via [`BenchMode::expand`]).
///
/// Each mode is measured **independently** — mirroring `mise bench:load`'s own
/// per-operation granularity (one named `PreparedLoadOp` per algorithm/operation,
/// never a combined round trip) — so `encrypt`, `decrypt`, `sign`, and `verify` each
/// get their own concurrency sweep and their own row/chart in the report, instead of
/// being timed together as a single "encrypt-decrypt" round trip.
#[derive(Clone, Copy, Debug, clap::ValueEnum, PartialEq, Eq)]
pub(crate) enum BenchMode {
    /// Run every mode below in sequence.
    All,
    /// `C_EncryptInit`/`C_Encrypt` on an AES key.
    Encrypt,
    /// `C_DecryptInit`/`C_Decrypt` on an AES key (using ciphertext produced once
    /// during setup, not timed).
    Decrypt,
    /// Every signature algorithm the provider supports, one after another: RSA
    /// PKCS#1 v1.5-SHA256 (`CKM_SHA256_RSA_PKCS`), ECDSA P-256
    /// (`CKM_ECDSA`, pre-hashed), and — in `non-fips` builds — `EdDSA` Ed25519
    /// (`CKM_EDDSA`, PKCS#11 v3 message-signing). Expands to
    /// [`ConcreteMode::SignRsa`], [`ConcreteMode::SignEcdsa`], and (non-FIPS only)
    /// [`ConcreteMode::SignEdDsa`]; use `sign-rsa`/`sign-ecdsa`/`sign-eddsa` to
    /// benchmark a single algorithm instead.
    Sign,
    /// The `C_Verify` counterpart to [`Self::Sign`]: every verify algorithm the
    /// provider supports, one after another. Any algorithm not implemented by the
    /// loaded provider is skipped with a console notice (see
    /// [`ConcreteMode::VerifyRsa`]).
    Verify,
    /// `C_SignInit`/`C_Sign` on an RSA private key (`CKM_SHA256_RSA_PKCS`).
    #[value(name = "sign-rsa")]
    SignRsa,
    /// `C_VerifyInit`/`C_Verify` on an RSA public key (`CKM_SHA256_RSA_PKCS`).
    /// Skipped with a console notice if the loaded provider does not implement it
    /// (see [`ConcreteMode::VerifyRsa`]).
    #[value(name = "verify-rsa")]
    VerifyRsa,
    /// `C_SignInit`/`C_Sign` on an EC P-256 private key (`CKM_ECDSA`, a pre-computed
    /// SHA-256 digest — the mechanism itself performs no hashing).
    #[value(name = "sign-ecdsa")]
    SignEcdsa,
    /// `C_VerifyInit`/`C_Verify` on an EC P-256 public key (`CKM_ECDSA`). Skipped
    /// with a console notice if the loaded provider does not implement it (see
    /// [`ConcreteMode::VerifyRsa`]).
    #[value(name = "verify-ecdsa")]
    VerifyEcdsa,
    /// PKCS#11 v3 `C_MessageSignInit` once, then `C_SignMessage` per Ed25519
    /// message (`CKM_EDDSA`).
    #[value(name = "sign-eddsa")]
    SignEdDsa,
    /// `C_VerifyInit`/`C_Verify` on an Ed25519 public key (`CKM_EDDSA`). Skipped with
    /// a console notice if the loaded provider does not implement it (see
    /// [`ConcreteMode::VerifyRsa`]).
    #[value(name = "verify-eddsa")]
    VerifyEdDsa,
    /// `C_GenerateKey` + `C_DestroyObject` (ephemeral AES key per iteration).
    KeyCreation,
}

/// The concrete (non-`All`, non-`Sign`/`Verify`) operation families `run_all`
/// actually knows how to execute — kept as a separate type (rather than reusing
/// [`BenchMode`]) so that dispatch in [`run_all`] is exhaustive without an `All`
/// (or aggregate `Sign`/`Verify`) arm that could never be reached at that point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConcreteMode {
    Encrypt,
    Decrypt,
    SignRsa,
    VerifyRsa,
    SignEcdsa,
    VerifyEcdsa,
    SignEdDsa,
    VerifyEdDsa,
    KeyCreation,
}

impl ConcreteMode {
    /// The operation name used in report output (also becomes the report's
    /// `### <label>` section heading and SVG chart file name).
    const fn label(self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt/aes-cbc",
            Self::Decrypt => "decrypt/aes-cbc",
            Self::SignRsa => "sign/rsa-pkcs-sha256",
            Self::VerifyRsa => "verify/rsa-pkcs-sha256",
            Self::SignEcdsa => "sign/ecdsa-p256",
            Self::VerifyEcdsa => "verify/ecdsa-p256",
            Self::SignEdDsa => "sign/eddsa-ed25519",
            Self::VerifyEdDsa => "verify/eddsa-ed25519",
            Self::KeyCreation => "key-creation/aes",
        }
    }
}

impl BenchMode {
    /// Expands `All`/`Sign`/`Verify` to the concrete list of modes they represent;
    /// any other variant expands to the single matching [`ConcreteMode`].
    #[cfg(feature = "non-fips")]
    pub(crate) const fn expand(self) -> &'static [ConcreteMode] {
        match self {
            Self::All => &[
                ConcreteMode::Encrypt,
                ConcreteMode::Decrypt,
                ConcreteMode::SignRsa,
                ConcreteMode::SignEcdsa,
                ConcreteMode::SignEdDsa,
                ConcreteMode::VerifyRsa,
                ConcreteMode::VerifyEcdsa,
                ConcreteMode::VerifyEdDsa,
                ConcreteMode::KeyCreation,
            ],
            Self::Encrypt => &[ConcreteMode::Encrypt],
            Self::Decrypt => &[ConcreteMode::Decrypt],
            Self::Sign => &[
                ConcreteMode::SignRsa,
                ConcreteMode::SignEcdsa,
                ConcreteMode::SignEdDsa,
            ],
            Self::Verify => &[
                ConcreteMode::VerifyRsa,
                ConcreteMode::VerifyEcdsa,
                ConcreteMode::VerifyEdDsa,
            ],
            Self::SignRsa => &[ConcreteMode::SignRsa],
            Self::VerifyRsa => &[ConcreteMode::VerifyRsa],
            Self::SignEcdsa => &[ConcreteMode::SignEcdsa],
            Self::VerifyEcdsa => &[ConcreteMode::VerifyEcdsa],
            Self::SignEdDsa => &[ConcreteMode::SignEdDsa],
            Self::VerifyEdDsa => &[ConcreteMode::VerifyEdDsa],
            Self::KeyCreation => &[ConcreteMode::KeyCreation],
        }
    }

    /// FIPS expansion excludes Ed25519 modes (`Sign`/`Verify`/`All` silently drop
    /// them); selecting `sign-eddsa`/`verify-eddsa` explicitly returns an empty list
    /// so `main` can surface a clear feature-gating error instead.
    #[cfg(not(feature = "non-fips"))]
    pub(crate) const fn expand(self) -> &'static [ConcreteMode] {
        match self {
            Self::All => &[
                ConcreteMode::Encrypt,
                ConcreteMode::Decrypt,
                ConcreteMode::SignRsa,
                ConcreteMode::SignEcdsa,
                ConcreteMode::VerifyRsa,
                ConcreteMode::VerifyEcdsa,
                ConcreteMode::KeyCreation,
            ],
            Self::Encrypt => &[ConcreteMode::Encrypt],
            Self::Decrypt => &[ConcreteMode::Decrypt],
            Self::Sign => &[ConcreteMode::SignRsa, ConcreteMode::SignEcdsa],
            Self::Verify => &[ConcreteMode::VerifyRsa, ConcreteMode::VerifyEcdsa],
            Self::SignRsa => &[ConcreteMode::SignRsa],
            Self::VerifyRsa => &[ConcreteMode::VerifyRsa],
            Self::SignEcdsa => &[ConcreteMode::SignEcdsa],
            Self::VerifyEcdsa => &[ConcreteMode::VerifyEcdsa],
            Self::SignEdDsa | Self::VerifyEdDsa => &[],
            Self::KeyCreation => &[ConcreteMode::KeyCreation],
        }
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

    let secret_key = if modes
        .iter()
        .any(|mode| matches!(mode, ConcreteMode::Encrypt | ConcreteMode::Decrypt))
    {
        Some(setup_session.find_first_by_class(CKO_SECRET_KEY)?)
    } else {
        None
    };
    // Three private/public key pairs (RSA, EC P-256, and Ed25519) are provisioned
    // by `setup.rs`, so — unlike `secret_key` above — these must be disambiguated
    // by `CK_KEY_TYPE`, not just `CK_OBJECT_CLASS`.
    let private_key = if modes
        .iter()
        .any(|mode| matches!(mode, ConcreteMode::SignRsa | ConcreteMode::VerifyRsa))
    {
        Some(setup_session.find_first_by_class_and_key_type(CKO_PRIVATE_KEY, CKK_RSA)?)
    } else {
        None
    };
    let ecdsa_private_key = if modes
        .iter()
        .any(|mode| matches!(mode, ConcreteMode::SignEcdsa | ConcreteMode::VerifyEcdsa))
    {
        Some(setup_session.find_first_by_class_and_key_type(CKO_PRIVATE_KEY, CKK_EC)?)
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
    // Match `ckms bench --criterion`'s Ed25519 payload exactly so the raw-HTTP,
    // typed-client, and full PKCS#11 tiers differ only by client-side layers. Also
    // reused as the pre-computed digest for `CKM_ECDSA` (32 bytes ==
    // `signature_algorithm_to_kmip_params`'s SHA-256 default,
    // `crate/clients/pkcs11/provider/src/kms_object.rs`).
    let message = vec![0x42_u8; 32];

    // Ciphertext for the `Decrypt` sweep is produced once here (not timed) so the
    // sweep measures `C_Decrypt` alone, independent of `C_Encrypt`.
    let ciphertext = if modes.contains(&ConcreteMode::Decrypt) {
        let key = secret_key.ok_or_else(|| {
            BenchError::Setup("Decrypt mode requires a provisioned secret key".to_owned())
        })?;
        Some(setup_session.encrypt(key, &plaintext)?)
    } else {
        None
    };

    // The signature for the `VerifyRsa` sweep is produced once here (not timed), and
    // also doubles as the probe call that detects whether `C_Verify` is supported at
    // all by the loaded provider.
    let verify_signature = if modes.contains(&ConcreteMode::VerifyRsa) {
        let key = private_key.ok_or_else(|| {
            BenchError::Setup("VerifyRsa mode requires a provisioned RSA private key".to_owned())
        })?;
        Some(setup_session.sign(key, &message, CKM_SHA256_RSA_PKCS, RSA_2048_SIGNATURE_LEN)?)
    } else {
        None
    };
    // Likewise for `VerifyEcdsa`, signing the same 32-byte digest used by `SignEcdsa`.
    let verify_ecdsa_signature = if modes.contains(&ConcreteMode::VerifyEcdsa) {
        let key = ecdsa_private_key.ok_or_else(|| {
            BenchError::Setup("VerifyEcdsa mode requires a provisioned EC P-256 key".to_owned())
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
            ConcreteMode::Encrypt => {
                let Some(secret_key) = secret_key else {
                    continue;
                };
                let plaintext = plaintext.clone();
                Box::new(move |session: &Pkcs11Session<'a>| {
                    session.encrypt(secret_key, &plaintext)?;
                    Ok(())
                })
            }
            ConcreteMode::Decrypt => {
                let Some(secret_key) = secret_key else {
                    continue;
                };
                // Checked above: `ciphertext` is `Some` whenever `Decrypt` is requested.
                let Some(ciphertext) = ciphertext.clone() else {
                    continue;
                };
                Box::new(move |session: &Pkcs11Session<'a>| {
                    session.decrypt(secret_key, &ciphertext)?;
                    Ok(())
                })
            }
            ConcreteMode::SignRsa => {
                let Some(private_key) = private_key else {
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
            ConcreteMode::SignEcdsa => {
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
            ConcreteMode::VerifyRsa => {
                // Checked above: `verify_signature` is `Some` whenever `VerifyRsa`
                // is requested.
                let Some(signature) = verify_signature.clone() else {
                    continue;
                };
                let public_key =
                    setup_session.find_first_by_class_and_key_type(CKO_PUBLIC_KEY, CKK_RSA)?;
                match setup_session.verify(public_key, &message, &signature, CKM_SHA256_RSA_PKCS) {
                    Ok(()) => { /* supported: fall through to the closure below */ }
                    Err(e) if e.is_function_not_supported() => {
                        eprintln!(
                            "[bench:load-pkcs11] '{}' — C_Verify is not implemented by the \
                             loaded provider (CKR_FUNCTION_NOT_SUPPORTED); skipping",
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
            ConcreteMode::VerifyEcdsa => {
                // Checked above: `verify_ecdsa_signature` is `Some` whenever
                // `VerifyEcdsa` is requested.
                let Some(signature) = verify_ecdsa_signature.clone() else {
                    continue;
                };
                let public_key =
                    setup_session.find_first_by_class_and_key_type(CKO_PUBLIC_KEY, CKK_EC)?;
                match setup_session.verify(public_key, &message, &signature, CKM_ECDSA) {
                    Ok(()) => { /* supported: fall through to the closure below */ }
                    Err(e) if e.is_function_not_supported() => {
                        eprintln!(
                            "[bench:load-pkcs11] '{}' — C_Verify is not implemented by the \
                             loaded provider (CKR_FUNCTION_NOT_SUPPORTED); skipping",
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
                // Checked above: `eddsa_verify_signature` is `Some` whenever
                // `VerifyEdDsa` is requested.
                let Some(signature) = eddsa_verify_signature.clone() else {
                    continue;
                };
                let public_key = setup_session
                    .find_first_by_class_and_key_type(CKO_PUBLIC_KEY, CKK_EC_EDWARDS)?;
                match setup_session.verify(public_key, &message, &signature, CKM_EDDSA) {
                    Ok(()) => { /* supported: fall through to the closure below */ }
                    Err(e) if e.is_function_not_supported() => {
                        eprintln!(
                            "[bench:load-pkcs11] '{}' — C_Verify is not implemented by the \
                             loaded provider (CKR_FUNCTION_NOT_SUPPORTED); skipping",
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
