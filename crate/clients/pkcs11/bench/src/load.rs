//! Concurrency-sweep load engine for the PKCS#11 benchmark, mirroring the
//! vocabulary (concurrency levels, p50/p95/p99, throughput) of
//! `crate/clients/clap/src/actions/bench/load.rs`'s KMIP REST load sweep, but driving
//! the real Cryptoki C API over a single, shared `Pkcs11Session` instead.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use pkcs11_sys::{CK_OBJECT_HANDLE, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY};

use crate::{error::BenchResult, loader::Pkcs11Session};

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
    /// `C_SignInit`/`C_Sign` on an RSA private key.
    Sign,
    /// `C_VerifyInit`/`C_Verify` on an RSA public key. Skipped with a console notice
    /// if the loaded provider does not implement it (see [`ConcreteMode::Verify`]).
    Verify,
    /// `C_GenerateKey` + `C_DestroyObject` (ephemeral AES key per iteration).
    KeyCreation,
}

/// The concrete (non-`All`) operation families `run_all` actually knows how to
/// execute — kept as a separate type (rather than reusing [`BenchMode`]) so that
/// dispatch in [`run_all`] is exhaustive without an `All` arm that could never be
/// reached at that point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConcreteMode {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    KeyCreation,
}

impl ConcreteMode {
    /// The operation name used in report output (also becomes the report's
    /// `### <label>` section heading and SVG chart file name).
    const fn label(self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt/aes-cbc",
            Self::Decrypt => "decrypt/aes-cbc",
            Self::Sign => "sign/rsa-pkcs-sha256",
            Self::Verify => "verify/rsa-pkcs-sha256",
            Self::KeyCreation => "key-creation/aes",
        }
    }
}

impl BenchMode {
    /// Expands `All` to the concrete list of modes it represents; any other
    /// variant expands to the single matching [`ConcreteMode`].
    pub(crate) const fn expand(self) -> &'static [ConcreteMode] {
        match self {
            Self::All => &[
                ConcreteMode::Encrypt,
                ConcreteMode::Decrypt,
                ConcreteMode::Sign,
                ConcreteMode::Verify,
                ConcreteMode::KeyCreation,
            ],
            Self::Encrypt => &[ConcreteMode::Encrypt],
            Self::Decrypt => &[ConcreteMode::Decrypt],
            Self::Sign => &[ConcreteMode::Sign],
            Self::Verify => &[ConcreteMode::Verify],
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
/// Takes `&Pkcs11Session` (shared, not owned) because the session — and the single
/// Cryptoki handle it wraps — is intentionally reused by every thread: see
/// `Pkcs11Session`'s doc comment for why this models real-world single-session
/// contention.
type Op<'a> = dyn Fn(&Pkcs11Session<'a>) -> BenchResult<()> + Send + Sync + 'a;

/// Runs the full concurrency sweep for one named operation and returns one
/// [`LoadResult`] per concurrency level.
fn run_sweep<'a>(
    operation: &str,
    session: &Pkcs11Session<'a>,
    op: &Op<'a>,
    config: &SweepConfig,
) -> Vec<LoadResult> {
    let mut results = Vec::with_capacity(config.concurrency_levels.len());

    for &concurrency in &config.concurrency_levels {
        if !config.warmup_time.is_zero() {
            run_for(session, op, concurrency, config.warmup_time);
        }

        let (latencies, elapsed) = run_for(session, op, concurrency, config.measure_time);
        results.push(summarize(operation, concurrency, &latencies, elapsed));

        if !config.cooldown_time.is_zero() {
            thread::sleep(config.cooldown_time);
        }
    }

    results
}

/// Spawns `concurrency` threads, each hammering `op` against the shared `session`
/// for `duration`, and returns every observed per-call latency plus the actual
/// wall-clock time spent (used to compute throughput).
fn run_for<'a>(
    session: &Pkcs11Session<'a>,
    op: &Op<'a>,
    concurrency: usize,
    duration: Duration,
) -> (Vec<Duration>, Duration) {
    let stop_after = Instant::now() + duration;
    let error_count = Arc::new(AtomicUsize::new(0));

    let start = Instant::now();
    let per_thread_latencies: Vec<Vec<Duration>> = thread::scope(|scope| {
        // `.collect()` here is required, not needless: every `scope.spawn` must run
        // before the `.join()` pass below, otherwise threads would be spawned and
        // joined one at a time — serializing the very concurrency this benchmark
        // measures.
        #[allow(clippy::needless_collect)]
        let handles: Vec<_> = (0..concurrency.max(1))
            .map(|_| {
                let error_count = Arc::clone(&error_count);
                scope.spawn(move || {
                    let mut latencies = Vec::new();
                    while Instant::now() < stop_after {
                        let call_start = Instant::now();
                        let ok = op(session).is_ok();
                        let elapsed = call_start.elapsed();
                        if ok {
                            latencies.push(elapsed);
                        } else {
                            error_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    latencies
                })
            })
            .collect();
        handles
            .into_iter()
            // A worker thread only panics on a logic bug in this harness (not on a
            // Cryptoki error, which is captured as `Err` above). Treat a panicking
            // thread as having contributed zero samples rather than aborting the
            // whole sweep, but log it loudly so the bug is not silently lost.
            .map(|h| {
                h.join().unwrap_or_else(|_| {
                    cosmian_logger::error!("a benchmark worker thread panicked");
                    Vec::new()
                })
            })
            .collect()
    });
    let elapsed = start.elapsed();

    let errors = error_count.load(Ordering::Relaxed);
    if errors > 0 {
        cosmian_logger::warn!("{errors} PKCS#11 call(s) failed during this measurement window");
    }

    (
        per_thread_latencies.into_iter().flatten().collect(),
        elapsed,
    )
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

/// Runs every mode in `modes` and returns the combined list of results, in order.
///
/// `Verify` is attempted once during setup; if the loaded provider reports
/// `CKR_FUNCTION_NOT_SUPPORTED` (see [`Pkcs11Session::verify`]'s doc comment), it is
/// skipped with a console notice and excluded from the returned results — mirroring
/// `mise bench:load`'s own pattern of skipping a benchmark it cannot prepare (e.g. a
/// key-creation failure) rather than reporting fabricated numbers.
pub(crate) fn run_all<'a>(
    modes: &[ConcreteMode],
    session: &Pkcs11Session<'a>,
    config: &SweepConfig,
) -> BenchResult<Vec<LoadResult>> {
    let secret_key: CK_OBJECT_HANDLE = session.find_first_by_class(CKO_SECRET_KEY)?;
    let private_key: CK_OBJECT_HANDLE = session.find_first_by_class(CKO_PRIVATE_KEY)?;
    let plaintext = vec![0x42_u8; 4096];
    let message = vec![0x24_u8; 256];

    // Ciphertext for the `Decrypt` sweep is produced once here (not timed) so the
    // sweep measures `C_Decrypt` alone, independent of `C_Encrypt`.
    let ciphertext = if modes.contains(&ConcreteMode::Decrypt) {
        Some(session.encrypt(secret_key, &plaintext)?)
    } else {
        None
    };

    // The signature for the `Verify` sweep is produced once here (not timed), and
    // also doubles as the probe call that detects whether `C_Verify` is supported at
    // all by the loaded provider.
    let verify_signature = if modes.contains(&ConcreteMode::Verify) {
        Some(session.sign(private_key, &message)?)
    } else {
        None
    };

    let mut all_results = Vec::new();
    for mode in modes {
        let results = match mode {
            ConcreteMode::Encrypt => {
                let plaintext = plaintext.clone();
                let op: Box<Op<'a>> = Box::new(move |session: &Pkcs11Session<'a>| {
                    session.encrypt(secret_key, &plaintext)?;
                    Ok(())
                });
                run_sweep(mode.label(), session, &*op, config)
            }
            ConcreteMode::Decrypt => {
                // Checked above: `ciphertext` is `Some` whenever `Decrypt` is requested.
                let Some(ciphertext) = ciphertext.clone() else {
                    continue;
                };
                let op: Box<Op<'a>> = Box::new(move |session: &Pkcs11Session<'a>| {
                    session.decrypt(secret_key, &ciphertext)?;
                    Ok(())
                });
                run_sweep(mode.label(), session, &*op, config)
            }
            ConcreteMode::Sign => {
                let message = message.clone();
                let op: Box<Op<'a>> = Box::new(move |session: &Pkcs11Session<'a>| {
                    session.sign(private_key, &message)?;
                    Ok(())
                });
                run_sweep(mode.label(), session, &*op, config)
            }
            ConcreteMode::Verify => {
                // Checked above: `verify_signature` is `Some` whenever `Verify` is
                // requested.
                let Some(signature) = verify_signature.clone() else {
                    continue;
                };
                let public_key = session.find_first_by_class(CKO_PUBLIC_KEY)?;
                match session.verify(public_key, &message, &signature) {
                    Ok(()) => { /* supported: fall through to the sweep below */ }
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
                let op: Box<Op<'a>> = Box::new(move |session: &Pkcs11Session<'a>| {
                    session.verify(public_key, &message, &signature)
                });
                run_sweep(mode.label(), session, &*op, config)
            }
            ConcreteMode::KeyCreation => {
                let op: Box<Op<'a>> =
                    Box::new(move |session: &Pkcs11Session<'a>| session.generate_and_destroy_key());
                run_sweep(mode.label(), session, &*op, config)
            }
        };
        all_results.extend(results);
    }
    Ok(all_results)
}
