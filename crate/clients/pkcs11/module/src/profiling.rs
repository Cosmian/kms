//! Compile-time-only PKCS#11 Sign profiling primitives.
//!
//! The `benchmarking` feature is enabled only for `mise bench:load-pkcs11`.
//! Without it, all helpers inline to no-ops and production builds contain no
//! clocks or atomic updates on the signing hot path.

/// Number of latency buckets per phase: exact nanoseconds for 0..31 ns, then
/// two logarithmic sub-buckets per power of two through `u64::MAX`.
pub const SIGN_PROFILE_BUCKETS: usize = 150;

/// Sign phases recorded across the PKCS#11 module/provider boundary.
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum SignPhase {
    /// Work inside the `C_Sign` implementation (excluding the exported wrapper).
    CSignBody = 0,
    /// Session-map read lock, lookup, and `Arc` clone.
    SessionMapLookup = 1,
    /// Wait to acquire the selected session's mutex.
    SessionLockWait = 2,
    /// The callback executed while the selected session is locked.
    SessionCallback = 3,
    /// Dispatch from `Session::sign` through the private-key trait.
    PrivateKeySign = 4,
    /// Lookup and clone of the globally registered backend.
    BackendLookup = 5,
    /// Backend `remote_sign` dispatch into the provider.
    BackendRemoteSign = 6,
    /// PKCS#11 algorithm mapping and owned KMIP Sign request construction.
    RequestBuild = 7,
    /// Synchronous-to-async Tokio `Runtime::block_on` boundary, including its future.
    RuntimeBlockOn = 8,
    /// Typed `KmsClient::sign` call, including serialization, HTTP, and response parsing.
    KmsClientSign = 9,
    /// Copying the returned signature into the caller's output buffer.
    SignatureCopy = 10,
}

/// Number of [`SignPhase`] variants.
pub const SIGN_PROFILE_PHASES: usize = 11;

impl SignPhase {
    #[cfg(feature = "benchmarking")]
    const fn index(self) -> usize {
        match self {
            Self::CSignBody => 0,
            Self::SessionMapLookup => 1,
            Self::SessionLockWait => 2,
            Self::SessionCallback => 3,
            Self::PrivateKeySign => 4,
            Self::BackendLookup => 5,
            Self::BackendRemoteSign => 6,
            Self::RequestBuild => 7,
            Self::RuntimeBlockOn => 8,
            Self::KmsClientSign => 9,
            Self::SignatureCopy => 10,
        }
    }

    /// Stable phase name written to benchmark JSON.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CSignBody => "c-sign-body",
            Self::SessionMapLookup => "session-map-lookup",
            Self::SessionLockWait => "session-lock-wait",
            Self::SessionCallback => "session-callback",
            Self::PrivateKeySign => "private-key-sign",
            Self::BackendLookup => "backend-lookup",
            Self::BackendRemoteSign => "backend-remote-sign",
            Self::RequestBuild => "request-build",
            Self::RuntimeBlockOn => "runtime-block-on",
            Self::KmsClientSign => "kms-client-sign",
            Self::SignatureCopy => "signature-copy",
        }
    }
}

/// Snapshot of one phase's aggregate counters and logarithmic histogram.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignPhaseSnapshot {
    /// Number of observations.
    pub count: u64,
    /// Sum of all observations in nanoseconds.
    pub total_ns: u64,
    /// Maximum observation in nanoseconds.
    pub max_ns: u64,
    /// Log2 nanosecond histogram buckets.
    pub buckets: [u64; SIGN_PROFILE_BUCKETS],
}

impl Default for SignPhaseSnapshot {
    fn default() -> Self {
        Self {
            count: 0,
            total_ns: 0,
            max_ns: 0,
            buckets: [0; SIGN_PROFILE_BUCKETS],
        }
    }
}

/// Complete C-compatible Sign profiling snapshot.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignProfileSnapshot {
    /// Per-phase snapshots indexed by [`SignPhase`] discriminant.
    pub phases: [SignPhaseSnapshot; SIGN_PROFILE_PHASES],
}

impl Default for SignProfileSnapshot {
    fn default() -> Self {
        Self {
            phases: [SignPhaseSnapshot::default(); SIGN_PROFILE_PHASES],
        }
    }
}

#[cfg(feature = "benchmarking")]
mod enabled {
    use std::{
        cell::Cell,
        sync::atomic::{AtomicU64, Ordering},
        time::Instant,
    };

    use super::{
        SIGN_PROFILE_BUCKETS, SIGN_PROFILE_PHASES, SignPhase, SignPhaseSnapshot,
        SignProfileSnapshot,
    };

    struct PhaseStats {
        count: AtomicU64,
        total_ns: AtomicU64,
        max_ns: AtomicU64,
        buckets: [AtomicU64; SIGN_PROFILE_BUCKETS],
    }

    impl PhaseStats {
        const fn new() -> Self {
            Self {
                count: AtomicU64::new(0),
                total_ns: AtomicU64::new(0),
                max_ns: AtomicU64::new(0),
                buckets: [const { AtomicU64::new(0) }; SIGN_PROFILE_BUCKETS],
            }
        }

        fn reset(&self) {
            self.count.store(0, Ordering::Relaxed);
            self.total_ns.store(0, Ordering::Relaxed);
            self.max_ns.store(0, Ordering::Relaxed);
            for bucket in &self.buckets {
                bucket.store(0, Ordering::Relaxed);
            }
        }

        fn record(&self, elapsed_ns: u64) {
            self.count.fetch_add(1, Ordering::Relaxed);
            self.total_ns.fetch_add(elapsed_ns, Ordering::Relaxed);
            self.max_ns.fetch_max(elapsed_ns, Ordering::Relaxed);
            let bucket = if elapsed_ns < 32 {
                usize::try_from(elapsed_ns).unwrap_or(31)
            } else {
                let exponent = u64::BITS - 1 - elapsed_ns.leading_zeros();
                let base = 1_u64 << exponent;
                let step = base / 2;
                let sub_bucket = ((elapsed_ns - base) / step).min(1);
                32 + usize::try_from((exponent - 5) * 2 + u32::try_from(sub_bucket).unwrap_or(1))
                    .unwrap_or(SIGN_PROFILE_BUCKETS - 1)
            };
            if let Some(counter) = self.buckets.get(bucket) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }

        fn snapshot(&self) -> SignPhaseSnapshot {
            let mut buckets = [0; SIGN_PROFILE_BUCKETS];
            for (output, bucket) in buckets.iter_mut().zip(&self.buckets) {
                *output = bucket.load(Ordering::Relaxed);
            }
            SignPhaseSnapshot {
                count: self.count.load(Ordering::Relaxed),
                total_ns: self.total_ns.load(Ordering::Relaxed),
                max_ns: self.max_ns.load(Ordering::Relaxed),
                buckets,
            }
        }
    }

    static STATS: [PhaseStats; SIGN_PROFILE_PHASES] =
        [const { PhaseStats::new() }; SIGN_PROFILE_PHASES];
    static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    thread_local! {
        static SIGN_ACTIVE: Cell<bool> = const { Cell::new(false) };
    }

    /// RAII phase timer; records on drop only while a top-level Sign scope is active.
    pub struct PhaseGuard {
        phase: SignPhase,
        start: Option<Instant>,
    }

    impl Drop for PhaseGuard {
        fn drop(&mut self) {
            if let Some(start) = self.start {
                let elapsed_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
                if let Some(stats) = STATS.get(self.phase.index()) {
                    stats.record(elapsed_ns);
                }
            }
        }
    }

    /// Starts one nested phase timer when Sign profiling is active.
    pub fn phase(phase: SignPhase) -> PhaseGuard {
        let active = ENABLED.load(Ordering::Relaxed) && SIGN_ACTIVE.with(Cell::get);
        PhaseGuard {
            phase,
            start: active.then(Instant::now),
        }
    }

    /// Runs one top-level `C_Sign` body with nested phase collection enabled.
    pub fn sign_scope<T>(f: impl FnOnce() -> T) -> T {
        if !ENABLED.load(Ordering::Relaxed) {
            return f();
        }
        SIGN_ACTIVE.with(|active| {
            let previous = active.replace(true);
            let start = Instant::now();
            let output = f();
            if let Some(stats) = STATS.get(SignPhase::CSignBody.index()) {
                stats.record(u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX));
            }
            active.set(previous);
            output
        })
    }

    /// Clears all collected Sign profiling samples.
    pub fn reset() {
        for phase in &STATS {
            phase.reset();
        }
    }

    /// Enables or disables phase collection at runtime.
    pub fn set_enabled(enabled: bool) {
        ENABLED.store(enabled, Ordering::Relaxed);
    }

    /// Returns a point-in-time copy of all Sign profiling samples.
    #[must_use]
    pub fn snapshot() -> SignProfileSnapshot {
        let mut phases = [SignPhaseSnapshot::default(); SIGN_PROFILE_PHASES];
        for (output, phase) in phases.iter_mut().zip(&STATS) {
            *output = phase.snapshot();
        }
        SignProfileSnapshot { phases }
    }
}

#[cfg(feature = "benchmarking")]
pub use enabled::{PhaseGuard, phase, reset, set_enabled, sign_scope, snapshot};

#[cfg(not(feature = "benchmarking"))]
mod disabled {
    use super::{SignPhase, SignProfileSnapshot};

    /// No-op phase guard used when the benchmarking feature is disabled.
    pub struct PhaseGuard;

    impl Drop for PhaseGuard {
        fn drop(&mut self) {}
    }

    /// Starts a no-op phase timer.
    #[inline]
    #[must_use]
    pub const fn phase(_phase: SignPhase) -> PhaseGuard {
        PhaseGuard
    }

    /// Runs a closure without profiling.
    #[inline]
    pub fn sign_scope<T>(f: impl FnOnce() -> T) -> T {
        f()
    }

    /// No-op reset.
    pub const fn reset() {}

    /// No-op runtime switch.
    pub const fn set_enabled(_enabled: bool) {}

    /// Returns an empty snapshot.
    #[must_use]
    pub fn snapshot() -> SignProfileSnapshot {
        SignProfileSnapshot::default()
    }
}

#[cfg(not(feature = "benchmarking"))]
pub use disabled::{PhaseGuard, phase, reset, set_enabled, sign_scope, snapshot};

#[cfg(all(test, feature = "benchmarking"))]
mod tests {
    use std::thread;

    use super::*;

    fn phase_count(snapshot: &SignProfileSnapshot, phase: SignPhase) -> u64 {
        snapshot
            .phases
            .get(phase.index())
            .map_or(0, |phase| phase.count)
    }

    #[test]
    #[serial_test::serial]
    fn reset_and_snapshot_account_for_nested_phases() {
        reset();
        set_enabled(true);
        sign_scope(|| {
            let guard = phase(SignPhase::BackendLookup);
            std::hint::black_box(());
            drop(guard);
        });

        let first = snapshot();
        assert_eq!(phase_count(&first, SignPhase::CSignBody), 1);
        assert_eq!(phase_count(&first, SignPhase::BackendLookup), 1);

        reset();
        set_enabled(false);
        let second = snapshot();
        assert_eq!(phase_count(&second, SignPhase::CSignBody), 0);
        assert_eq!(phase_count(&second, SignPhase::BackendLookup), 0);
    }

    #[test]
    #[serial_test::serial]
    fn concurrent_updates_are_not_lost() {
        reset();
        set_enabled(true);
        let threads: Vec<_> = (0..4)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..100 {
                        sign_scope(|| {
                            let guard = phase(SignPhase::RequestBuild);
                            std::hint::black_box(());
                            drop(guard);
                        });
                    }
                })
            })
            .collect();
        for handle in threads {
            assert!(
                handle.join().is_ok(),
                "profiling test thread must not panic"
            );
        }

        let result = snapshot();
        set_enabled(false);
        assert_eq!(phase_count(&result, SignPhase::CSignBody), 400);
        assert_eq!(phase_count(&result, SignPhase::RequestBuild), 400);
    }
}
