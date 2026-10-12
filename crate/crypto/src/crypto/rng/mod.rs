use std::ffi::{c_int, c_uint, c_void};

use openssl::error::ErrorStack;
use openssl_sys::RAND_add;
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Security strength, in bits, requested from OpenSSL's DRBG on every generate call.
///
/// NIST SP 800-133r2 §4: random bits used for keys "shall be obtained from the output of an
/// approved RBG" that "shall be instantiated at a security strength that supports the security
/// strength required to protect the target data". The largest key protected by this server is
/// AES-256 / P-521-class (≥ 256-bit strength), so 256 is requested. OpenSSL (SP 800-90A r1
/// §9.3.1 `Generate_function`, step "if `requested_security_strength` > the security strength of
/// the internal state, return an error") then fails closed if the DRBG that serves the request
/// is weaker than that, instead of silently returning lower-strength bits as `RAND_bytes` (which
/// passes a strength of 0) would.
const REQUIRED_STRENGTH_BITS: c_uint = 256;

#[expect(unsafe_code)]
unsafe extern "C" {
    /// `RAND_priv_bytes_ex(3)`: generate from the *private* DRBG of the default library context.
    fn RAND_priv_bytes_ex(ctx: *mut c_void, buf: *mut u8, num: usize, strength: c_uint) -> c_int;
    /// `RAND_bytes_ex(3)`: generate from the *public* DRBG of the default library context.
    fn RAND_bytes_ex(ctx: *mut c_void, buf: *mut u8, num: usize, strength: c_uint) -> c_int;
}

/// Thread-safe KMS random number generator, a thin wrapper around OpenSSL's DRBG hierarchy.
///
/// `KmsRng` is instantiated once during KMS startup and shared via `Arc<KmsRng>`. It is used for:
/// - Symmetric key and `SecretData` seed generation
/// - Split keys
/// - Certificate serial numbers
/// - KMIP RNG operations (`RNGRetrieve`, `RNGSeed`)
/// - PQC key generation seed injection for ML-KEM and ML-DSA
///
/// SLH-DSA and hybrid KEM do not draw seeds from `KmsRng`: OpenSSL generates their key
/// material from its own default DRBG. Several other call sites also call
/// `openssl::rand::rand_bytes` directly; they reach the same OpenSSL DRBG hierarchy but not
/// through this type.
///
/// # Design
///
/// - **No state of its own.** All random bits come from OpenSSL's DRBG hierarchy (AES-256
///   CTR-DRBG per SP 800-90A r1: a primary DRBG seeded by the operating system, and per-thread
///   public and private DRBGs that are reseeded from it). `KmsRng` holds no seed, key or counter,
///   so it cannot weaken that hierarchy and has nothing to protect or zeroize.
/// - **No lock.** OpenSSL's RAND API is thread-safe (each thread uses its own public/private
///   DRBG), so serialising callers behind a `Mutex` would add contention and a poisoning failure
///   mode without adding safety.
/// - **Private vs public DRBG.** [`fill_bytes`](Self::fill_bytes) and
///   [`random_vec`](Self::random_vec) use OpenSSL's *private* DRBG (`RAND_priv_bytes_ex`), which
///   OpenSSL documents for long-term key material. [`fill_public_bytes`](Self::fill_public_bytes)
///   uses the *public* DRBG (`RAND_bytes_ex`) for values that are handed to clients, such as
///   KMIP `RNGRetrieve`, so that output visible to a client never comes from the generator that
///   produces keys.
/// - **Requested strength.** Every call requests [`REQUIRED_STRENGTH_BITS`] bits of security
///   strength and returns an error if the serving DRBG cannot provide it
///   (NIST SP 800-133r2 §4, SP 800-90A r1 §9.3.1).
///
/// # Thread Safety
///
/// `KmsRng` is `Send + Sync` and may be shared freely.
///
/// # Compliance
///
/// This type makes no entropy-source validation (NIST SP 800-90B) or FIPS 140-3 claim: entropy
/// comes from whatever OpenSSL's default DRBG is seeded with by the operating system, and which
/// provider (FIPS or default) serves the DRBG depends on the provider configuration in effect
/// when OpenSSL first generates random bytes.
///
/// # Why not `cosmian_crypto_core::CsRng`
///
/// `CsRng` (`rand_chacha::ChaCha12Rng`, seeded via `getrandom`) is used elsewhere in this
/// codebase for non-compliance-relevant randomness, but it bypasses OpenSSL entirely and is not
/// an NIST SP 800-90A-approved DRBG construction. Do not substitute it here — see
/// `documentation/adr/2026-10-10-keep-kmsrng-openssl-backed-over-csrng.md`.
#[derive(Debug, Default)]
pub struct KmsRng;

// `Send + Sync` are auto traits: `KmsRng` has no fields, so both hold without a derive. This
// assertion makes the documented guarantee fail to compile if a non-thread-safe field is added.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<KmsRng>();
};

impl KmsRng {
    /// Create a new `KmsRng` instance.
    ///
    /// This initializes nothing: OpenSSL's DRBG hierarchy is instantiated lazily by OpenSSL
    /// on first use, using its own automatic seeding.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Fill a buffer with cryptographically random bytes for **secret** values (keys, seeds,
    /// split-key material, serial numbers).
    ///
    /// Uses OpenSSL's private DRBG and requests [`REQUIRED_STRENGTH_BITS`] bits of strength.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if OpenSSL cannot generate the bytes at the requested strength
    /// (DRBG not instantiated, entropy source failure, or DRBG strength below 256 bits).
    /// The buffer content is unspecified on error and MUST NOT be used.
    #[expect(unsafe_code)]
    pub fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        // SAFETY: `dest` is a valid, exclusively borrowed slice, so `dest.as_mut_ptr()` is valid
        // for writes of `dest.len()` bytes (a dangling non-null pointer with length 0 is allowed
        // by OpenSSL, which does not dereference it). A NULL library context selects the default
        // context.
        let ret = unsafe {
            RAND_priv_bytes_ex(
                std::ptr::null_mut(),
                dest.as_mut_ptr(),
                dest.len(),
                REQUIRED_STRENGTH_BITS,
            )
        };
        check_rand_result(ret)
    }

    /// Fill a buffer with random bytes that are **handed to clients** (KMIP `RNGRetrieve`).
    ///
    /// Uses OpenSSL's public DRBG, separate from the private DRBG that generates keys, and
    /// requests [`REQUIRED_STRENGTH_BITS`] bits of strength.
    ///
    /// # Errors
    ///
    /// Same as [`fill_bytes`](Self::fill_bytes).
    #[expect(unsafe_code)]
    pub fn fill_public_bytes(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        // SAFETY: see `fill_bytes`.
        let ret = unsafe {
            RAND_bytes_ex(
                std::ptr::null_mut(),
                dest.as_mut_ptr(),
                dest.len(),
                REQUIRED_STRENGTH_BITS,
            )
        };
        check_rand_result(ret)
    }

    /// Generate a vector of random bytes with automatic zeroization.
    ///
    /// The returned `Zeroizing<Vec<u8>>` automatically zeros its contents
    /// when dropped, suitable for sensitive cryptographic material.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if random byte generation fails.
    pub fn random_vec(&self, len: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut buf = Zeroizing::new(vec![0_u8; len]);
        self.fill_bytes(&mut buf)?;
        Ok(buf)
    }

    /// Mix caller-supplied data into the OpenSSL primary DRBG as **additional input**
    /// (KMIP `RNGSeed`).
    ///
    /// OpenSSL (≥ 3.0, built with an entropy source) turns `RAND_add` into
    /// `EVP_RAND_reseed(primary, ..., additional_input = seed)`: the primary DRBG is
    /// **reseeded immediately from the operating-system entropy source** and `seed` is only
    /// additional input. NIST SP 800-90A r1 §8.7.2: a DRBG does not rely on additional input for
    /// entropy and "knowledge of the additional input by an adversary does not degrade the
    /// security strength of a DRBG", so a hostile or low-entropy `RNGSeed` cannot weaken the
    /// generator. The seed is credited with zero bits of entropy.
    ///
    /// Side effect: every call forces a reseed of the process-wide primary DRBG, so callers
    /// must authorise and rate-limit it; this method does not.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if the seed length exceeds `i32::MAX`.
    #[expect(unsafe_code)]
    pub fn reseed(&self, seed: &[u8]) -> Result<(), CryptoError> {
        if seed.is_empty() {
            return Ok(());
        }
        let seed_len_i32 = i32::try_from(seed.len())
            .map_err(|e| CryptoError::Default(format!("seed length exceeds i32: {e}")))?;
        // Client-supplied seed material is never credited as entropy (0.0 bits).
        let entropy_estimate = 0.0_f64;
        // SAFETY: RAND_add accepts a pointer to bytes, a valid length, and an entropy estimate.
        // seed is a valid byte slice; seed.as_ptr() is non-null and valid for seed.len() bytes.
        unsafe {
            RAND_add(
                seed.as_ptr().cast::<std::ffi::c_void>(),
                seed_len_i32,
                entropy_estimate,
            );
        }
        Ok(())
    }
}

/// Convert the return value of `RAND_*_bytes_ex` (1 on success, 0 or -1 on failure).
fn check_rand_result(ret: c_int) -> Result<(), CryptoError> {
    if ret == 1 {
        Ok(())
    } else {
        Err(CryptoError::Default(format!(
            "OpenSSL random generation failed at {REQUIRED_STRENGTH_BITS}-bit strength: {}",
            ErrorStack::get()
        )))
    }
}

#[expect(clippy::panic_in_result_fn)]
#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

    use super::*;

    #[test]
    fn private_and_public_outputs_are_distinct_and_empty_buffer_is_ok() -> Result<(), CryptoError> {
        let rng = KmsRng::new();
        // Collision probability of 256-bit values is negligible (2^-256).
        let a = rng.random_vec(32)?;
        let b = rng.random_vec(32)?;
        let mut p = [0_u8; 32];
        rng.fill_public_bytes(&mut p)?;
        assert_ne!(*a, *b);
        assert_ne!(*a, p.to_vec());
        rng.fill_bytes(&mut [])?;
        rng.fill_public_bytes(&mut [])?;
        assert!(rng.random_vec(0)?.is_empty());
        Ok(())
    }

    #[test]
    #[expect(unsafe_code)]
    fn requested_strength_above_the_drbg_strength_fails_closed() -> Result<(), CryptoError> {
        // AES-256 CTR-DRBG supports at most 256 bits; a 512-bit request must be refused rather
        // than served at a lower strength (SP 800-90A r1 §9.3.1).
        let mut buf = [0_u8; 32];
        // SAFETY: `buf` is a valid writable buffer of `buf.len()` bytes; NULL selects the
        // default library context.
        let ret =
            unsafe { RAND_priv_bytes_ex(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len(), 512) };
        assert_ne!(ret, 1);
        // The error queue entry left by the failed call must not poison later calls.
        drop(ErrorStack::get());
        KmsRng::new().random_vec(32)?;
        Ok(())
    }

    #[test]
    fn reseed_with_additional_input_does_not_break_or_repeat_output() -> Result<(), CryptoError> {
        let rng = KmsRng::new();
        let before = rng.random_vec(32)?;
        // The same additional input twice must not make the output repeat.
        rng.reseed(&[0x42; 32])?;
        let after_1 = rng.random_vec(32)?;
        rng.reseed(&[0x42; 32])?;
        let after_2 = rng.random_vec(32)?;
        rng.reseed(b"")?;
        assert_ne!(*before, *after_1);
        assert_ne!(*after_1, *after_2);
        Ok(())
    }

    #[test]
    fn concurrent_callers_never_receive_the_same_output() -> Result<(), Box<dyn std::error::Error>>
    {
        let rng = Arc::new(KmsRng::new());
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let rng = Arc::clone(&rng);
                std::thread::spawn(move || {
                    (0..50)
                        .map(|_| rng.random_vec(32).map(|v| v.to_vec()))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| format!("{e}"))
                })
            })
            .collect();
        let mut seen = HashSet::new();
        for handle in handles {
            let outputs = handle
                .join()
                .map_err(|e| format!("thread panicked: {e:?}"))??;
            for out in outputs {
                assert!(seen.insert(out), "duplicate 256-bit random output");
            }
        }
        assert_eq!(seen.len(), 8 * 50);
        Ok(())
    }
}
