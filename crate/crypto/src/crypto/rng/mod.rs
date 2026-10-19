use std::{
    ffi::{c_int, c_uint, c_void},
    sync::atomic::{Ordering, compiler_fence},
};

use cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{self, CryptoRng, RngCore, SeedableRng},
};
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

/// `RAND_priv_bytes_ex` / `RAND_bytes_ex` signature.
type RandBytesEx = unsafe extern "C" fn(*mut c_void, *mut u8, usize, c_uint) -> c_int;

#[expect(unsafe_code)]
unsafe extern "C" {
    /// `RAND_priv_bytes_ex(3)`: generate from the *private* DRBG of the default library context.
    fn RAND_priv_bytes_ex(ctx: *mut c_void, buf: *mut u8, num: usize, strength: c_uint) -> c_int;
    /// `RAND_bytes_ex(3)`: generate from the *public* DRBG of the default library context.
    fn RAND_bytes_ex(ctx: *mut c_void, buf: *mut u8, num: usize, strength: c_uint) -> c_int;
}

/// Thread-safe KMS random number generator, a thin wrapper around OpenSSL's DRBG hierarchy.
///
/// `KmsRng` is the single source of randomness for key material, nonces/IVs and secret tokens.
/// Because it is zero-sized, the server shares one `Arc<KmsRng>` (`KMS::rng`) while other code
/// (CLI, database layer, PKCS#11 module) may construct `KmsRng::new()` locally at no cost. It is
/// used for:
/// - Symmetric key and `SecretData` seed generation, nonces and IVs
/// - Key wrapping (KEK, nonces) and split keys
/// - Certificate serial numbers
/// - KMIP RNG operations (`RNGRetrieve`, `RNGSeed`)
/// - PQC key generation seed injection for ML-KEM and ML-DSA
/// - Seeding the pseudo-random generators that third-party APIs require (`OpenPGP`, ECIES
///   `SalsaSealBox`)
/// - Session/OIDC tokens and AES-GCM/JOSE content keys and IVs
///
/// SLH-DSA, hybrid KEM, RSA/EC/EdDSA key generation and Covercrypt do not draw from `KmsRng`:
/// OpenSSL (or the Covercrypt library, which exposes no way to inject an RNG) generates their
/// key material internally.
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
///   [`random_vec`](Self::random_vec) use OpenSSL's *private* DRBG (`RAND_priv_bytes_ex`) for
///   values that stay secret (keys, seeds, KEKs, split-key shares, tokens).
///   [`fill_public_bytes`](Self::fill_public_bytes) uses the *public* DRBG (`RAND_bytes_ex`) for
///   values that leave the server in clear (nonces, IVs, certificate serials, KMIP `RNGRetrieve`,
///   PKCS#11 `C_GenerateRandom`), so private-DRBG output is never observable. OpenSSL keeps the
///   two instances apart "so that a compromise of the public PRNG instance will not affect the
///   secrecy of these private values" (`RAND_bytes(3)`): defence in depth, since CTR-DRBG output
///   does not reveal its state.
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
/// `CsRng` (`rand_chacha::ChaCha12Rng`) bypasses OpenSSL when seeded via `getrandom` and is not an
/// NIST SP 800-90A-approved DRBG construction. It is only ever seeded from `KmsRng`
/// ([`KmsRng::seeded_csrng`]). Do not substitute it here — see
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
    /// KEKs, split-key material, tokens).
    ///
    /// Uses OpenSSL's private DRBG and requests [`REQUIRED_STRENGTH_BITS`] bits of strength.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if OpenSSL cannot generate the bytes at the requested strength
    /// (DRBG not instantiated, entropy source failure, or DRBG strength below 256 bits).
    /// The buffer content is unspecified on error and MUST NOT be used.
    pub fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        generate(RAND_priv_bytes_ex, dest)
    }

    /// Fill a buffer with random bytes for values that **leave the server in clear** (nonces,
    /// IVs, certificate serials, KMIP `RNGRetrieve`, PKCS#11 `C_GenerateRandom`).
    ///
    /// Uses OpenSSL's public DRBG, separate from the private DRBG that generates secrets, and
    /// requests [`REQUIRED_STRENGTH_BITS`] bits of strength.
    ///
    /// # Errors
    ///
    /// Same as [`fill_bytes`](Self::fill_bytes).
    pub fn fill_public_bytes(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        generate(RAND_bytes_ex, dest)
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

    /// A `ChaCha12` generator seeded with 256 bits from the private DRBG.
    ///
    /// For third-party APIs that require an infallible `rand_core` 0.6 `CryptoRngCore` and offer no
    /// way to inject entropy (ECIES `SalsaSealBox`, `OpenPGP`), and for test fixtures. Everything the
    /// returned generator produces is bounded by this single 256-bit draw from `KmsRng`.
    ///
    /// # Errors
    ///
    /// Same as [`fill_bytes`](Self::fill_bytes).
    pub fn seeded_csrng(&self) -> Result<SeededCsRng, CryptoError> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        self.fill_bytes(&mut seed[..])?;
        // `from_seed` takes the seed by value: that stack copy cannot be cleared from safe Rust.
        Ok(SeededCsRng(CsRng::from_seed(*seed)))
    }

    /// Mix caller-supplied data into the OpenSSL primary DRBG as **additional input**
    /// (KMIP `RNGSeed`).
    ///
    /// OpenSSL (≥ 3.0, built with an entropy source) turns `RAND_add` into
    /// `EVP_RAND_reseed(primary, ..., additional_input = seed)` (`crypto/rand/rand_meth.c`): the
    /// primary DRBG is **reseeded immediately from the operating-system entropy source** and `seed`
    /// is only additional input. NIST SP 800-90A r1 §8.7.2: a DRBG does not rely on additional input
    /// for entropy and "knowledge of the additional input by an adversary does not degrade the
    /// security strength of a DRBG", so a hostile or low-entropy `RNGSeed` cannot weaken the
    /// generator. The seed is credited with zero bits of entropy.
    ///
    /// `RAND_add` returns `void`: a failed reseed is not reported here. A DRBG whose entropy source
    /// fails refuses later generate calls, which [`fill_bytes`](Self::fill_bytes) reports.
    ///
    /// Cost (FIPS build, Apple M-series): about 0.6 µs for the reseed, plus about 3 µs on the next
    /// generate call, whose DRBG then reseeds from the primary. That is far below the cost of the
    /// KMIP request that triggers it, so `RNGSeed` needs no rate limit of its own.
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
        // SAFETY: `seed` is a valid byte slice, non-null and readable for `seed.len()` bytes.
        // Client-supplied seed material is never credited as entropy (0.0 bits).
        unsafe { RAND_add(seed.as_ptr().cast::<c_void>(), seed_len_i32, 0.0) };
        Ok(())
    }
}

/// [`KmsRng::seeded_csrng`] output: a `CsRng` overwritten when dropped.
///
/// Its `ChaCha12` key is the seed, so whoever reads the state can recompute every byte it produced
/// (ECIES ephemeral keys, `OpenPGP` keys). `CsRng` does not zeroize itself.
pub struct SeededCsRng(CsRng);

impl Drop for SeededCsRng {
    #[expect(
        unsafe_code,
        clippy::volatile_composites,
        reason = "the store only has to survive dead-store elimination; tearing is irrelevant"
    )]
    fn drop(&mut self) {
        // SAFETY: `self.0` is valid, aligned and initialised. `CsRng` has no `Drop` and owns no heap
        // memory, so overwriting it without dropping the old value releases nothing. The write is
        // volatile so that it is not removed as a dead store.
        unsafe { std::ptr::write_volatile(&raw mut self.0, CsRng::from_seed([0; 32])) };
        compiler_fence(Ordering::SeqCst);
    }
}

impl RngCore for SeededCsRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for SeededCsRng {}

/// Generate `dest.len()` bytes at [`REQUIRED_STRENGTH_BITS`] with `RAND_priv_bytes_ex` or
/// `RAND_bytes_ex`.
#[expect(unsafe_code)]
fn generate(rand_bytes_ex: RandBytesEx, dest: &mut [u8]) -> Result<(), CryptoError> {
    // SAFETY: `dest` is a valid, exclusively borrowed slice, so `dest.as_mut_ptr()` is valid for
    // writes of `dest.len()` bytes (a dangling non-null pointer with length 0 is allowed by
    // OpenSSL, which does not dereference it). A NULL library context selects the default context.
    let ret = unsafe {
        rand_bytes_ex(
            std::ptr::null_mut(),
            dest.as_mut_ptr(),
            dest.len(),
            REQUIRED_STRENGTH_BITS,
        )
    };
    // `RAND_*_bytes_ex` return 1 on success, 0 or -1 on failure.
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
    use std::{collections::HashSet, mem::ManuallyDrop, sync::Arc};

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
    #[expect(unsafe_code)]
    fn seeded_csrng_state_is_overwritten_on_drop() -> Result<(), CryptoError> {
        let mut rng = ManuallyDrop::new(KmsRng::new().seeded_csrng()?);
        rng.next_u64();
        assert_ne!(rng.0.get_seed(), [0; 32]);
        // SAFETY: `rng` is not dropped again; the drop only overwrites `rng.0` with another valid
        // `CsRng`, so reading it afterwards reads initialised memory.
        unsafe { ManuallyDrop::drop(&mut rng) };
        assert_eq!(rng.0.get_seed(), [0; 32]);
        assert_eq!(rng.0.get_word_pos(), 0);
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
