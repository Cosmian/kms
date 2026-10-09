use std::sync::Mutex;

use openssl::rand::rand_bytes;
use openssl_sys::RAND_add;
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Thread-safe KMS random number generator, a thin wrapper around OpenSSL's `RAND_bytes`.
///
/// `KmsRng` is instantiated once during KMS startup and shared via `Arc<KmsRng>`. It is used for:
/// - Symmetric key and `SecretData` seed generation
/// - Split keys
/// - Certificate serial numbers
/// - KMIP RNG operations (`RNGRetrieve`, `RNGSeed`)
///
/// - PQC key generation seed injection for ML-KEM and ML-DSA
///
/// SLH-DSA and hybrid KEM do not draw seeds from `KmsRng`: OpenSSL generates their key
/// material from its own default DRBG.
///
/// # Thread Safety
///
/// `KmsRng` uses an internal `Mutex` to serialize calls to the underlying OpenSSL RAND APIs.
/// Each call to `fill_bytes` holds the mutex only for the duration of the OpenSSL call.
///
/// # Compliance
///
/// This type makes no entropy-source validation (NIST SP 800-90B) or FIPS 140-3 claim: entropy
/// comes from whatever OpenSSL's default DRBG is seeded with by the operating system.
pub struct KmsRng {
    state: Mutex<()>,
}

impl Default for KmsRng {
    fn default() -> Self {
        Self::new()
    }
}

impl KmsRng {
    /// Create a new `KmsRng` instance.
    ///
    /// This initializes the wrapper around OpenSSL's DRBG. No manual seeding
    /// is performed here; OpenSSL's automatic seeding mechanisms are used.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(()),
        }
    }

    /// Fill a buffer with cryptographically random bytes.
    ///
    /// This is the primary entry point for random number generation.
    /// Internally uses OpenSSL's `RAND_bytes`, which draws from the
    /// active FIPS provider DRBG or system entropy source.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if OpenSSL's `RAND_bytes` fails
    /// (e.g., insufficient entropy).
    pub fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        let guard = self
            .state
            .lock()
            .map_err(|e| CryptoError::Default(format!("Failed to acquire RNG lock: {e}")))?;
        rand_bytes(dest).map_err(CryptoError::from)?;
        drop(guard);
        Ok(())
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

    /// Reseed the DRBG with external entropy.
    ///
    /// This method incorporates external seed data into the OpenSSL DRBG,
    /// as required by KMIP `RNGSeed` operations and NIST SP 800-133r3.
    ///
    /// The implementation uses OpenSSL's `RAND_add` to mix the seed material
    /// into the active DRBG state. This is compatible with both FIPS and
    /// non-FIPS modes.
    ///
    /// # Arguments
    ///
    /// * `seed` - Seed material to incorporate (typically 32+ bytes for strong entropy)
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` on failure (rarely, in practice).
    #[expect(unsafe_code)]
    pub fn reseed(&self, seed: &[u8]) -> Result<(), CryptoError> {
        if seed.is_empty() {
            return Ok(());
        }
        let guard = self
            .state
            .lock()
            .map_err(|e| CryptoError::Default(format!("Failed to acquire RNG lock: {e}")))?;
        let seed_len_i32 = i32::try_from(seed.len())
            .map_err(|e| CryptoError::Default(format!("seed length exceeds i32: {e}")))?;
        #[expect(clippy::as_conversions, clippy::cast_precision_loss)]
        let entropy_estimate = seed.len() as f64;
        // SAFETY: RAND_add accepts a pointer to bytes, a valid length, and an entropy estimate.
        // seed is a valid byte slice; seed.as_ptr() is non-null and valid for seed.len() bytes.
        unsafe {
            RAND_add(
                seed.as_ptr().cast::<std::ffi::c_void>(),
                seed_len_i32,
                entropy_estimate,
            );
        }
        drop(guard);
        Ok(())
    }
}

#[expect(clippy::panic_in_result_fn)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kms_rng_new() -> Result<(), CryptoError> {
        let rng = KmsRng::new();
        let mut buf = [0_u8; 16];
        rng.fill_bytes(&mut buf)?;
        assert!(buf.iter().any(|&b| b != 0));
        Ok(())
    }

    #[test]
    fn test_fill_bytes() -> Result<(), CryptoError> {
        let rng = KmsRng::new();
        let mut buf = [0_u8; 32];
        rng.fill_bytes(&mut buf)?;
        assert!(buf.iter().any(|&b| b != 0));
        Ok(())
    }

    #[test]
    fn test_random_vec() -> Result<(), CryptoError> {
        let rng = KmsRng::new();
        let vec = rng.random_vec(32)?;
        assert_eq!(vec.len(), 32);
        assert!(vec.iter().any(|&b| b != 0));
        Ok(())
    }

    #[test]
    fn test_reseed() -> Result<(), CryptoError> {
        let rng = KmsRng::new();
        let seed = b"test_seed_32_bytes_exactly______";
        rng.reseed(seed)?;
        Ok(())
    }

    #[test]
    fn test_reseed_empty() -> Result<(), CryptoError> {
        let rng = KmsRng::new();
        rng.reseed(b"")?;
        Ok(())
    }

    #[test]
    fn test_thread_safety() -> Result<(), Box<dyn std::error::Error>> {
        let rng = std::sync::Arc::new(KmsRng::new());
        let mut handles = vec![];

        for _ in 0..4 {
            let rng_clone = rng.clone();
            let handle = std::thread::spawn(move || {
                let mut buf = [0_u8; 16];
                for _ in 0..10 {
                    rng_clone
                        .fill_bytes(&mut buf)
                        .map_err(|e| format!("{e:?}"))?;
                    assert!(buf.iter().any(|&b| b != 0));
                }
                Ok::<(), String>(())
            });
            handles.push(handle);
        }

        for handle in handles {
            let thread_res = handle
                .join()
                .map_err(|e| format!("thread panicked: {e:?}"))?;
            thread_res.map_err(|e| format!("worker thread error: {e}"))?;
        }
        Ok(())
    }
}
