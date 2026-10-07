use std::sync::Mutex;

use openssl::rand::rand_bytes;
use openssl_sys::RAND_add;
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Unified, thread-safe NIST-compliant KMS RNG implementation.
///
/// `KmsRng` wraps OpenSSL's DRBG (CTR-DRBG or Hash_DRBG depending on provider)
/// and provides a thread-safe interface for cryptographic random number generation.
///
/// This struct should be instantiated once during KMS startup and shared
/// across all cryptographic operations via `Arc<KmsRng>`. It is the single
/// source of randomness for:
/// - Symmetric key generation
/// - Nonce/IV generation
/// - Split keys
/// - Certificate serial numbers
/// - KMIP RNG operations (RNGRetrieve, RNGSeed)
/// - PQC key generation seeding
///
/// # Thread Safety
///
/// `KmsRng` uses an internal `Mutex` to ensure thread-safe access to the
/// underlying OpenSSL RAND APIs. Each call to `fill_bytes` holds the mutex
/// only for the duration of the OpenSSL call, minimizing contention.
///
/// # Conformance
///
/// - NIST SP 800-90B/90C: Approved entropy source with CTR-DRBG or Hash_DRBG
/// - NIST SP 800-133r3: Deterministic seeding via `reseed` for RNGSeed operations
/// - FIPS 140-3: Compliant with IG 9.3.A, IG D.J, IG D.K
pub struct KmsRng {
    _state: Mutex<()>,
}

impl KmsRng {
    /// Create a new `KmsRng` instance.
    ///
    /// This initializes the wrapper around OpenSSL's DRBG. No manual seeding
    /// is performed here; OpenSSL's automatic seeding mechanisms are used.
    pub fn new() -> Result<Self, CryptoError> {
        Ok(Self {
            _state: Mutex::new(()),
        })
    }

    /// Fill a buffer with cryptographically random bytes.
    ///
    /// This is the primary entry point for random number generation.
    /// Internally uses OpenSSL's `RAND_bytes`, which draws from the
    /// active FIPS provider DRBG or system entropy source.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if OpenSSL's RAND_bytes fails
    /// (e.g., insufficient entropy).
    pub fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        let _guard = self
            ._state
            .lock()
            .map_err(|_| CryptoError::Default("Failed to acquire RNG lock".to_string()))?;
        rand_bytes(dest).map_err(CryptoError::from)?;
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
        let mut buf = Zeroizing::new(vec![0u8; len]);
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
        let _guard = self
            ._state
            .lock()
            .map_err(|_| CryptoError::Default("Failed to acquire RNG lock".to_string()))?;
        // SAFETY: RAND_add accepts a pointer to bytes and length, and entropy estimate.
        // We pass seed.as_ptr() (valid reference), seed.len() (correct length as i32),
        // and seed.len() as the entropy estimate (1.0 bit per byte). OpenSSL manages its
        // own state and will not dereference beyond the provided length.
        unsafe {
            RAND_add(
                seed.as_ptr() as *const std::ffi::c_void,
                seed.len() as i32,
                seed.len() as f64,
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kms_rng_new() {
        let rng = KmsRng::new();
        assert!(rng.is_ok());
    }

    #[test]
    fn test_fill_bytes() {
        let rng = KmsRng::new().expect("KmsRng creation failed");
        let mut buf = [0u8; 32];
        let result = rng.fill_bytes(&mut buf);
        assert!(result.is_ok());
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_vec() {
        let rng = KmsRng::new().expect("KmsRng creation failed");
        let result = rng.random_vec(32);
        assert!(result.is_ok());
        let vec = result.unwrap();
        assert_eq!(vec.len(), 32);
        assert!(vec.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_reseed() {
        let rng = KmsRng::new().expect("KmsRng creation failed");
        let seed = b"test_seed_32_bytes_exactly______";
        let result = rng.reseed(seed);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reseed_empty() {
        let rng = KmsRng::new().expect("KmsRng creation failed");
        let result = rng.reseed(b"");
        assert!(result.is_ok());
    }

    #[test]
    fn test_thread_safety() {
        let rng = std::sync::Arc::new(KmsRng::new().expect("KmsRng creation failed"));
        let mut handles = vec![];

        for _ in 0..4 {
            let rng_clone = rng.clone();
            let handle = std::thread::spawn(move || {
                let mut buf = [0u8; 16];
                for _ in 0..10 {
                    rng_clone.fill_bytes(&mut buf).expect("fill_bytes failed");
                    assert!(buf.iter().any(|&b| b != 0));
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }
    }
}
