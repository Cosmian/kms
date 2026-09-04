//! Ceremony record encryption and key obfuscation.
//!
//! Provides AES-256-GCM sealing/unsealing of ceremony activation records and
//! SHAKE-256-based obfuscation of Redis key names. This ensures that:
//!
//! 1. **Confidentiality**: Participant names, `activated_by`, and `key_hash` are
//!    encrypted at rest — an attacker with DB read access sees only opaque blobs.
//! 2. **Integrity**: The GCM authentication tag prevents forging ceremony records
//!    via direct DB writes — tampered records fail unsealing.
//! 3. **Key obfuscation** (Redis): Role names are not stored in plaintext as Redis
//!    keys — an attacker cannot enumerate which roles have ceremonies.

use std::sync::Mutex;

use base64::{Engine, engine::general_purpose::STANDARD};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    Aes256Gcm, CsRng, Dem, Instantiable, Nonce, RandomFixedSizeCBytes, SymmetricKey, kdf256,
    reexport::rand_core::SeedableRng,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{DbError, DbResult};

/// Length of the ceremony secret in bytes (256-bit).
pub const CEREMONY_SECRET_LENGTH: usize = 32;

/// The plaintext payload sealed inside a ceremony activation record.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CeremonyPayload {
    pub activated_by: String,
    pub participants: Vec<String>,
    pub key_hash: String,
}

/// Cryptographic key material for ceremony record protection.
///
/// Derived from the `ceremony_secret` configuration value. Provides:
/// - AES-256-GCM encryption of ceremony payloads
/// - SHAKE-256-based key name obfuscation for Redis
///
/// # Zeroization
///
/// Both sensitive fields are automatically wiped on drop:
/// - `aes_key` wraps `SymmetricKey<32>` → `Secret<32>: ZeroizeOnDrop`
/// - `obfuscation_key` is wrapped in `Zeroizing<[u8; 32]>: ZeroizeOnDrop`
///
/// The `Aes256Gcm` cipher is **not** stored as a field because
/// `aes_gcm::AesGcm` does not implement `ZeroizeOnDrop` (the round-key schedule
/// would linger in heap memory after drop). Instead, the cipher is constructed
/// locally inside each `seal`/`unseal` call from `aes_key` and dropped
/// immediately after use.
pub struct CeremonyKeys {
    /// Raw AES-256 key bytes — auto-zeroized on drop via `Secret<32>: ZeroizeOnDrop`.
    aes_key: SymmetricKey<32>,
    /// Key material for SHAKE-256 obfuscation of Redis key names.
    obfuscation_key: Zeroizing<[u8; 32]>,
    /// Thread-safe RNG for nonce generation.
    rng: Mutex<CsRng>,
}

impl CeremonyKeys {
    /// Derive ceremony keys from a 32-byte secret.
    ///
    /// Two independent keys are derived using SHAKE-256 (via `kdf256!`):
    /// - `aes_key`: for AES-256-GCM encryption of ceremony payloads
    /// - `obfuscation_key`: for Redis key name obfuscation
    #[must_use]
    pub fn derive(ceremony_secret: &[u8; CEREMONY_SECRET_LENGTH]) -> Self {
        let mut aes_key = SymmetricKey::<32>::default();
        kdf256!(&mut *aes_key, ceremony_secret, b"ceremony_aes_key");

        let mut obfuscation_key = Zeroizing::new([0_u8; 32]);
        kdf256!(
            &mut *obfuscation_key,
            ceremony_secret,
            b"ceremony_obfuscation"
        );

        Self {
            aes_key,
            obfuscation_key,
            rng: Mutex::new(CsRng::from_entropy()),
        }
    }

    /// Encrypt a ceremony payload into a sealed record (base64-encoded).
    ///
    /// Format: base64(nonce ‖ ciphertext ‖ GCM-tag)
    ///
    /// The `role` parameter is used as Additional Authenticated Data (AAD),
    /// binding the ciphertext to a specific role and preventing cross-role replay.
    pub fn seal(&self, payload: &CeremonyPayload, role: &str) -> DbResult<String> {
        let nonce = {
            let mut rng = self.rng.lock().map_err(|e| {
                DbError::DatabaseError(format!("failed acquiring lock on ceremony RNG: {e:?}"))
            })?;
            Nonce::new(&mut *rng)
        };
        let plaintext = serde_json::to_vec(payload).map_err(|e| {
            DbError::DatabaseError(format!("failed to serialize ceremony payload: {e}"))
        })?;
        // Construct the cipher locally so the round-key schedule is dropped
        // immediately after use rather than persisting for the lifetime of CeremonyKeys.
        let dem = Aes256Gcm::new(&self.aes_key);
        let ct = dem
            .encrypt(&nonce, &plaintext, Some(role.as_bytes()))
            .map_err(|e| {
                DbError::CryptographicError(format!("failed to encrypt ceremony record: {e}"))
            })?;
        let mut sealed = Vec::with_capacity(Aes256Gcm::NONCE_LENGTH + ct.len());
        sealed.extend_from_slice(nonce.as_bytes());
        sealed.extend(ct);
        Ok(STANDARD.encode(&sealed))
    }

    /// Decrypt and authenticate a sealed ceremony record.
    ///
    /// Returns `Err` if the record has been tampered with (GCM tag verification failure)
    /// or if the `role` AAD does not match the one used during sealing.
    pub fn unseal(&self, sealed_b64: &str, role: &str) -> DbResult<CeremonyPayload> {
        // Generic error message to avoid leaking sealed-record structure details.
        let generic_err =
            || DbError::CryptographicError("ceremony record verification failed".to_owned());

        let sealed = STANDARD.decode(sealed_b64).map_err(|_e| generic_err())?;
        let (nonce_bytes, ciphertext) = sealed
            .split_at_checked(Aes256Gcm::NONCE_LENGTH)
            .ok_or_else(generic_err)?;
        if ciphertext.is_empty() {
            return Err(generic_err());
        }
        let nonce = Nonce::try_from(nonce_bytes).map_err(|_e| generic_err())?;
        // Construct the cipher locally — same reasoning as in `seal`.
        let dem = Aes256Gcm::new(&self.aes_key);
        let plaintext = dem
            .decrypt(&nonce, ciphertext, Some(role.as_bytes()))
            .map_err(|_e| generic_err())?;
        serde_json::from_slice(&plaintext).map_err(|_e| generic_err())
    }

    /// Compute an obfuscated Redis key name for a ceremony role.
    ///
    /// Uses SHAKE-256 with the obfuscation key and role name to produce a
    /// 16-character hex string that hides which role the key belongs to.
    ///
    /// Format: `c:<16 hex chars>`
    #[must_use]
    pub fn obfuscate_key(&self, role: &str) -> String {
        let mut hash = [0_u8; 8]; // 8 bytes = 16 hex chars
        kdf256!(&mut hash, &*self.obfuscation_key, role.as_bytes());
        format!("c:{}", hex::encode(hash))
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        let mut s = [0_u8; 32];
        s[0] = 0x42;
        s[31] = 0xFF;
        s
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let keys = CeremonyKeys::derive(&test_secret());
        let payload = CeremonyPayload {
            activated_by: "admin@example.com".to_owned(),
            participants: vec!["alice@ex.com".to_owned(), "bob@ex.com".to_owned()],
            key_hash: "abcdef0123456789".to_owned(),
        };
        let sealed = keys.seal(&payload, "crypto_officer").expect("seal failed");
        let recovered = keys
            .unseal(&sealed, "crypto_officer")
            .expect("unseal failed");
        assert_eq!(recovered.activated_by, payload.activated_by);
        assert_eq!(recovered.participants, payload.participants);
        assert_eq!(recovered.key_hash, payload.key_hash);
    }

    #[test]
    fn tampered_record_fails() {
        let keys = CeremonyKeys::derive(&test_secret());
        let payload = CeremonyPayload {
            activated_by: "admin@example.com".to_owned(),
            participants: vec!["alice@ex.com".to_owned()],
            key_hash: "abcdef".to_owned(),
        };
        let sealed = keys.seal(&payload, "crypto_officer").expect("seal failed");
        // Flip a byte in the middle of the sealed blob
        let mut raw = STANDARD.decode(&sealed).expect("decode failed");
        if let Some(byte) = raw.get_mut(20) {
            *byte ^= 0xFF;
        }
        let tampered = STANDARD.encode(&raw);
        assert!(
            keys.unseal(&tampered, "crypto_officer").is_err(),
            "should fail on tampered record"
        );
    }

    #[test]
    fn wrong_role_aad_fails() {
        let keys = CeremonyKeys::derive(&test_secret());
        let payload = CeremonyPayload {
            activated_by: "admin@example.com".to_owned(),
            participants: vec![],
            key_hash: "abc".to_owned(),
        };
        let sealed = keys.seal(&payload, "crypto_officer").expect("seal failed");
        // Try to unseal with a different role → AAD mismatch → GCM failure
        assert!(
            keys.unseal(&sealed, "operator").is_err(),
            "should fail with wrong role AAD"
        );
    }

    #[test]
    fn obfuscate_key_is_deterministic() {
        let keys = CeremonyKeys::derive(&test_secret());
        let k1 = keys.obfuscate_key("crypto_officer");
        let k2 = keys.obfuscate_key("crypto_officer");
        assert_eq!(k1, k2);
        assert!(k1.starts_with("c:"));
        assert_eq!(k1.len(), 2 + 16); // "c:" + 16 hex chars
    }

    #[test]
    fn obfuscate_key_differs_per_role() {
        let keys = CeremonyKeys::derive(&test_secret());
        let k_co = keys.obfuscate_key("crypto_officer");
        let k_op = keys.obfuscate_key("operator");
        let k_other = keys.obfuscate_key("other_role");
        assert_ne!(k_co, k_op);
        assert_ne!(k_co, k_other);
        assert_ne!(k_op, k_other);
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let keys1 = CeremonyKeys::derive(&test_secret());
        let mut s2 = test_secret();
        s2[0] = 0x99;
        let keys2 = CeremonyKeys::derive(&s2);
        let k1 = keys1.obfuscate_key("crypto_officer");
        let k2 = keys2.obfuscate_key("crypto_officer");
        assert_ne!(k1, k2);
    }
}
