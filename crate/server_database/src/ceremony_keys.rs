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

use base64::{Engine, engine::general_purpose::STANDARD};
use cosmian_kms_crypto::crypto::symmetric::symmetric_ciphers::{
    AES_256_GCM_IV_LENGTH, AES_256_GCM_KEY_LENGTH, AES_256_GCM_MAC_LENGTH, SymCipher,
    aes_gcm_encrypt_generated_iv, decrypt,
};
use openssl::hash::{Hasher, MessageDigest};
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
/// Every primitive runs in the OpenSSL provider in use, i.e. inside the FIPS module in a FIPS
/// build: SHAKE-256 (FIPS 202) for the derivation, AES-256-GCM with a provider-generated IV
/// (NIST SP 800-38D §8.2.2) for the sealing.
///
/// # Zeroization
///
/// Both keys are heap-allocated (`Zeroizing<Vec<u8>>`): they are zeroized on drop and moving a
/// `CeremonyKeys` copies only the vector header, never the 32 key bytes. No cipher context is
/// kept: each `seal`/`unseal` call builds and frees its own, so no round-key schedule lingers.
pub struct CeremonyKeys {
    /// AES-256 key of the sealed records.
    aes_key: Zeroizing<Vec<u8>>,
    /// Key material for SHAKE-256 obfuscation of Redis key names.
    obfuscation_key: Zeroizing<Vec<u8>>,
}

/// SHAKE-256 of the concatenation of `parts`, squeezed into `out`.
fn shake256(parts: &[&[u8]], out: &mut [u8]) -> DbResult<()> {
    let openssl_err =
        |e: openssl::error::ErrorStack| DbError::CryptographicError(format!("SHAKE-256: {e}"));
    let mut hasher = Hasher::new(MessageDigest::shake_256()).map_err(openssl_err)?;
    for part in parts {
        hasher.update(part).map_err(openssl_err)?;
    }
    hasher.finish_xof(out).map_err(openssl_err)
}

/// A 32-byte key: SHAKE-256 of the concatenation of `parts`.
fn shake256_key(parts: &[&[u8]]) -> DbResult<Zeroizing<Vec<u8>>> {
    let mut key = Zeroizing::new(vec![0_u8; AES_256_GCM_KEY_LENGTH]);
    shake256(parts, &mut key)?;
    Ok(key)
}

impl CeremonyKeys {
    /// Derive ceremony keys from a 32-byte secret.
    ///
    /// Two independent keys are derived using SHAKE-256:
    /// - `aes_key`: for AES-256-GCM encryption of ceremony payloads
    /// - `obfuscation_key`: for Redis key name obfuscation
    ///
    /// # Errors
    /// When the OpenSSL provider fails to compute the digest.
    pub fn derive(ceremony_secret: &[u8; CEREMONY_SECRET_LENGTH]) -> DbResult<Self> {
        Ok(Self {
            aes_key: shake256_key(&[ceremony_secret, b"ceremony_aes_key"])?,
            obfuscation_key: shake256_key(&[ceremony_secret, b"ceremony_obfuscation"])?,
        })
    }

    /// Encrypt a ceremony payload into a sealed record (base64-encoded).
    ///
    /// Format: base64(IV ‖ ciphertext ‖ GCM-tag)
    ///
    /// The `role` parameter is used as Additional Authenticated Data (AAD),
    /// binding the ciphertext to a specific role and preventing cross-role replay.
    pub fn seal(&self, payload: &CeremonyPayload, role: &str) -> DbResult<String> {
        let plaintext = serde_json::to_vec(payload).map_err(|e| {
            DbError::DatabaseError(format!("failed to serialize ceremony payload: {e}"))
        })?;
        let (iv, ciphertext, tag) = aes_gcm_encrypt_generated_iv(
            SymCipher::Aes256Gcm,
            &self.aes_key,
            role.as_bytes(),
            &plaintext,
        )
        .map_err(|e| {
            DbError::CryptographicError(format!("failed to encrypt ceremony record: {e}"))
        })?;
        let mut sealed = Vec::with_capacity(iv.len() + ciphertext.len() + tag.len());
        sealed.extend(iv);
        sealed.extend(ciphertext);
        sealed.extend(tag);
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
        let (iv, rest) = sealed
            .split_at_checked(AES_256_GCM_IV_LENGTH)
            .ok_or_else(generic_err)?;
        let (ciphertext, tag) = rest
            .split_at_checked(
                rest.len()
                    .checked_sub(AES_256_GCM_MAC_LENGTH)
                    .ok_or_else(generic_err)?,
            )
            .ok_or_else(generic_err)?;
        let plaintext = decrypt(
            SymCipher::Aes256Gcm,
            &self.aes_key,
            iv,
            role.as_bytes(),
            ciphertext,
            tag,
            None,
        )
        .map_err(|_e| generic_err())?;
        serde_json::from_slice(&plaintext).map_err(|_e| generic_err())
    }

    /// Compute an obfuscated Redis key name for a ceremony role.
    ///
    /// Uses SHAKE-256 with the obfuscation key and role name to produce a
    /// 16-character hex string that hides which role the key belongs to.
    ///
    /// Format: `c:<16 hex chars>`
    ///
    /// # Errors
    /// When the OpenSSL provider fails to compute the digest.
    pub fn obfuscate_key(&self, role: &str) -> DbResult<String> {
        let mut hash = [0_u8; 8]; // 8 bytes = 16 hex chars
        shake256(&[&self.obfuscation_key, role.as_bytes()], &mut hash)?;
        Ok(format!("c:{}", hex::encode(hash)))
    }
}

#[cfg(test)]
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
        let keys = CeremonyKeys::derive(&test_secret()).expect("derive failed");
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
        let keys = CeremonyKeys::derive(&test_secret()).expect("derive failed");
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
        let keys = CeremonyKeys::derive(&test_secret()).expect("derive failed");
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
        let keys = CeremonyKeys::derive(&test_secret()).expect("derive failed");
        let k1 = keys
            .obfuscate_key("crypto_officer")
            .expect("obfuscate failed");
        let k2 = keys
            .obfuscate_key("crypto_officer")
            .expect("obfuscate failed");
        assert_eq!(k1, k2);
        assert!(k1.starts_with("c:"));
        assert_eq!(k1.len(), 2 + 16); // "c:" + 16 hex chars
    }

    #[test]
    fn obfuscate_key_differs_per_role() {
        let keys = CeremonyKeys::derive(&test_secret()).expect("derive failed");
        let k_co = keys
            .obfuscate_key("crypto_officer")
            .expect("obfuscate failed");
        let k_op = keys.obfuscate_key("operator").expect("obfuscate failed");
        let k_other = keys.obfuscate_key("other_role").expect("obfuscate failed");
        assert_ne!(k_co, k_op);
        assert_ne!(k_co, k_other);
        assert_ne!(k_op, k_other);
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let keys1 = CeremonyKeys::derive(&test_secret()).expect("derive failed");
        let mut s2 = test_secret();
        s2[0] = 0x99;
        let keys2 = CeremonyKeys::derive(&s2).expect("derive failed");
        let k1 = keys1
            .obfuscate_key("crypto_officer")
            .expect("obfuscate failed");
        let k2 = keys2
            .obfuscate_key("crypto_officer")
            .expect("obfuscate failed");
        assert_ne!(k1, k2);
    }

    /// Records and Redis key names already stored were produced by the former `cosmian_crypto_core`
    /// implementation (SHAKE-256 derivation, AES-256-GCM, `nonce ‖ ciphertext ‖ tag`): the OpenSSL
    /// implementation must read and name them the same way.
    #[test]
    fn stored_records_and_key_names_stay_compatible() {
        use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
            Aes256Gcm, Dem, Instantiable, Nonce, SymmetricKey, kdf256,
        };

        let secret = test_secret();
        let keys = CeremonyKeys::derive(&secret).expect("derive failed");

        let mut aes_key = SymmetricKey::<32>::default();
        kdf256!(&mut *aes_key, &secret, b"ceremony_aes_key");
        let payload = CeremonyPayload {
            activated_by: "admin@example.com".to_owned(),
            participants: vec!["alice@ex.com".to_owned()],
            key_hash: "abcdef".to_owned(),
        };
        let nonce = Nonce::from([7_u8; 12]);
        let ciphertext = Aes256Gcm::new(&aes_key)
            .encrypt(
                &nonce,
                &serde_json::to_vec(&payload).expect("serialize failed"),
                Some(b"crypto_officer"),
            )
            .expect("legacy encrypt failed");
        let mut stored = vec![7_u8; 12];
        stored.extend(ciphertext);
        let recovered = keys
            .unseal(&STANDARD.encode(&stored), "crypto_officer")
            .expect("a record sealed by the former implementation must still unseal");
        assert_eq!(recovered.key_hash, payload.key_hash);

        let mut obfuscation_key = SymmetricKey::<32>::default();
        kdf256!(&mut *obfuscation_key, &secret, b"ceremony_obfuscation");
        let mut name = [0_u8; 8];
        kdf256!(&mut name, &*obfuscation_key, b"crypto_officer");
        assert_eq!(
            keys.obfuscate_key("crypto_officer")
                .expect("obfuscate failed"),
            format!("c:{}", hex::encode(name))
        );
    }
}
