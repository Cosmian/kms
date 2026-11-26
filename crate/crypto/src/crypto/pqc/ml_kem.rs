use std::ptr;

use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::kmip_types::{CryptographicAlgorithm, KeyFormatType},
};
use foreign_types::ForeignType;
use openssl::{
    pkey::{HasPrivate, HasPublic, PKey, PKeyRef},
    pkey_ctx::PkeyCtx,
};

use super::{PqcKeyMaterial, PqcKeyPolicy, create_pqc_key_pair, ml_kem_algorithm_name, pqc_keygen};
use crate::{
    crypto::{KeyPair, KeyPairIdentity},
    error::CryptoError,
};

/// Create an ML-KEM key pair.
///
/// Supports `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` via OpenSSL 3.4+.
///
/// When `rng` is supplied, a 64-byte seed is drawn from `KmsRng` and passed to OpenSSL's
/// key generation context (per FIPS 203 §7.1 and OpenSSL `ml_kem_kmgmt.c`), generating
/// the key pair deterministically from that seed. When `None`, OpenSSL draws entropy
/// directly from its own default DRBG.
pub fn create_ml_kem_key_pair(
    algorithm: CryptographicAlgorithm,
    identity: KeyPairIdentity<'_>,
    rng: Option<&crate::crypto::KmsRng>,
) -> Result<KeyPair, CryptoError> {
    let _ = ml_kem_algorithm_name(algorithm)?; // validate
    let (private_key_der, public_key_der, num_bits) =
        pqc_keygen(ml_kem_algorithm_name(algorithm)?, rng, None)?;
    create_pqc_key_pair(
        identity,
        PqcKeyMaterial {
            private_key_der: &private_key_der,
            public_key_der: &public_key_der,
            cryptographic_length: i32::try_from(num_bits)?,
            key_format_type: KeyFormatType::PKCS8,
        },
        PqcKeyPolicy {
            cryptographic_algorithm: algorithm,
            private_key_usage_mask: CryptographicUsageMask::Unrestricted,
            public_key_usage_mask: CryptographicUsageMask::Unrestricted,
        },
    )
}

/// ML-KEM encapsulation: produces a (`shared_secret`, `ciphertext`) pair.
///
/// The `public_key_der` should be SPKI (`SubjectPublicKeyInfo`) DER bytes.
pub fn ml_kem_encapsulate(public_key_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let pkey = PKey::public_key_from_der(public_key_der)?;
    kem_encapsulate(&pkey, "ML-KEM")
}

/// ML-KEM decapsulation: recovers the shared secret from a ciphertext.
///
/// The `private_key_der` should be PKCS#8 DER bytes.
pub fn ml_kem_decapsulate(
    private_key_der: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let pkey = PKey::private_key_from_der(private_key_der)?;
    kem_decapsulate(&pkey, ciphertext, "ML-KEM")
}

/// KEM encapsulation with an OpenSSL provider key (ML-KEM or hybrid). `label` prefixes errors.
///
/// Upstream tracking: `rust-openssl` has no safe `EVP_PKEY_encapsulate` (Issue #1251,
/// upstream PRs #2649, #2646, #2636, #2611). The context is owned by the safe `PkeyCtx`.
#[expect(
    unsafe_code,
    reason = "EVP_PKEY_encapsulate has no safe rust-openssl binding (#1251)"
)]
pub(crate) fn kem_encapsulate<T: HasPublic>(
    pkey: &PKeyRef<T>,
    label: &str,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let pctx = PkeyCtx::new(pkey).map_err(|e| {
        CryptoError::Default(format!("{label} encapsulate: EVP_PKEY_CTX_new failed: {e}"))
    })?;
    let ctx = pctx.as_ptr();
    // SAFETY: `ctx` is a valid EVP_PKEY_CTX owned by the `PkeyCtx` (`pctx`) above, which outlives
    // every call below; the output buffers are sized by the preceding size query.
    unsafe {
        if openssl_sys::EVP_PKEY_encapsulate_init(ctx, ptr::null()) != 1 {
            return Err(CryptoError::Default(format!(
                "{label} encapsulate: EVP_PKEY_encapsulate_init failed"
            )));
        }

        // Determine output sizes
        let mut wrapped_len: usize = 0;
        let mut secret_len: usize = 0;
        if openssl_sys::EVP_PKEY_encapsulate(
            ctx,
            ptr::null_mut(),
            ptr::from_mut(&mut wrapped_len),
            ptr::null_mut(),
            ptr::from_mut(&mut secret_len),
        ) != 1
        {
            return Err(CryptoError::Default(format!(
                "{label} encapsulate: size query failed"
            )));
        }

        let expected_wrapped = wrapped_len;
        let expected_secret = secret_len;
        let mut wrapped_key = vec![0_u8; wrapped_len];
        let mut shared_secret = vec![0_u8; secret_len];

        if openssl_sys::EVP_PKEY_encapsulate(
            ctx,
            wrapped_key.as_mut_ptr(),
            ptr::from_mut(&mut wrapped_len),
            shared_secret.as_mut_ptr(),
            ptr::from_mut(&mut secret_len),
        ) != 1
        {
            return Err(CryptoError::Default(format!("{label} encapsulate failed")));
        }

        if wrapped_len != expected_wrapped {
            return Err(CryptoError::Default(format!(
                "{label} encapsulate: ciphertext size mismatch (expected {expected_wrapped}, got {wrapped_len})"
            )));
        }
        if secret_len != expected_secret {
            return Err(CryptoError::Default(format!(
                "{label} encapsulate: shared secret size mismatch (expected {expected_secret}, got {secret_len})"
            )));
        }

        Ok((shared_secret, wrapped_key))
    }
}

/// KEM decapsulation with an OpenSSL provider key (ML-KEM or hybrid). `label` prefixes errors.
///
/// Upstream tracking: `rust-openssl` has no safe `EVP_PKEY_decapsulate` (Issue #1251,
/// upstream PRs #2649, #2646, #2636, #2611). The context is owned by the safe `PkeyCtx`.
#[expect(
    unsafe_code,
    reason = "EVP_PKEY_decapsulate has no safe rust-openssl binding (#1251)"
)]
pub(crate) fn kem_decapsulate<T: HasPrivate>(
    pkey: &PKeyRef<T>,
    ciphertext: &[u8],
    label: &str,
) -> Result<Vec<u8>, CryptoError> {
    // Guard: an empty slice has a dangling .as_ptr(); passing it to C is UB.
    if ciphertext.is_empty() {
        return Err(CryptoError::Default(format!(
            "{label} decapsulate: empty ciphertext"
        )));
    }
    let pctx = PkeyCtx::new(pkey).map_err(|e| {
        CryptoError::Default(format!("{label} decapsulate: EVP_PKEY_CTX_new failed: {e}"))
    })?;
    let ctx = pctx.as_ptr();
    // SAFETY: `ctx` is a valid EVP_PKEY_CTX owned by the `PkeyCtx` (`pctx`) above, which outlives
    // every call below; `ciphertext` is non-empty (checked above) and the output buffer is
    // sized by the preceding size query.
    unsafe {
        if openssl_sys::EVP_PKEY_decapsulate_init(ctx, ptr::null()) != 1 {
            return Err(CryptoError::Default(format!(
                "{label} decapsulate: EVP_PKEY_decapsulate_init failed"
            )));
        }

        // Determine output size for the shared secret
        let mut secret_len: usize = 0;
        if openssl_sys::EVP_PKEY_decapsulate(
            ctx,
            ptr::null_mut(),
            ptr::from_mut(&mut secret_len),
            ciphertext.as_ptr(),
            ciphertext.len(),
        ) != 1
        {
            return Err(CryptoError::Default(format!(
                "{label} decapsulate: size query failed"
            )));
        }

        let expected_secret = secret_len;
        let mut shared_secret = vec![0_u8; secret_len];

        if openssl_sys::EVP_PKEY_decapsulate(
            ctx,
            shared_secret.as_mut_ptr(),
            ptr::from_mut(&mut secret_len),
            ciphertext.as_ptr(),
            ciphertext.len(),
        ) != 1
        {
            return Err(CryptoError::Default(format!("{label} decapsulate failed")));
        }

        if secret_len != expected_secret {
            return Err(CryptoError::Default(format!(
                "{label} decapsulate: shared secret size mismatch (expected {expected_secret}, got {secret_len})"
            )));
        }
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests {

    use cosmian_kmip::kmip_2_1::{kmip_attributes::Attributes, kmip_types::KeyFormatType};

    use super::*;

    #[test]
    fn ml_kem_512_roundtrip() {
        let (priv_der, pub_der, _bits) =
            super::super::pqc_keygen("ML-KEM-512", None, None).unwrap();

        // Encapsulate with public key
        let (shared_secret1, ciphertext) = ml_kem_encapsulate(&pub_der).unwrap();

        // Decapsulate with private key
        let shared_secret2 = ml_kem_decapsulate(&priv_der, &ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert_ne!(shared_secret1.len(), 0);
    }

    #[test]
    fn ml_kem_768_roundtrip() {
        let (priv_der, pub_der, _bits) =
            super::super::pqc_keygen("ML-KEM-768", None, None).unwrap();

        let (ss1, ct) = ml_kem_encapsulate(&pub_der).unwrap();
        let ss2 = ml_kem_decapsulate(&priv_der, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }
    #[test]
    fn ml_kem_768_roundtrip_with_kms_rng_seed() {
        let rng = crate::crypto::KmsRng::new();
        let (priv_der, pub_der, _bits) =
            super::super::pqc_keygen("ML-KEM-768", Some(&rng), None).unwrap();

        let (ss1, ct) = ml_kem_encapsulate(&pub_der).unwrap();
        let ss2 = ml_kem_decapsulate(&priv_der, &ct).unwrap();
        assert_eq!(ss1, ss2, "encapsulate/decapsulate on seeded key must match");
        assert_ne!(ss1.len(), 0);
    }

    #[test]
    fn ml_kem_1024_roundtrip() {
        let (priv_der, pub_der, _bits) =
            super::super::pqc_keygen("ML-KEM-1024", None, None).unwrap();

        let (ss1, ct) = ml_kem_encapsulate(&pub_der).unwrap();
        let ss2 = ml_kem_decapsulate(&priv_der, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn ml_kem_create_key_pair() {
        let key_pair = create_ml_kem_key_pair(
            CryptographicAlgorithm::MLKEM_768,
            KeyPairIdentity {
                vendor_id: "cosmian",
                private_key_uid: "sk-uid",
                public_key_uid: "pk-uid",
                common_attributes: Attributes::default(),
                private_key_attributes: None,
                public_key_attributes: None,
            },
            None,
        )
        .unwrap();

        let (sk, pk) = (key_pair.0.0, key_pair.0.1);
        assert!(matches!(
            sk,
            cosmian_kmip::kmip_2_1::kmip_objects::Object::PrivateKey(_)
        ));
        assert!(matches!(
            pk,
            cosmian_kmip::kmip_2_1::kmip_objects::Object::PublicKey(_)
        ));

        let sk_block = sk.key_block().unwrap();
        assert_eq!(sk_block.key_format_type, KeyFormatType::PKCS8);
        assert_eq!(
            sk_block.cryptographic_algorithm,
            Some(CryptographicAlgorithm::MLKEM_768)
        );
    }

    // ── Limit / panic-safety tests ────────────────────────────────────────────
    // All of these MUST return Err and must NOT panic, abort, or leak memory.

    #[test]
    fn ml_kem_encapsulate_empty_input_returns_err() {
        let result = ml_kem_encapsulate(&[]);
        assert!(result.is_err(), "empty DER must return Err, not panic");
    }

    #[test]
    fn ml_kem_encapsulate_garbage_der_returns_err() {
        let result = ml_kem_encapsulate(&[0xFF_u8; 64]);
        assert!(result.is_err(), "garbage DER must return Err, not panic");
    }

    #[test]
    fn ml_kem_encapsulate_truncated_der_returns_err() {
        // A valid DER sequence header but no content — structurally malformed.
        let result = ml_kem_encapsulate(&[0x30, 0x10]);
        assert!(result.is_err(), "truncated DER must return Err, not panic");
    }

    #[test]
    fn ml_kem_decapsulate_empty_private_key_returns_err() {
        let result = ml_kem_decapsulate(&[], &[]);
        assert!(
            result.is_err(),
            "empty private key DER must return Err, not panic"
        );
    }

    #[test]
    fn ml_kem_decapsulate_garbage_private_key_returns_err() {
        let result = ml_kem_decapsulate(&[0xDE_u8; 64], &[0_u8; 768]);
        assert!(
            result.is_err(),
            "garbage private key DER must return Err, not panic"
        );
    }

    #[test]
    fn ml_kem_decapsulate_empty_ciphertext_returns_err() {
        let (priv_der, _pub_der, _bits) =
            super::super::pqc_keygen("ML-KEM-512", None, None).unwrap();
        let result = ml_kem_decapsulate(&priv_der, &[]);
        assert!(
            result.is_err(),
            "empty ciphertext must return Err, not panic"
        );
    }

    #[test]
    fn ml_kem_decapsulate_truncated_ciphertext_returns_err() {
        // ML-KEM-512 ciphertext is 768 bytes; passing just 1 byte must fail.
        let (priv_der, _pub_der, _bits) =
            super::super::pqc_keygen("ML-KEM-512", None, None).unwrap();
        let result = ml_kem_decapsulate(&priv_der, &[0_u8; 1]);
        assert!(
            result.is_err(),
            "truncated ciphertext must return Err, not panic"
        );
    }

    #[test]
    fn ml_kem_decapsulate_wrong_size_ciphertext_returns_err() {
        // ML-KEM-768 ciphertext is 1088 bytes; pass a ML-KEM-512-sized one.
        let (priv_der, _pub_der, _bits) =
            super::super::pqc_keygen("ML-KEM-768", None, None).unwrap();
        let result = ml_kem_decapsulate(&priv_der, &[0_u8; 768]);
        assert!(
            result.is_err(),
            "wrong-size ciphertext must return Err, not panic"
        );
    }

    #[test]
    fn ml_kem_encapsulate_wrong_algorithm_returns_err() {
        // Exercises the error path when `ml_kem_encapsulate` receives a valid
        // SPKI DER for a non-ML-KEM key type.
        // We generate a real ML-DSA key and try to KEM-encapsulate it — reusing the
        // same well-formed SPKI but wrong algorithm.
        let (_, pub_der, _) = super::super::pqc_keygen("ML-DSA-44", None, None).unwrap();
        // This must fail (wrong key type for KEM) without panicking or leaking.
        let result = ml_kem_encapsulate(&pub_der);
        assert!(
            result.is_err(),
            "wrong-algorithm public key must return Err, not panic"
        );
    }
}
#[cfg(test)]
mod characterization_tests {
    use super::{ml_kem_decapsulate, ml_kem_encapsulate};

    #[test]
    fn characterization_ml_kem_768_encaps_decaps() {
        let (priv_der, pub_der, _bits) =
            crate::crypto::pqc::pqc_keygen("ML-KEM-768", None, None).unwrap();

        let (ss, ct) = ml_kem_encapsulate(&pub_der).unwrap();
        let ss_recovered = ml_kem_decapsulate(&priv_der, &ct).unwrap();
        assert_eq!(ss, ss_recovered);
        assert_ne!(ss.len(), 0);
    }
}
