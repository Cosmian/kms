use std::{os::raw::c_long, ptr};

use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_types::{CryptographicAlgorithm, KeyFormatType},
    },
};

use super::{create_pqc_key_pair, ml_kem_algorithm_name, pqc_keygen};
use crate::{crypto::KeyPair, error::CryptoError};

/// Create an ML-KEM key pair.
///
/// Supports `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` via OpenSSL 3.4+.
pub fn create_ml_kem_key_pair(
    algorithm: CryptographicAlgorithm,
    vendor_id: &str,
    private_key_uid: &str,
    public_key_uid: &str,
    common_attributes: Attributes,
    private_key_attributes: Option<Attributes>,
    public_key_attributes: Option<Attributes>,
) -> Result<KeyPair, CryptoError> {
    let _ = ml_kem_algorithm_name(algorithm)?; // validate
    let (private_key_der, public_key_der, num_bits) =
        pqc_keygen(ml_kem_algorithm_name(algorithm)?)?;

    create_pqc_key_pair(
        vendor_id,
        &private_key_der,
        &public_key_der,
        i32::try_from(num_bits)?,
        algorithm,
        KeyFormatType::PKCS8,
        private_key_uid,
        public_key_uid,
        common_attributes,
        private_key_attributes,
        public_key_attributes,
        CryptographicUsageMask::Unrestricted,
        CryptographicUsageMask::Unrestricted,
    )
}

/// ML-KEM encapsulation: produces a (`shared_secret`, `ciphertext`) pair.
///
/// The `public_key_der` should be SPKI (`SubjectPublicKeyInfo`) DER bytes.
#[expect(unsafe_code)]
pub fn ml_kem_encapsulate(public_key_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Guard: an empty slice has a dangling .as_ptr(); passing it to d2i_PUBKEY
    // is UB — return a clean error instead.
    if public_key_der.is_empty() {
        return Err(CryptoError::Default(
            "ML-KEM encapsulate: empty public key DER".to_owned(),
        ));
    }
    unsafe {
        // Load the public key from DER
        let mut der_ptr = public_key_der.as_ptr();
        let raw = openssl_sys::d2i_PUBKEY(
            ptr::null_mut(),
            ptr::from_mut(&mut der_ptr),
            c_long::try_from(public_key_der.len())
                .map_err(|e| CryptoError::Default(format!("DER length overflow: {e}")))?,
        );
        if raw.is_null() {
            return Err(CryptoError::Default(
                "ML-KEM encapsulate: failed to load public key from DER".to_owned(),
            ));
        }
        // SAFETY: PKeyGuard takes ownership and calls EVP_PKEY_free on drop,
        // so the key is freed even if `ml_kem_encapsulate_raw` panics.
        let pkey = super::PKeyGuard(raw);
        ml_kem_encapsulate_raw(pkey.as_ptr())
    }
}

/// ML-KEM encapsulation using a raw `EVP_PKEY` pointer.
#[expect(unsafe_code)]
unsafe fn ml_kem_encapsulate_raw(
    pkey: *mut openssl_sys::EVP_PKEY,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    unsafe {
        let ctx = openssl_sys::EVP_PKEY_CTX_new(pkey, ptr::null_mut());
        if ctx.is_null() {
            return Err(CryptoError::Default(
                "ML-KEM encapsulate: EVP_PKEY_CTX_new failed".to_owned(),
            ));
        }
        let _ctx_guard = CtxGuard(ctx);

        if openssl_sys::EVP_PKEY_encapsulate_init(ctx, ptr::null()) != 1 {
            return Err(CryptoError::Default(
                "ML-KEM encapsulate: EVP_PKEY_encapsulate_init failed".to_owned(),
            ));
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
            return Err(CryptoError::Default(
                "ML-KEM encapsulate: size query failed".to_owned(),
            ));
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
            return Err(CryptoError::Default("ML-KEM encapsulate failed".to_owned()));
        }

        if wrapped_len != expected_wrapped {
            return Err(CryptoError::Default(format!(
                "ML-KEM encapsulate: ciphertext size mismatch (expected {expected_wrapped}, got {wrapped_len})"
            )));
        }
        if secret_len != expected_secret {
            return Err(CryptoError::Default(format!(
                "ML-KEM encapsulate: shared secret size mismatch (expected {expected_secret}, got {secret_len})"
            )));
        }

        Ok((shared_secret, wrapped_key))
    }
}

/// ML-KEM decapsulation: recovers the shared secret from a ciphertext.
///
/// The `private_key_der` should be PKCS#8 DER bytes.
#[expect(unsafe_code)]
pub fn ml_kem_decapsulate(
    private_key_der: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Guard: empty slices yield dangling pointers; trap both before any FFI.
    if private_key_der.is_empty() {
        return Err(CryptoError::Default(
            "ML-KEM decapsulate: empty private key DER".to_owned(),
        ));
    }
    if ciphertext.is_empty() {
        return Err(CryptoError::Default(
            "ML-KEM decapsulate: empty ciphertext".to_owned(),
        ));
    }
    unsafe {
        // Load the private key from PKCS#8 DER
        let mut der_ptr = private_key_der.as_ptr();
        let raw = openssl_sys::d2i_AutoPrivateKey(
            ptr::null_mut(),
            ptr::from_mut(&mut der_ptr),
            c_long::try_from(private_key_der.len())
                .map_err(|e| CryptoError::Default(format!("DER length overflow: {e}")))?,
        );
        if raw.is_null() {
            return Err(CryptoError::Default(
                "ML-KEM decapsulate: failed to load private key from DER".to_owned(),
            ));
        }
        // SAFETY: PKeyGuard takes ownership and calls EVP_PKEY_free on drop,
        // so the key is freed even if `ml_kem_decapsulate_raw` panics.
        let pkey = super::PKeyGuard(raw);
        ml_kem_decapsulate_raw(pkey.as_ptr(), ciphertext)
    }
}

/// ML-KEM decapsulation using a raw `EVP_PKEY` pointer.
#[expect(unsafe_code)]
unsafe fn ml_kem_decapsulate_raw(
    pkey: *mut openssl_sys::EVP_PKEY,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    unsafe {
        let ctx = openssl_sys::EVP_PKEY_CTX_new(pkey, ptr::null_mut());
        if ctx.is_null() {
            return Err(CryptoError::Default(
                "ML-KEM decapsulate: EVP_PKEY_CTX_new failed".to_owned(),
            ));
        }
        let _ctx_guard = CtxGuard(ctx);

        if openssl_sys::EVP_PKEY_decapsulate_init(ctx, ptr::null()) != 1 {
            return Err(CryptoError::Default(
                "ML-KEM decapsulate: EVP_PKEY_decapsulate_init failed".to_owned(),
            ));
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
            return Err(CryptoError::Default(
                "ML-KEM decapsulate: size query failed".to_owned(),
            ));
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
            return Err(CryptoError::Default("ML-KEM decapsulate failed".to_owned()));
        }

        if secret_len != expected_secret {
            return Err(CryptoError::Default(format!(
                "ML-KEM decapsulate: shared secret size mismatch (expected {expected_secret}, got {secret_len})"
            )));
        }
        Ok(shared_secret)
    }
}

/// RAII guard to free an `EVP_PKEY_CTX`.
pub(crate) struct CtxGuard(pub(crate) *mut openssl_sys::EVP_PKEY_CTX);

impl Drop for CtxGuard {
    #[expect(unsafe_code)]
    fn drop(&mut self) {
        unsafe {
            openssl_sys::EVP_PKEY_CTX_free(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use cosmian_kmip::kmip_2_1::kmip_types::KeyFormatType;

    use super::*;

    #[test]
    fn ml_kem_512_roundtrip() {
        let (priv_der, pub_der, _bits) = super::super::pqc_keygen("ML-KEM-512").unwrap();

        // Encapsulate with public key
        let (shared_secret1, ciphertext) = ml_kem_encapsulate(&pub_der).unwrap();

        // Decapsulate with private key
        let shared_secret2 = ml_kem_decapsulate(&priv_der, &ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert!(!shared_secret1.is_empty());
    }

    #[test]
    fn ml_kem_768_roundtrip() {
        let (priv_der, pub_der, _bits) = super::super::pqc_keygen("ML-KEM-768").unwrap();

        let (ss1, ct) = ml_kem_encapsulate(&pub_der).unwrap();
        let ss2 = ml_kem_decapsulate(&priv_der, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn ml_kem_1024_roundtrip() {
        let (priv_der, pub_der, _bits) = super::super::pqc_keygen("ML-KEM-1024").unwrap();

        let (ss1, ct) = ml_kem_encapsulate(&pub_der).unwrap();
        let ss2 = ml_kem_decapsulate(&priv_der, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn ml_kem_create_key_pair() {
        let key_pair = create_ml_kem_key_pair(
            CryptographicAlgorithm::MLKEM_768,
            "cosmian",
            "sk-uid",
            "pk-uid",
            Attributes::default(),
            None,
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
        let (priv_der, _pub_der, _bits) = super::super::pqc_keygen("ML-KEM-512").unwrap();
        let result = ml_kem_decapsulate(&priv_der, &[]);
        assert!(
            result.is_err(),
            "empty ciphertext must return Err, not panic"
        );
    }

    #[test]
    fn ml_kem_decapsulate_truncated_ciphertext_returns_err() {
        // ML-KEM-512 ciphertext is 768 bytes; passing just 1 byte must fail.
        let (priv_der, _pub_der, _bits) = super::super::pqc_keygen("ML-KEM-512").unwrap();
        let result = ml_kem_decapsulate(&priv_der, &[0_u8; 1]);
        assert!(
            result.is_err(),
            "truncated ciphertext must return Err, not panic"
        );
    }

    #[test]
    fn ml_kem_decapsulate_wrong_size_ciphertext_returns_err() {
        // ML-KEM-768 ciphertext is 1088 bytes; pass a ML-KEM-512-sized one.
        let (priv_der, _pub_der, _bits) = super::super::pqc_keygen("ML-KEM-768").unwrap();
        let result = ml_kem_decapsulate(&priv_der, &[0_u8; 768]);
        assert!(
            result.is_err(),
            "wrong-size ciphertext must return Err, not panic"
        );
    }

    #[test]
    fn ml_kem_pkey_guard_freed_on_encapsulate_bad_key() {
        // Exercises the PKeyGuard drop path when `ml_kem_encapsulate_raw` returns Err
        // immediately after a successful `d2i_PUBKEY`.  We use a valid-looking SPKI DER
        // for a different key type (RSA-1024 stub — any non-ML-KEM key will do) so that
        // `d2i_PUBKEY` succeeds but `EVP_PKEY_encapsulate_init` fails.
        // We generate a real ML-DSA key and try to KEM-encapsulate it — reusing the
        // same well-formed SPKI but wrong algorithm.
        let (_, pub_der, _) = super::super::pqc_keygen("ML-DSA-44").unwrap();
        // This must fail (wrong key type for KEM) without panicking or leaking.
        let result = ml_kem_encapsulate(&pub_der);
        assert!(
            result.is_err(),
            "wrong-algorithm public key must return Err, not panic"
        );
    }
}
