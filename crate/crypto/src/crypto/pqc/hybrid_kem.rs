use std::ptr;

use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_types::{CryptographicAlgorithm, KeyFormatType},
    },
};

use super::{
    create_pqc_key_pair, hybrid_kem_algorithm_name, load_raw_private_key, load_raw_public_key,
    pqc_keygen_raw,
};
use crate::{crypto::KeyPair, error::CryptoError};

/// Create a hybrid KEM key pair.
///
/// Supports `X25519MLKEM768` and `X448MLKEM1024` via OpenSSL 3.6+.
///
/// Note: `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` are NOT supported
/// because OpenSSL 3.6.0 cannot serialize/deserialize their private keys.
///
/// Hybrid KEM keys don't support DER serialization in OpenSSL 3.6,
/// so raw key bytes are stored with `KeyFormatType::Raw`.
pub fn create_hybrid_kem_key_pair(
    algorithm: CryptographicAlgorithm,
    vendor_id: &str,
    private_key_uid: &str,
    public_key_uid: &str,
    common_attributes: Attributes,
    private_key_attributes: Option<Attributes>,
    public_key_attributes: Option<Attributes>,
) -> Result<KeyPair, CryptoError> {
    let algorithm_name = hybrid_kem_algorithm_name(algorithm)?;
    let (private_key_raw, public_key_raw, num_bits) = pqc_keygen_raw(algorithm_name)?;

    create_pqc_key_pair(
        vendor_id,
        &private_key_raw,
        &public_key_raw,
        i32::try_from(num_bits)?,
        algorithm,
        KeyFormatType::Raw,
        private_key_uid,
        public_key_uid,
        common_attributes,
        private_key_attributes,
        public_key_attributes,
        CryptographicUsageMask::Unrestricted,
        CryptographicUsageMask::Unrestricted,
    )
}

/// Hybrid KEM encapsulation: produces a (`shared_secret`, `ciphertext`) pair.
///
/// `algorithm` identifies the hybrid KEM variant.
/// `public_key_raw` should be raw public key bytes (from `EVP_PKEY_get_raw_public_key`).
#[expect(unsafe_code)]
pub fn hybrid_kem_encapsulate(
    algorithm: CryptographicAlgorithm,
    public_key_raw: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let algorithm_name = hybrid_kem_algorithm_name(algorithm)?;
    let pkey = load_raw_public_key(algorithm_name, public_key_raw)?;
    // SAFETY: `pkey` is a valid EVP_PKEY for the duration of this call; freed on drop.
    unsafe { encapsulate_raw(pkey.as_ptr()) }
}

/// Hybrid KEM decapsulation: recovers the shared secret from a ciphertext.
///
/// `algorithm` identifies the hybrid KEM variant.
/// `private_key_raw` should be raw private key bytes (from `EVP_PKEY_get_raw_private_key`).
#[expect(unsafe_code)]
pub fn hybrid_kem_decapsulate(
    algorithm: CryptographicAlgorithm,
    private_key_raw: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Guard: empty ciphertext yields a dangling pointer that would be passed to
    // EVP_PKEY_decapsulate inside decapsulate_raw — trap it before any FFI.
    if ciphertext.is_empty() {
        return Err(CryptoError::Default(
            "Hybrid KEM decapsulate: empty ciphertext".to_owned(),
        ));
    }
    let algorithm_name = hybrid_kem_algorithm_name(algorithm)?;
    let pkey = load_raw_private_key(algorithm_name, private_key_raw)?;
    // SAFETY: `pkey` is a valid EVP_PKEY for the duration of this call; freed on drop.
    unsafe { decapsulate_raw(pkey.as_ptr(), ciphertext) }
}

/// Inner encapsulation using a raw `EVP_PKEY` pointer.
#[expect(unsafe_code)]
unsafe fn encapsulate_raw(
    pkey: *mut openssl_sys::EVP_PKEY,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    use crate::crypto::pqc::ml_kem::CtxGuard;
    unsafe {
        let ctx = openssl_sys::EVP_PKEY_CTX_new(pkey, ptr::null_mut());
        if ctx.is_null() {
            return Err(CryptoError::Default(
                "Hybrid KEM encapsulate: EVP_PKEY_CTX_new failed".to_owned(),
            ));
        }
        let _ctx_guard = CtxGuard(ctx);

        if openssl_sys::EVP_PKEY_encapsulate_init(ctx, ptr::null()) != 1 {
            return Err(CryptoError::Default(
                "Hybrid KEM encapsulate: EVP_PKEY_encapsulate_init failed".to_owned(),
            ));
        }

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
                "Hybrid KEM encapsulate: size query failed".to_owned(),
            ));
        }

        let mut wrapped_key = vec![0_u8; wrapped_len];
        let mut shared_secret = vec![0_u8; secret_len];

        let expected_wrapped = wrapped_key.len();
        let expected_secret = shared_secret.len();

        if openssl_sys::EVP_PKEY_encapsulate(
            ctx,
            wrapped_key.as_mut_ptr(),
            ptr::from_mut(&mut wrapped_len),
            shared_secret.as_mut_ptr(),
            ptr::from_mut(&mut secret_len),
        ) != 1
        {
            return Err(CryptoError::Default(
                "Hybrid KEM encapsulate failed".to_owned(),
            ));
        }

        if wrapped_len != expected_wrapped {
            return Err(CryptoError::Default(format!(
                "Hybrid KEM encapsulate: ciphertext size mismatch (expected {expected_wrapped}, got {wrapped_len})"
            )));
        }
        if secret_len != expected_secret {
            return Err(CryptoError::Default(format!(
                "Hybrid KEM encapsulate: shared secret size mismatch (expected {expected_secret}, got {secret_len})"
            )));
        }
        Ok((shared_secret, wrapped_key))
    }
}

/// Inner decapsulation using a raw `EVP_PKEY` pointer.
#[expect(unsafe_code)]
unsafe fn decapsulate_raw(
    pkey: *mut openssl_sys::EVP_PKEY,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use crate::crypto::pqc::ml_kem::CtxGuard;
    unsafe {
        let ctx = openssl_sys::EVP_PKEY_CTX_new(pkey, ptr::null_mut());
        if ctx.is_null() {
            return Err(CryptoError::Default(
                "Hybrid KEM decapsulate: EVP_PKEY_CTX_new failed".to_owned(),
            ));
        }
        let _ctx_guard = CtxGuard(ctx);

        if openssl_sys::EVP_PKEY_decapsulate_init(ctx, ptr::null()) != 1 {
            return Err(CryptoError::Default(
                "Hybrid KEM decapsulate: EVP_PKEY_decapsulate_init failed".to_owned(),
            ));
        }

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
                "Hybrid KEM decapsulate: size query failed".to_owned(),
            ));
        }

        let mut shared_secret = vec![0_u8; secret_len];
        let expected_secret = shared_secret.len();
        if openssl_sys::EVP_PKEY_decapsulate(
            ctx,
            shared_secret.as_mut_ptr(),
            ptr::from_mut(&mut secret_len),
            ciphertext.as_ptr(),
            ciphertext.len(),
        ) != 1
        {
            return Err(CryptoError::Default(
                "Hybrid KEM decapsulate failed".to_owned(),
            ));
        }

        if secret_len != expected_secret {
            return Err(CryptoError::Default(format!(
                "Hybrid KEM decapsulate: shared secret size mismatch (expected {expected_secret}, got {secret_len})"
            )));
        }
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn encaps_decaps_roundtrip(algorithm: CryptographicAlgorithm) {
        let algorithm_name = hybrid_kem_algorithm_name(algorithm).unwrap();
        let (priv_raw, pub_raw, _bits) =
            super::super::pqc_keygen_raw(algorithm_name).expect("keygen");

        let (ss1, ct) = hybrid_kem_encapsulate(algorithm, &pub_raw).expect("encapsulate");
        let ss2 = hybrid_kem_decapsulate(algorithm, &priv_raw, &ct).expect("decapsulate");
        assert_eq!(ss1, ss2);
        assert!(!ss1.is_empty());
    }

    #[test]
    fn x25519_ml_kem_768_roundtrip() {
        encaps_decaps_roundtrip(CryptographicAlgorithm::X25519MLKEM768);
    }

    #[test]
    fn x448_ml_kem_1024_roundtrip() {
        encaps_decaps_roundtrip(CryptographicAlgorithm::X448MLKEM1024);
    }

    #[test]
    fn hybrid_kem_create_key_pair() {
        let key_pair = create_hybrid_kem_key_pair(
            CryptographicAlgorithm::X25519MLKEM768,
            "cosmian",
            "sk-uid",
            "pk-uid",
            Attributes::default(),
            None,
            None,
        )
        .expect("create key pair");

        let (sk, pk) = (key_pair.0.0, key_pair.0.1);
        assert!(matches!(
            sk,
            cosmian_kmip::kmip_2_1::kmip_objects::Object::PrivateKey(_)
        ));
        assert!(matches!(
            pk,
            cosmian_kmip::kmip_2_1::kmip_objects::Object::PublicKey(_)
        ));

        let sk_block = sk.key_block().expect("sk key block");
        assert_eq!(sk_block.key_format_type, KeyFormatType::Raw);
        assert_eq!(
            sk_block.cryptographic_algorithm,
            Some(CryptographicAlgorithm::X25519MLKEM768)
        );
    }

    // ── Limit / panic-safety tests ────────────────────────────────────────────
    // All of these MUST return Err and must NOT panic, abort, or leak memory.

    #[test]
    fn hybrid_kem_encapsulate_empty_key_returns_err() {
        let result = hybrid_kem_encapsulate(CryptographicAlgorithm::X25519MLKEM768, &[]);
        assert!(
            result.is_err(),
            "empty raw public key must return Err, not panic"
        );
    }

    #[test]
    fn hybrid_kem_encapsulate_garbage_key_returns_err() {
        let result = hybrid_kem_encapsulate(CryptographicAlgorithm::X25519MLKEM768, &[0xFF_u8; 64]);
        assert!(
            result.is_err(),
            "garbage raw public key must return Err, not panic"
        );
    }

    #[test]
    fn hybrid_kem_decapsulate_empty_private_key_returns_err() {
        let result = hybrid_kem_decapsulate(CryptographicAlgorithm::X25519MLKEM768, &[], &[]);
        assert!(
            result.is_err(),
            "empty raw private key must return Err, not panic"
        );
    }

    #[test]
    fn hybrid_kem_decapsulate_empty_ciphertext_returns_err() {
        let algorithm_name =
            hybrid_kem_algorithm_name(CryptographicAlgorithm::X25519MLKEM768).unwrap();
        let (priv_raw, _pub_raw, _bits) =
            super::super::pqc_keygen_raw(algorithm_name).expect("keygen");
        let result = hybrid_kem_decapsulate(CryptographicAlgorithm::X25519MLKEM768, &priv_raw, &[]);
        assert!(
            result.is_err(),
            "empty ciphertext must return Err, not panic"
        );
    }

    #[test]
    fn hybrid_kem_decapsulate_garbage_ciphertext_returns_err() {
        let algorithm_name =
            hybrid_kem_algorithm_name(CryptographicAlgorithm::X25519MLKEM768).unwrap();
        let (priv_raw, _pub_raw, _bits) =
            super::super::pqc_keygen_raw(algorithm_name).expect("keygen");
        let result = hybrid_kem_decapsulate(
            CryptographicAlgorithm::X25519MLKEM768,
            &priv_raw,
            &[0xFF_u8; 64],
        );
        assert!(
            result.is_err(),
            "garbage ciphertext must return Err, not panic"
        );
    }
}
