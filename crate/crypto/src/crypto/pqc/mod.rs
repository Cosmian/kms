pub mod hybrid_kem;
pub mod ml_dsa;
pub mod ml_kem;
pub mod slh_dsa;

use std::{
    ffi::{CString, c_char},
    ptr,
};

use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        extra::tagging::{SYSTEM_TAG_PRIVATE_KEY, SYSTEM_TAG_PUBLIC_KEY},
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PrivateKey, PublicKey},
        kmip_types::{
            CryptographicAlgorithm, KeyFormatType, LinkType, LinkedObjectIdentifier,
            UniqueIdentifier,
        },
    },
};
use zeroize::Zeroizing;

use crate::{crypto::KeyPair, error::CryptoError};

/// RAII guard for an owned `EVP_PKEY` pointer — calls `EVP_PKEY_free` on drop.
///
/// `PKey<T>` from the `openssl` crate offers the same guarantee, but constructing
/// it from a raw pointer requires importing the `ForeignType` trait from
/// `foreign_types_shared` which is not a direct workspace dependency. This thin
/// wrapper achieves the same RAII semantics without the extra dependency.
pub(crate) struct PKeyGuard(pub(crate) *mut openssl_sys::EVP_PKEY);

/// RAII guard for an owned `BIO` pointer — calls `BIO_free_all` on drop.
///
/// Ensures the BIO memory is freed even if the code reading its contents
/// panics (e.g. an OOM abort in `to_vec()`), eliminating a resource leak
/// in `evp_pkey_to_pkcs8_der` / `evp_pkey_to_spki_der`.
struct BioGuard(*mut openssl_sys::BIO);

impl Drop for BioGuard {
    #[expect(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: pointer was checked for null before wrapping; BIO_free_all
        // accepts null as a documented no-op, so double-drop is also safe.
        unsafe { openssl_sys::BIO_free_all(self.0) }
    }
}

impl PKeyGuard {
    pub(crate) const fn as_ptr(&self) -> *mut openssl_sys::EVP_PKEY {
        self.0
    }
}

impl Drop for PKeyGuard {
    #[expect(unsafe_code)]
    fn drop(&mut self) {
        unsafe {
            openssl_sys::EVP_PKEY_free(self.0);
        }
    }
}

/// Result of [`pqc_keygen`]: (private PKCS#8 DER, public SPKI DER, key bits).
type PqcKeygenResult = (Zeroizing<Vec<u8>>, Vec<u8>, u32);

/// Serialize an `EVP_PKEY` to PKCS#8 DER (private key).
#[expect(unsafe_code)]
fn evp_pkey_to_pkcs8_der(pkey: *mut openssl_sys::EVP_PKEY) -> Result<Vec<u8>, CryptoError> {
    unsafe {
        let bio = openssl_sys::BIO_new(openssl_sys::BIO_s_mem());
        if bio.is_null() {
            return Err(CryptoError::Default("BIO_new failed".to_owned()));
        }
        // SAFETY: BioGuard frees the BIO on drop — even if to_vec() panics
        // with OOM later in this function, preventing a resource leak.
        let _bio_guard = BioGuard(bio);

        if openssl_sys::i2d_PrivateKey_bio(bio, pkey) != 1 {
            return Err(CryptoError::Default(format!(
                "i2d_PKCS8PrivateKeyInfo_bio failed: {}",
                openssl::error::ErrorStack::get()
            )));
        }
        let mut ptr: *mut c_char = ptr::null_mut();
        let len = openssl_sys::BIO_get_mem_data(bio, ptr::from_mut(&mut ptr));
        if len <= 0 || ptr.is_null() {
            return Err(CryptoError::Default("BIO_get_mem_data failed".to_owned()));
        }
        // Propagate length overflow as an error rather than silently returning
        // an empty slice (would only happen on 32-bit targets with >2 GB keys).
        let len_usize = usize::try_from(len)
            .map_err(|e| CryptoError::Default(format!("BIO data length overflow: {e}")))?;
        // Copy the bytes *before* _bio_guard drops — the slice borrows BIO
        // internal memory, so it must not outlive the BIO.
        let der = std::slice::from_raw_parts(ptr.cast::<u8>(), len_usize).to_vec();
        Ok(der)
        // _bio_guard drops here, freeing the BIO.
    }
}

/// Serialize an `EVP_PKEY` to `SubjectPublicKeyInfo` DER (public key).
#[expect(unsafe_code)]
fn evp_pkey_to_spki_der(pkey: *mut openssl_sys::EVP_PKEY) -> Result<Vec<u8>, CryptoError> {
    unsafe {
        let bio = openssl_sys::BIO_new(openssl_sys::BIO_s_mem());
        if bio.is_null() {
            return Err(CryptoError::Default("BIO_new failed".to_owned()));
        }
        // SAFETY: BioGuard frees the BIO on drop — even if to_vec() panics
        // with OOM later in this function, preventing a resource leak.
        let _bio_guard = BioGuard(bio);

        if openssl_sys::i2d_PUBKEY_bio(bio, pkey) != 1 {
            return Err(CryptoError::Default(format!(
                "i2d_PUBKEY_bio failed: {}",
                openssl::error::ErrorStack::get()
            )));
        }
        let mut ptr: *mut c_char = ptr::null_mut();
        let len = openssl_sys::BIO_get_mem_data(bio, ptr::from_mut(&mut ptr));
        if len <= 0 || ptr.is_null() {
            return Err(CryptoError::Default("BIO_get_mem_data failed".to_owned()));
        }
        // Propagate length overflow as an error rather than silently returning
        // an empty slice (would only happen on 32-bit targets with >2 GB keys).
        let len_usize = usize::try_from(len)
            .map_err(|e| CryptoError::Default(format!("BIO data length overflow: {e}")))?;
        // Copy the bytes *before* _bio_guard drops — the slice borrows BIO
        // internal memory, so it must not outlive the BIO.
        let der = std::slice::from_raw_parts(ptr.cast::<u8>(), len_usize).to_vec();
        Ok(der)
        // _bio_guard drops here, freeing the BIO.
    }
}

/// Extract the raw private key bytes from an `EVP_PKEY`.
#[expect(unsafe_code)]
fn evp_pkey_get_raw_private(pkey: *mut openssl_sys::EVP_PKEY) -> Result<Vec<u8>, CryptoError> {
    unsafe {
        let mut len: usize = 0;
        if openssl_sys::EVP_PKEY_get_raw_private_key(pkey, ptr::null_mut(), &raw mut len) != 1 {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_get_raw_private_key (size) failed: {}",
                openssl::error::ErrorStack::get()
            )));
        }
        let mut buf = vec![0_u8; len];
        let expected = len;
        if openssl_sys::EVP_PKEY_get_raw_private_key(pkey, buf.as_mut_ptr(), &raw mut len) != 1 {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_get_raw_private_key (data) failed: {}",
                openssl::error::ErrorStack::get()
            )));
        }
        if len != expected {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_get_raw_private_key: size mismatch (expected {expected}, got {len})"
            )));
        }
        Ok(buf)
    }
}

/// Extract the raw public key bytes from an `EVP_PKEY`.
#[expect(unsafe_code)]
fn evp_pkey_get_raw_public(pkey: *mut openssl_sys::EVP_PKEY) -> Result<Vec<u8>, CryptoError> {
    unsafe {
        let mut len: usize = 0;
        if openssl_sys::EVP_PKEY_get_raw_public_key(pkey, ptr::null_mut(), &raw mut len) != 1 {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_get_raw_public_key (size) failed: {}",
                openssl::error::ErrorStack::get()
            )));
        }
        let mut buf = vec![0_u8; len];
        let expected = len;
        if openssl_sys::EVP_PKEY_get_raw_public_key(pkey, buf.as_mut_ptr(), &raw mut len) != 1 {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_get_raw_public_key (data) failed: {}",
                openssl::error::ErrorStack::get()
            )));
        }
        if len != expected {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_get_raw_public_key: size mismatch (expected {expected}, got {len})"
            )));
        }
        Ok(buf)
    }
}

/// Generate a PQC key pair using OpenSSL `EVP_PKEY_Q_keygen`.
#[expect(unsafe_code)]
fn pqc_keygen(algorithm_name: &str) -> Result<PqcKeygenResult, CryptoError> {
    let name = CString::new(algorithm_name)
        .map_err(|e| CryptoError::Default(format!("invalid algorithm name: {e}")))?;

    unsafe {
        let raw = openssl_sys::EVP_PKEY_Q_keygen(ptr::null_mut(), ptr::null(), name.as_ptr());
        if raw.is_null() {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_Q_keygen failed for {algorithm_name}: {}",
                openssl::error::ErrorStack::get()
            )));
        }
        // Take ownership: freed automatically on drop, even if subsequent calls error.
        let pkey = PKeyGuard(raw);

        let bits = u32::try_from(openssl_sys::EVP_PKEY_bits(pkey.as_ptr())).map_err(|e| {
            CryptoError::Default(format!("EVP_PKEY_bits returned negative value: {e}"))
        })?;

        let private_der = evp_pkey_to_pkcs8_der(pkey.as_ptr())?;
        let public_der = evp_pkey_to_spki_der(pkey.as_ptr())?;

        Ok((Zeroizing::from(private_der), public_der, bits))
    }
}

/// Generate a PQC key pair and extract raw key bytes (for algorithms that don't
/// support DER serialization, such as hybrid KEMs).
#[expect(unsafe_code)]
fn pqc_keygen_raw(algorithm_name: &str) -> Result<PqcKeygenResult, CryptoError> {
    let name = CString::new(algorithm_name)
        .map_err(|e| CryptoError::Default(format!("invalid algorithm name: {e}")))?;

    unsafe {
        let raw = openssl_sys::EVP_PKEY_Q_keygen(ptr::null_mut(), ptr::null(), name.as_ptr());
        if raw.is_null() {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_Q_keygen failed for {algorithm_name}: {}",
                openssl::error::ErrorStack::get()
            )));
        }
        // Take ownership: freed automatically on drop, even if subsequent calls error.
        let pkey = PKeyGuard(raw);

        let bits = u32::try_from(openssl_sys::EVP_PKEY_bits(pkey.as_ptr())).map_err(|e| {
            CryptoError::Default(format!("EVP_PKEY_bits returned negative value: {e}"))
        })?;

        let private_raw = evp_pkey_get_raw_private(pkey.as_ptr())?;
        let public_raw = evp_pkey_get_raw_public(pkey.as_ptr())?;

        Ok((Zeroizing::from(private_raw), public_raw, bits))
    }
}

// FFI declarations for OpenSSL 3.x _ex raw key loading functions
// (not available in openssl-sys crate)
#[expect(unsafe_code)]
unsafe extern "C" {
    fn EVP_PKEY_new_raw_public_key_ex(
        libctx: *mut openssl_sys::OSSL_LIB_CTX,
        keytype: *const std::ffi::c_char,
        propq: *const std::ffi::c_char,
        key: *const u8,
        keylen: usize,
    ) -> *mut openssl_sys::EVP_PKEY;

    fn EVP_PKEY_new_raw_private_key_ex(
        libctx: *mut openssl_sys::OSSL_LIB_CTX,
        keytype: *const std::ffi::c_char,
        propq: *const std::ffi::c_char,
        key: *const u8,
        keylen: usize,
    ) -> *mut openssl_sys::EVP_PKEY;
}

/// Load a raw public key into a `PKeyGuard` using the algorithm name.
/// The returned guard owns the allocation and frees it on drop.
#[expect(unsafe_code)]
pub(crate) fn load_raw_public_key(
    algorithm_name: &str,
    raw_bytes: &[u8],
) -> Result<PKeyGuard, CryptoError> {
    // Guard: an empty slice has a dangling .as_ptr(); passing it to C is UB.
    if raw_bytes.is_empty() {
        return Err(CryptoError::Default(format!(
            "load_raw_public_key: empty key bytes for {algorithm_name}"
        )));
    }
    let name = CString::new(algorithm_name)
        .map_err(|e| CryptoError::Default(format!("invalid algorithm name: {e}")))?;
    unsafe {
        let raw = EVP_PKEY_new_raw_public_key_ex(
            ptr::null_mut(),
            name.as_ptr(),
            ptr::null(),
            raw_bytes.as_ptr(),
            raw_bytes.len(),
        );
        if raw.is_null() {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_new_raw_public_key_ex failed for {algorithm_name}: {}",
                openssl::error::ErrorStack::get()
            )));
        }
        Ok(PKeyGuard(raw))
    }
}

/// Load a raw private key into a `PKeyGuard` using the algorithm name.
/// The returned guard owns the allocation and frees it on drop.
#[expect(unsafe_code)]
pub(crate) fn load_raw_private_key(
    algorithm_name: &str,
    raw_bytes: &[u8],
) -> Result<PKeyGuard, CryptoError> {
    // Guard: an empty slice has a dangling .as_ptr(); passing it to C is UB.
    if raw_bytes.is_empty() {
        return Err(CryptoError::Default(format!(
            "load_raw_private_key: empty key bytes for {algorithm_name}"
        )));
    }
    let name = CString::new(algorithm_name)
        .map_err(|e| CryptoError::Default(format!("invalid algorithm name: {e}")))?;
    unsafe {
        let raw = EVP_PKEY_new_raw_private_key_ex(
            ptr::null_mut(),
            name.as_ptr(),
            ptr::null(),
            raw_bytes.as_ptr(),
            raw_bytes.len(),
        );
        if raw.is_null() {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_new_raw_private_key_ex failed for {algorithm_name}: {}",
                openssl::error::ErrorStack::get()
            )));
        }
        Ok(PKeyGuard(raw))
    }
}

/// Map a `CryptographicAlgorithm` to the OpenSSL algorithm name string.
fn ml_kem_algorithm_name(algorithm: CryptographicAlgorithm) -> Result<&'static str, CryptoError> {
    match algorithm {
        CryptographicAlgorithm::MLKEM_512 => Ok("ML-KEM-512"),
        CryptographicAlgorithm::MLKEM_768 => Ok("ML-KEM-768"),
        CryptographicAlgorithm::MLKEM_1024 => Ok("ML-KEM-1024"),
        other => Err(CryptoError::Default(format!(
            "Not an ML-KEM algorithm: {other:?}"
        ))),
    }
}

/// Map a `CryptographicAlgorithm` to the OpenSSL algorithm name string.
fn ml_dsa_algorithm_name(algorithm: CryptographicAlgorithm) -> Result<&'static str, CryptoError> {
    match algorithm {
        CryptographicAlgorithm::MLDSA_44 => Ok("ML-DSA-44"),
        CryptographicAlgorithm::MLDSA_65 => Ok("ML-DSA-65"),
        CryptographicAlgorithm::MLDSA_87 => Ok("ML-DSA-87"),
        other => Err(CryptoError::Default(format!(
            "Not an ML-DSA algorithm: {other:?}"
        ))),
    }
}

/// Map a hybrid KEM `CryptographicAlgorithm` to the OpenSSL algorithm name string.
fn hybrid_kem_algorithm_name(
    algorithm: CryptographicAlgorithm,
) -> Result<&'static str, CryptoError> {
    match algorithm {
        CryptographicAlgorithm::X25519MLKEM768 => Ok("X25519MLKEM768"),
        CryptographicAlgorithm::X448MLKEM1024 => Ok("X448MLKEM1024"),
        other => Err(CryptoError::Default(format!(
            "Not a hybrid KEM algorithm: {other:?}"
        ))),
    }
}

/// Map an SLH-DSA `CryptographicAlgorithm` to the OpenSSL algorithm name string.
fn slh_dsa_algorithm_name(algorithm: CryptographicAlgorithm) -> Result<&'static str, CryptoError> {
    match algorithm {
        CryptographicAlgorithm::SLHDSA_SHA2_128s => Ok("SLH-DSA-SHA2-128s"),
        CryptographicAlgorithm::SLHDSA_SHA2_128f => Ok("SLH-DSA-SHA2-128f"),
        CryptographicAlgorithm::SLHDSA_SHA2_192s => Ok("SLH-DSA-SHA2-192s"),
        CryptographicAlgorithm::SLHDSA_SHA2_192f => Ok("SLH-DSA-SHA2-192f"),
        CryptographicAlgorithm::SLHDSA_SHA2_256s => Ok("SLH-DSA-SHA2-256s"),
        CryptographicAlgorithm::SLHDSA_SHA2_256f => Ok("SLH-DSA-SHA2-256f"),
        CryptographicAlgorithm::SLHDSA_SHAKE_128s => Ok("SLH-DSA-SHAKE-128s"),
        CryptographicAlgorithm::SLHDSA_SHAKE_128f => Ok("SLH-DSA-SHAKE-128f"),
        CryptographicAlgorithm::SLHDSA_SHAKE_192s => Ok("SLH-DSA-SHAKE-192s"),
        CryptographicAlgorithm::SLHDSA_SHAKE_192f => Ok("SLH-DSA-SHAKE-192f"),
        CryptographicAlgorithm::SLHDSA_SHAKE_256s => Ok("SLH-DSA-SHAKE-256s"),
        CryptographicAlgorithm::SLHDSA_SHAKE_256f => Ok("SLH-DSA-SHAKE-256f"),
        other => Err(CryptoError::Default(format!(
            "Not an SLH-DSA algorithm: {other:?}"
        ))),
    }
}

/// Build a KMIP key pair from key bytes.
#[expect(clippy::too_many_arguments)]
fn create_pqc_key_pair(
    vendor_id: &str,
    private_key_der: &Zeroizing<Vec<u8>>,
    public_key_der: &[u8],
    cryptographic_length: i32,
    cryptographic_algorithm: CryptographicAlgorithm,
    key_format_type: KeyFormatType,
    private_key_uid: &str,
    public_key_uid: &str,
    mut common_attributes: Attributes,
    private_key_attributes: Option<Attributes>,
    public_key_attributes: Option<Attributes>,
    private_key_usage_mask: CryptographicUsageMask,
    public_key_usage_mask: CryptographicUsageMask,
) -> Result<KeyPair, CryptoError> {
    // Recover tags and clean them from common attributes
    let tags = common_attributes.remove_tags(vendor_id).unwrap_or_default();
    Attributes::check_user_tags(&tags)?;

    // Build private key KMIP Object
    let mut priv_attrs = private_key_attributes.unwrap_or_default();
    priv_attrs.merge(&common_attributes, false);
    priv_attrs.cryptographic_algorithm = Some(cryptographic_algorithm);
    priv_attrs.cryptographic_length = Some(cryptographic_length);
    priv_attrs.key_format_type = Some(key_format_type);
    priv_attrs.object_type = Some(ObjectType::PrivateKey);
    priv_attrs.cryptographic_usage_mask = priv_attrs
        .cryptographic_usage_mask
        .or(Some(private_key_usage_mask));
    priv_attrs.unique_identifier = Some(UniqueIdentifier::TextString(private_key_uid.to_owned()));
    priv_attrs.set_link(
        LinkType::PublicKeyLink,
        LinkedObjectIdentifier::TextString(public_key_uid.to_owned()),
    );
    let mut sk_tags = tags.clone();
    sk_tags.insert(SYSTEM_TAG_PRIVATE_KEY.to_owned());
    priv_attrs.set_tags(vendor_id, sk_tags)?;

    let private_key_object = Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            key_format_type,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(private_key_der.clone()),
                attributes: Some(priv_attrs),
            }),
            cryptographic_algorithm: Some(cryptographic_algorithm),
            cryptographic_length: Some(cryptographic_length),
            key_wrapping_data: None,
            key_compression_type: None,
        },
    });

    // Build public key KMIP Object
    let mut pub_attrs = public_key_attributes.unwrap_or_default();
    pub_attrs.merge(&common_attributes, false);
    pub_attrs.cryptographic_algorithm = Some(cryptographic_algorithm);
    pub_attrs.cryptographic_length = Some(cryptographic_length);
    pub_attrs.key_format_type = Some(key_format_type);
    pub_attrs.object_type = Some(ObjectType::PublicKey);
    pub_attrs.cryptographic_usage_mask = pub_attrs
        .cryptographic_usage_mask
        .or(Some(public_key_usage_mask));
    pub_attrs.unique_identifier = Some(UniqueIdentifier::TextString(public_key_uid.to_owned()));
    pub_attrs.set_link(
        LinkType::PrivateKeyLink,
        LinkedObjectIdentifier::TextString(private_key_uid.to_owned()),
    );
    let mut pk_tags = tags;
    pk_tags.insert(SYSTEM_TAG_PUBLIC_KEY.to_owned());
    pub_attrs.set_tags(vendor_id, pk_tags)?;

    let public_key_object = Object::PublicKey(PublicKey {
        key_block: KeyBlock {
            key_format_type,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::from(public_key_der.to_vec())),
                attributes: Some(pub_attrs),
            }),
            cryptographic_algorithm: Some(cryptographic_algorithm),
            cryptographic_length: Some(cryptographic_length),
            key_wrapping_data: None,
            key_compression_type: None,
        },
    });

    Ok(KeyPair::new(private_key_object, public_key_object))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    // ── BIO RAII / serialization round-trip ─────────────────────────────────

    /// Verify that the key serialization helpers (`evp_pkey_to_pkcs8_der` /
    /// `evp_pkey_to_spki_der`) work and do not panic or leak when called with a
    /// freshly generated ML-DSA key (the cheapest DER-capable PQC key).
    #[test]
    fn bio_serialization_roundtrip_does_not_panic() {
        let (priv_der, pub_der, _bits) = pqc_keygen("ML-DSA-44").expect("keygen");
        assert!(!priv_der.is_empty(), "private DER must not be empty");
        assert!(!pub_der.is_empty(), "public DER must not be empty");
    }

    // ── load_raw_public_key error paths ─────────────────────────────────────
    // All must return Err and MUST NOT panic, abort, or leak memory.

    #[test]
    fn load_raw_pub_key_empty_returns_err() {
        let result = load_raw_public_key("X25519MLKEM768", &[]);
        assert!(result.is_err(), "empty bytes must return Err, not panic");
    }

    #[test]
    fn load_raw_pub_key_garbage_returns_err() {
        let result = load_raw_public_key("X25519MLKEM768", &[0xFF_u8; 64]);
        assert!(result.is_err(), "garbage bytes must return Err, not panic");
    }

    #[test]
    fn load_raw_pub_key_wrong_algorithm_returns_err() {
        // Generate a valid X25519MLKEM768 raw public key, then load it under a
        // different (wrong) algorithm name — OpenSSL must reject it.
        let (_, pub_raw, _) = pqc_keygen_raw("X25519MLKEM768").expect("keygen");
        let result = load_raw_public_key("X448MLKEM1024", &pub_raw);
        assert!(
            result.is_err(),
            "key for wrong algorithm must return Err, not panic"
        );
    }

    // ── load_raw_private_key error paths ────────────────────────────────────

    #[test]
    fn load_raw_priv_key_empty_returns_err() {
        let result = load_raw_private_key("X25519MLKEM768", &[]);
        assert!(result.is_err(), "empty bytes must return Err, not panic");
    }

    #[test]
    fn load_raw_priv_key_garbage_returns_err() {
        let result = load_raw_private_key("X25519MLKEM768", &[0xDE_u8; 64]);
        assert!(result.is_err(), "garbage bytes must return Err, not panic");
    }

    #[test]
    fn load_raw_priv_key_wrong_algorithm_returns_err() {
        let (priv_raw, _, _) = pqc_keygen_raw("X25519MLKEM768").expect("keygen");
        let result = load_raw_private_key("X448MLKEM1024", &priv_raw);
        assert!(
            result.is_err(),
            "key for wrong algorithm must return Err, not panic"
        );
    }
}
