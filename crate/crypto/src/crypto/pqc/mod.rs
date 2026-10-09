pub mod hybrid_kem;
pub mod ml_dsa;
pub mod ml_kem;
pub mod slh_dsa;

use std::{ffi::CString, ptr};

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
use foreign_types::ForeignType;
use openssl::pkey::{PKey, Private, Public};
use zeroize::Zeroizing;

use crate::{crypto::KeyPair, error::CryptoError};

/// Result of [`pqc_keygen`]: (private PKCS#8 DER, public SPKI DER, key bits).
type PqcKeygenResult = (Zeroizing<Vec<u8>>, Vec<u8>, u32);

/// Generate a PQC key with `EVP_PKEY_Q_keygen`, which the `openssl` crate cannot yet wrap.
#[expect(unsafe_code)]
fn q_keygen(algorithm_name: &str) -> Result<PKey<Private>, CryptoError> {
    let name = CString::new(algorithm_name)
        .map_err(|e| CryptoError::Default(format!("invalid algorithm name: {e}")))?;

    // SAFETY: `name` is NUL-terminated and outlives the call; null context/propq select the defaults.
    let raw =
        unsafe { openssl_sys::EVP_PKEY_Q_keygen(ptr::null_mut(), ptr::null(), name.as_ptr()) };
    if raw.is_null() {
        return Err(CryptoError::Default(format!(
            "EVP_PKEY_Q_keygen failed for {algorithm_name}: {}",
            openssl::error::ErrorStack::get()
        )));
    }
    // SAFETY: `raw` is non-null and exclusively owned; `PKey` frees it on drop.
    Ok(unsafe { PKey::from_ptr(raw) })
}

/// Generate a PQC key pair using OpenSSL `EVP_PKEY_Q_keygen`.
fn pqc_keygen(algorithm_name: &str) -> Result<PqcKeygenResult, CryptoError> {
    let pkey = q_keygen(algorithm_name)?;
    Ok((
        Zeroizing::from(pkey.private_key_to_der()?),
        pkey.public_key_to_der()?,
        pkey.bits(),
    ))
}

/// Generate a PQC key pair and extract raw key bytes (for algorithms that don't
/// support DER serialization, such as hybrid KEMs).
fn pqc_keygen_raw(algorithm_name: &str) -> Result<PqcKeygenResult, CryptoError> {
    let pkey = q_keygen(algorithm_name)?;
    Ok((
        Zeroizing::from(pkey.raw_private_key()?),
        pkey.raw_public_key()?,
        pkey.bits(),
    ))
}

/// Load a raw public key using the algorithm name.
#[expect(unsafe_code)]
pub(crate) fn load_raw_public_key(
    algorithm_name: &str,
    raw_bytes: &[u8],
) -> Result<PKey<Public>, CryptoError> {
    // Guard: an empty slice has a dangling .as_ptr(); passing it to C is UB.
    if raw_bytes.is_empty() {
        return Err(CryptoError::Default(format!(
            "load_raw_public_key: empty key bytes for {algorithm_name}"
        )));
    }
    let name = CString::new(algorithm_name)
        .map_err(|e| CryptoError::Default(format!("invalid algorithm name: {e}")))?;
    // SAFETY: `name` and `raw_bytes` outlive the call; null context/propq select the defaults.
    // `raw` is checked non-null and exclusively owned by the returned `PKey`.
    unsafe {
        let raw = openssl_sys::EVP_PKEY_new_raw_public_key_ex(
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
        Ok(PKey::from_ptr(raw))
    }
}

/// Load a raw private key using the algorithm name.
#[expect(unsafe_code)]
pub(crate) fn load_raw_private_key(
    algorithm_name: &str,
    raw_bytes: &[u8],
) -> Result<PKey<Private>, CryptoError> {
    // Guard: an empty slice has a dangling .as_ptr(); passing it to C is UB.
    if raw_bytes.is_empty() {
        return Err(CryptoError::Default(format!(
            "load_raw_private_key: empty key bytes for {algorithm_name}"
        )));
    }
    let name = CString::new(algorithm_name)
        .map_err(|e| CryptoError::Default(format!("invalid algorithm name: {e}")))?;
    // SAFETY: `name` and `raw_bytes` outlive the call; null context/propq select the defaults.
    // `raw` is checked non-null and exclusively owned by the returned `PKey`.
    unsafe {
        let raw = openssl_sys::EVP_PKEY_new_raw_private_key_ex(
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
        Ok(PKey::from_ptr(raw))
    }
}

/// Convert a PQC private key from PKCS#8 DER to raw bytes.
///
/// Loads the DER into an `EVP_PKEY` and extracts the raw private key material
/// via `EVP_PKEY_get_raw_private_key`.
pub fn pqc_private_key_pkcs8_to_raw(pkcs8_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if pkcs8_der.is_empty() {
        return Err(CryptoError::Default(
            "pqc_private_key_pkcs8_to_raw: empty PKCS#8 DER input".to_owned(),
        ));
    }
    Ok(PKey::private_key_from_der(pkcs8_der)?.raw_private_key()?)
}

/// Convert a PQC public key from SPKI DER to raw bytes.
///
/// Loads the DER into an `EVP_PKEY` and extracts the raw public key material
/// via `EVP_PKEY_get_raw_public_key`.
pub fn pqc_public_key_spki_to_raw(spki_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if spki_der.is_empty() {
        return Err(CryptoError::Default(
            "pqc_public_key_spki_to_raw: empty SPKI DER input".to_owned(),
        ));
    }
    Ok(PKey::public_key_from_der(spki_der)?.raw_public_key()?)
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

    /// Verify that `pqc_keygen` serializes a freshly generated ML-DSA key (the
    /// cheapest DER-capable PQC key) without panicking.
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

    // ── PKCS8/SPKI → Raw conversion round-trip ─────────────────────────────

    #[test]
    fn pkcs8_to_raw_private_roundtrip_ml_dsa_44() {
        // Generate key via pqc_keygen (PKCS8) and pqc_keygen + load → raw extraction
        let (pkcs8_der, _, _) = pqc_keygen("ML-DSA-44").expect("keygen");
        let raw = pqc_private_key_pkcs8_to_raw(&pkcs8_der).expect("pkcs8 to raw");
        assert!(!raw.is_empty(), "raw private key must not be empty");
        // Verify it can be loaded back
        let key = load_raw_private_key("ML-DSA-44", &raw).expect("reload raw");
        let raw2 = key.raw_private_key().expect("re-extract");
        assert_eq!(raw, raw2, "round-trip raw private key must match");
    }

    #[test]
    fn spki_to_raw_public_roundtrip_ml_dsa_44() {
        let (_, spki_der, _) = pqc_keygen("ML-DSA-44").expect("keygen");
        let raw = pqc_public_key_spki_to_raw(&spki_der).expect("spki to raw");
        assert!(!raw.is_empty(), "raw public key must not be empty");
        let key = load_raw_public_key("ML-DSA-44", &raw).expect("reload raw");
        let raw2 = key.raw_public_key().expect("re-extract");
        assert_eq!(raw, raw2, "round-trip raw public key must match");
    }

    #[test]
    fn pkcs8_to_raw_private_roundtrip_ml_kem_768() {
        let (pkcs8_der, _, _) = pqc_keygen("ML-KEM-768").expect("keygen");
        let raw = pqc_private_key_pkcs8_to_raw(&pkcs8_der).expect("pkcs8 to raw");
        assert!(!raw.is_empty(), "raw private key must not be empty");
        let key = load_raw_private_key("ML-KEM-768", &raw).expect("reload raw");
        let raw2 = key.raw_private_key().expect("re-extract");
        assert_eq!(raw, raw2, "round-trip raw private key must match");
    }

    #[test]
    fn spki_to_raw_public_roundtrip_ml_kem_768() {
        let (_, spki_der, _) = pqc_keygen("ML-KEM-768").expect("keygen");
        let raw = pqc_public_key_spki_to_raw(&spki_der).expect("spki to raw");
        assert!(!raw.is_empty(), "raw public key must not be empty");
        let key = load_raw_public_key("ML-KEM-768", &raw).expect("reload raw");
        let raw2 = key.raw_public_key().expect("re-extract");
        assert_eq!(raw, raw2, "round-trip raw public key must match");
    }

    #[test]
    fn pkcs8_to_raw_private_roundtrip_slh_dsa_sha2_128s() {
        let (pkcs8_der, _, _) = pqc_keygen("SLH-DSA-SHA2-128s").expect("keygen");
        let raw = pqc_private_key_pkcs8_to_raw(&pkcs8_der).expect("pkcs8 to raw");
        assert!(!raw.is_empty(), "raw private key must not be empty");
        let key = load_raw_private_key("SLH-DSA-SHA2-128s", &raw).expect("reload raw");
        let raw2 = key.raw_private_key().expect("re-extract");
        assert_eq!(raw, raw2, "round-trip raw private key must match");
    }

    #[test]
    fn spki_to_raw_public_roundtrip_slh_dsa_sha2_128s() {
        let (_, spki_der, _) = pqc_keygen("SLH-DSA-SHA2-128s").expect("keygen");
        let raw = pqc_public_key_spki_to_raw(&spki_der).expect("spki to raw");
        assert!(!raw.is_empty(), "raw public key must not be empty");
        let key = load_raw_public_key("SLH-DSA-SHA2-128s", &raw).expect("reload raw");
        let raw2 = key.raw_public_key().expect("re-extract");
        assert_eq!(raw, raw2, "round-trip raw public key must match");
    }

    #[test]
    fn pkcs8_to_raw_empty_input_returns_err() {
        assert!(
            pqc_private_key_pkcs8_to_raw(&[]).is_err(),
            "empty private key input should fail"
        );
        assert!(
            pqc_public_key_spki_to_raw(&[]).is_err(),
            "empty public key input should fail"
        );
    }

    #[test]
    fn pkcs8_to_raw_garbage_input_returns_err() {
        assert!(
            pqc_private_key_pkcs8_to_raw(&[0xDE; 128]).is_err(),
            "garbage private key input should fail"
        );
        assert!(
            pqc_public_key_spki_to_raw(&[0xDE; 128]).is_err(),
            "garbage public key input should fail"
        );
    }
}
