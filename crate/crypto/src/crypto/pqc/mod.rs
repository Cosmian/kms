pub mod hybrid_kem;
pub mod ml_dsa;
pub mod ml_kem;
pub mod slh_dsa;

use std::{
    ffi::{CStr, CString},
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
use foreign_types::ForeignType;
use openssl::pkey::{KeyType, PKey, Private, Public};
use zeroize::Zeroizing;

use crate::{
    crypto::{KeyPair, KeyPairIdentity, KmsRng},
    error::CryptoError,
};

/// Result of [`pqc_keygen`]: (private PKCS#8 DER, public SPKI DER, key bits).
type PqcKeygenResult = (Zeroizing<Vec<u8>>, Vec<u8>, u32);

/// Generate deterministic seed bytes for PQC key generation.
///
/// Returns `seed_len` random bytes from `KmsRng`, in a zeroizing buffer.
///
/// When `rng` is supplied to [`pqc_keygen`], seeds of 64 bytes (ML-KEM) or 32 bytes
/// (ML-DSA) are drawn from this function and injected into OpenSSL's keygen context.
///
/// # Arguments
/// * `rng` - The KMS RNG instance
/// * `seed_len` - Desired seed length in bytes
///
/// # Returns
/// A `Zeroizing<Vec<u8>>` containing cryptographically random seed bytes that
/// are automatically zeroed on drop, preventing accidental leakage of entropy state.
pub fn generate_pqc_seed(rng: &KmsRng, seed_len: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    rng.random_vec(seed_len)
        .map_err(|e| CryptoError::Default(format!("PQC seed generation failed: {e}")))
}

/// `KeyType` and seed length (bytes) of the algorithms OpenSSL derives from a seed:
/// ML-KEM takes a 64-byte seed (FIPS 203 §7.1), ML-DSA a 32-byte seed (FIPS 204 §6.1).
fn seeded_key_type(algorithm_name: &str) -> Option<(KeyType, usize)> {
    Some(match algorithm_name {
        "ML-KEM-512" => (KeyType::ML_KEM_512, 64),
        "ML-KEM-768" => (KeyType::ML_KEM_768, 64),
        "ML-KEM-1024" => (KeyType::ML_KEM_1024, 64),
        "ML-DSA-44" => (KeyType::ML_DSA_44, 32),
        "ML-DSA-65" => (KeyType::ML_DSA_65, 32),
        "ML-DSA-87" => (KeyType::ML_DSA_87, 32),
        _ => return None,
    })
}

/// Derive an ML-KEM or ML-DSA key pair from `seed` with the safe
/// `PKey::private_key_from_seed` (`EVP_PKEY_fromdata` with the `seed` parameter; the
/// provider's import runs the pairwise consistency test).
fn pqc_keygen_seeded(
    key_type: KeyType,
    seed: &[u8],
    propquery: Option<&CStr>,
) -> Result<PKey<Private>, CryptoError> {
    PKey::private_key_from_seed(None, key_type, propquery, seed).map_err(|e| {
        CryptoError::Default(format!(
            "seeded PQC key generation failed for {key_type:?}: {e}"
        ))
    })
}

/// Generate a key pair by algorithm name with OpenSSL's internal DRBG.
///
/// Upstream tracking: `EVP_PKEY_Q_keygen` is used until `rust-openssl` offers keygen by
/// algorithm name (Issue #1251, upstream PRs #2649, #2646, #2636, #2611).
#[expect(
    unsafe_code,
    reason = "EVP_PKEY_Q_keygen has no safe rust-openssl binding (#1251)"
)]
fn pqc_keygen_unseeded(
    algorithm_name: &str,
    propquery: Option<&CStr>,
) -> Result<PKey<Private>, CryptoError> {
    let name = CString::new(algorithm_name)
        .map_err(|e| CryptoError::Default(format!("invalid algorithm name: {e}")))?;
    // SAFETY: `name` and `propquery` (when `Some`) are valid NUL-terminated strings that
    // outlive the call; a null propq selects OpenSSL defaults. The returned non-null key is
    // owned by `PKey`.
    unsafe {
        let raw = openssl_sys::EVP_PKEY_Q_keygen(
            ptr::null_mut(),
            propquery.map_or(ptr::null(), CStr::as_ptr),
            name.as_ptr(),
        );
        if raw.is_null() {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_Q_keygen failed for {algorithm_name}: {}",
                openssl::error::ErrorStack::get()
            )));
        }
        Ok(PKey::from_ptr(raw))
    }
}

/// Convert an optional string slice propquery to an optional `CString`.
fn parse_propquery(propquery: Option<&str>) -> Result<Option<CString>, CryptoError> {
    propquery
        .map(|pq| {
            CString::new(pq)
                .map_err(|e| CryptoError::Default(format!("invalid propquery string: {e}")))
        })
        .transpose()
}

/// Generate a PQC key pair, seeded from `KmsRng` when possible.
///
/// When `rng` is `Some`:
/// - ML-KEM draws a 64-byte seed from `KmsRng` (FIPS 203 §7.1 / OpenSSL `ml_kem_kmgmt.c`).
/// - ML-DSA draws a 32-byte seed from `KmsRng` (FIPS 204 §6.1 / OpenSSL `ml_dsa_kmgmt.c`).
///
/// Seeded keys come from `PKey::private_key_from_seed`. SLH-DSA, whose seed parameter
/// OpenSSL documents as testing-only (`EVP_PKEY-SLH-DSA(7)`), and every call with `rng`
/// `None` use OpenSSL's internal DRBG through [`pqc_keygen_unseeded`].
fn pqc_keygen(
    algorithm_name: &str,
    rng: Option<&KmsRng>,
    propquery: Option<&str>,
) -> Result<PqcKeygenResult, CryptoError> {
    let propq_c = parse_propquery(propquery)?;
    let safe_pkey = match (rng, seeded_key_type(algorithm_name)) {
        (Some(rng), Some((key_type, seed_len))) => {
            let seed = generate_pqc_seed(rng, seed_len)?;
            pqc_keygen_seeded(key_type, &seed, propq_c.as_deref())?
        }
        _ => pqc_keygen_unseeded(algorithm_name, propq_c.as_deref())?,
    };

    let bits = safe_pkey.bits();
    let private_der = safe_pkey
        .private_key_to_pkcs8()
        .map_err(|e| CryptoError::Default(format!("private_key_to_pkcs8 failed: {e}")))?;
    let public_der = safe_pkey
        .public_key_to_der()
        .map_err(|e| CryptoError::Default(format!("public_key_to_der failed: {e}")))?;

    Ok((Zeroizing::from(private_der), public_der, bits))
}

/// Generate a PQC key pair and extract raw key bytes (for algorithms that don't
/// support DER serialization, such as hybrid KEMs).
///
/// `rng` is unused for hybrid KEMs: OpenSSL 3.6.5 generates composite keys atomically
/// without exposing a seed parameter (see `mlx_kmgmt.c`).
fn pqc_keygen_raw(
    algorithm_name: &str,
    rng: Option<&KmsRng>,
    propquery: Option<&str>,
) -> Result<PqcKeygenResult, CryptoError> {
    let _ = rng;
    let propq_c = parse_propquery(propquery)?;
    let safe_pkey = pqc_keygen_unseeded(algorithm_name, propq_c.as_deref())?;
    let bits = safe_pkey.bits();
    let private_raw = safe_pkey
        .raw_private_key()
        .map_err(|e| CryptoError::Default(format!("raw_private_key failed: {e}")))?;
    let public_raw = safe_pkey
        .raw_public_key()
        .map_err(|e| CryptoError::Default(format!("raw_public_key failed: {e}")))?;

    Ok((Zeroizing::from(private_raw), public_raw, bits))
}

/// Load a raw public key by algorithm name.
///
/// Upstream tracking: `openssl::pkey::PKey::public_key_from_raw_bytes_ex` takes a `KeyType`,
/// which has no hybrid KEM value (Issue #1251); `EVP_PKEY_new_raw_public_key_ex` is used.
#[expect(
    unsafe_code,
    reason = "KeyType has no hybrid KEM value for public_key_from_raw_bytes_ex (#1251)"
)]
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
    // SAFETY: `name` is a valid NUL-terminated CString and `raw_bytes` is non-empty (checked
    // above); a null libctx/propq selects OpenSSL defaults. The returned non-null key is
    // owned by `PKey`.
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

/// Load a raw private key by algorithm name.
///
/// Upstream tracking: `openssl::pkey::PKey::private_key_from_raw_bytes_ex` takes a `KeyType`,
/// which has no hybrid KEM value (Issue #1251); `EVP_PKEY_new_raw_private_key_ex` is used.
#[expect(
    unsafe_code,
    reason = "KeyType has no hybrid KEM value for private_key_from_raw_bytes_ex (#1251)"
)]
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
    // SAFETY: `name` is a valid NUL-terminated CString and `raw_bytes` is non-empty (checked
    // above); a null libctx/propq selects OpenSSL defaults. The returned non-null key is
    // owned by `PKey`.
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
/// Completely safe implementation using native `openssl::pkey::PKey` methods (Issue #894).
pub fn pqc_private_key_pkcs8_to_raw(pkcs8_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if pkcs8_der.is_empty() {
        return Err(CryptoError::Default(
            "pqc_private_key_pkcs8_to_raw: empty PKCS#8 DER input".to_owned(),
        ));
    }
    let pkey = PKey::private_key_from_der(pkcs8_der)
        .map_err(|e| CryptoError::Default(format!("pqc_private_key_pkcs8_to_raw: {e}")))?;
    let raw = pkey
        .raw_private_key()
        .map_err(|e| CryptoError::Default(format!("pqc_private_key_pkcs8_to_raw: {e}")))?;
    Ok(raw)
}

/// Convert a PQC public key from SPKI DER to raw bytes.
///
/// Completely safe implementation using native `openssl::pkey::PKey` methods (Issue #894).
pub fn pqc_public_key_spki_to_raw(spki_der: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if spki_der.is_empty() {
        return Err(CryptoError::Default(
            "pqc_public_key_spki_to_raw: empty SPKI DER input".to_owned(),
        ));
    }
    let pkey = PKey::public_key_from_der(spki_der)
        .map_err(|e| CryptoError::Default(format!("pqc_public_key_spki_to_raw: {e}")))?;
    let raw = pkey
        .raw_public_key()
        .map_err(|e| CryptoError::Default(format!("pqc_public_key_spki_to_raw: {e}")))?;
    Ok(raw)
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

/// Raw key material of a freshly generated PQC key pair.
#[derive(Clone, Copy)]
struct PqcKeyMaterial<'a> {
    private_key_der: &'a Zeroizing<Vec<u8>>,
    public_key_der: &'a [u8],
    cryptographic_length: i32,
    key_format_type: KeyFormatType,
}

/// Algorithm and default usage masks applied to a PQC key pair.
#[derive(Clone, Copy)]
struct PqcKeyPolicy {
    cryptographic_algorithm: CryptographicAlgorithm,
    private_key_usage_mask: CryptographicUsageMask,
    public_key_usage_mask: CryptographicUsageMask,
}

/// Build a KMIP key pair from key bytes.
fn create_pqc_key_pair(
    identity: KeyPairIdentity<'_>,
    material: PqcKeyMaterial<'_>,
    policy: PqcKeyPolicy,
) -> Result<KeyPair, CryptoError> {
    let KeyPairIdentity {
        vendor_id,
        private_key_uid,
        public_key_uid,
        mut common_attributes,
        private_key_attributes,
        public_key_attributes,
    } = identity;
    let PqcKeyMaterial {
        private_key_der,
        public_key_der,
        cryptographic_length,
        key_format_type,
    } = material;
    let PqcKeyPolicy {
        cryptographic_algorithm,
        private_key_usage_mask,
        public_key_usage_mask,
    } = policy;

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
                key_material: KeyMaterial::ByteString(private_key_der.clone().into()),
                attributes: Some(Box::new(priv_attrs)),
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
                key_material: KeyMaterial::ByteString(cosmian_kmip::SensitiveBytes::from(
                    public_key_der.to_vec(),
                )),
                attributes: Some(Box::new(pub_attrs)),
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

    use super::*;

    // ── Safe serialization round-trip ───────────────────────────────────────

    /// Verify that safe key serialization (`private_key_to_pkcs8` / `public_key_to_der`)
    /// works and does not panic or leak when called with a freshly generated ML-DSA key.
    #[test]
    fn safe_serialization_roundtrip_does_not_panic() {
        let (priv_der, pub_der, _bits) = pqc_keygen("ML-DSA-44", None, None).expect("keygen");
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
        let (_, pub_raw, _) = pqc_keygen_raw("X25519MLKEM768", None, None).expect("keygen");
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
        let (priv_raw, _, _) = pqc_keygen_raw("X25519MLKEM768", None, None).expect("keygen");
        let result = load_raw_private_key("X448MLKEM1024", &priv_raw);
        assert!(
            result.is_err(),
            "key for wrong algorithm must return Err, not panic"
        );
    }

    // ── PKCS8/SPKI → Raw conversion round-trip ─────────────────────────────

    #[test]
    fn pkcs8_to_raw_private_roundtrip_ml_dsa_44() {
        let (pkcs8_der, _, _) = pqc_keygen("ML-DSA-44", None, None).expect("keygen");
        let raw = pqc_private_key_pkcs8_to_raw(&pkcs8_der).expect("pkcs8 to raw");
        assert!(!raw.is_empty(), "raw private key must not be empty");
        let pkey = PKey::private_key_from_der(&pkcs8_der).expect("reload der");
        let raw2 = pkey.raw_private_key().expect("re-extract");
        assert_eq!(raw, raw2, "round-trip raw private key must match");
    }

    #[test]
    fn spki_to_raw_public_roundtrip_ml_dsa_44() {
        let (_, spki_der, _) = pqc_keygen("ML-DSA-44", None, None).expect("keygen");
        let raw = pqc_public_key_spki_to_raw(&spki_der).expect("spki to raw");
        assert!(!raw.is_empty(), "raw public key must not be empty");
        let pkey = PKey::public_key_from_der(&spki_der).expect("reload der");
        let raw2 = pkey.raw_public_key().expect("re-extract");
        assert_eq!(raw, raw2, "round-trip raw public key must match");
    }

    #[test]
    fn pkcs8_to_raw_private_roundtrip_ml_kem_768() {
        let (pkcs8_der, _, _) = pqc_keygen("ML-KEM-768", None, None).expect("keygen");
        let raw = pqc_private_key_pkcs8_to_raw(&pkcs8_der).expect("pkcs8 to raw");
        assert!(!raw.is_empty(), "raw private key must not be empty");
        let pkey = PKey::private_key_from_der(&pkcs8_der).expect("reload der");
        let raw2 = pkey.raw_private_key().expect("re-extract");
        assert_eq!(raw, raw2, "round-trip raw private key must match");
    }

    #[test]
    fn spki_to_raw_public_roundtrip_ml_kem_768() {
        let (_, spki_der, _) = pqc_keygen("ML-KEM-768", None, None).expect("keygen");
        let raw = pqc_public_key_spki_to_raw(&spki_der).expect("spki to raw");
        assert!(!raw.is_empty(), "raw public key must not be empty");
        let pkey = PKey::public_key_from_der(&spki_der).expect("reload der");
        let raw2 = pkey.raw_public_key().expect("re-extract");
        assert_eq!(raw, raw2, "round-trip raw public key must match");
    }

    #[test]
    fn pkcs8_to_raw_private_roundtrip_slh_dsa_sha2_128s() {
        let (pkcs8_der, _, _) = pqc_keygen("SLH-DSA-SHA2-128s", None, None).expect("keygen");
        let raw = pqc_private_key_pkcs8_to_raw(&pkcs8_der).expect("pkcs8 to raw");
        assert!(!raw.is_empty(), "raw private key must not be empty");
        let pkey = PKey::private_key_from_der(&pkcs8_der).expect("reload der");
        let raw2 = pkey.raw_private_key().expect("re-extract");
        assert_eq!(raw, raw2, "round-trip raw private key must match");
    }

    #[test]
    fn spki_to_raw_public_roundtrip_slh_dsa_sha2_128s() {
        let (_, spki_der, _) = pqc_keygen("SLH-DSA-SHA2-128s", None, None).expect("keygen");
        let raw = pqc_public_key_spki_to_raw(&spki_der).expect("spki to raw");
        assert!(!raw.is_empty(), "raw public key must not be empty");
        let pkey = PKey::public_key_from_der(&spki_der).expect("reload der");
        let raw2 = pkey.raw_public_key().expect("re-extract");
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

    // ── PQC seed generation for NIST SP 800-133r3 compliance ───────────────

    #[test]
    fn generate_pqc_seed_produces_entropy() {
        let rng = super::super::KmsRng::new();

        // Generate a 32-byte seed (typical for ML-KEM per FIPS 203)
        let seed_32 = generate_pqc_seed(&rng, 32).expect("seed generation");
        assert_eq!(seed_32.len(), 32, "seed must be exactly 32 bytes");
        assert!(
            !seed_32.iter().all(|&b| b == 0),
            "seed must not be all zeros"
        );

        // Generate a 64-byte seed (alternative for ML-DSA per FIPS 204)
        let seed_64 = generate_pqc_seed(&rng, 64).expect("seed generation");
        assert_eq!(seed_64.len(), 64, "seed must be exactly 64 bytes");
        assert!(
            !seed_64.iter().all(|&b| b == 0),
            "seed must not be all zeros"
        );

        // Verify that two consecutive seeds are different (entropy is not deterministic)
        let seed_a = generate_pqc_seed(&rng, 32).expect("seed a");
        let seed_b = generate_pqc_seed(&rng, 32).expect("seed b");
        assert_ne!(
            seed_a.as_slice(),
            seed_b.as_slice(),
            "consecutive seeds must differ"
        );
    }

    #[test]
    fn generate_pqc_seed_zeroizes_on_drop() {
        let rng = super::super::KmsRng::new();

        // This test verifies that Zeroizing works by creating a seed and
        // allowing it to be dropped. The actual memory zeroization is
        // checked by tools like valgrind in CI, but we verify the type exists.
        let seed = generate_pqc_seed(&rng, 32).expect("seed generation");
        assert_eq!(seed.len(), 32);
        // seed is dropped here; Zeroizing::drop() zero-fills the memory
    }

    // ── Deterministic seeded PQC key generation tests ────────────────────────

    #[test]
    fn pqc_keygen_seeded_is_deterministic_ml_kem() {
        let seed = [0x42_u8; 64];

        let pkey1 = pqc_keygen_seeded(KeyType::ML_KEM_768, &seed, None).expect("seeded keygen 1");
        let pkey2 = pqc_keygen_seeded(KeyType::ML_KEM_768, &seed, None).expect("seeded keygen 2");
        let priv1 = pkey1.private_key_to_pkcs8().expect("priv1");
        let priv2 = pkey2.private_key_to_pkcs8().expect("priv2");
        assert_eq!(
            priv1, priv2,
            "same seed must produce identical ML-KEM private key"
        );

        let pub1 = pkey1.public_key_to_der().expect("pub1");
        let pub2 = pkey2.public_key_to_der().expect("pub2");
        assert_eq!(
            pub1, pub2,
            "same seed must produce identical ML-KEM public key"
        );
    }

    #[test]
    fn pqc_keygen_seeded_is_deterministic_ml_dsa() {
        let seed = [0x55_u8; 32];

        let pkey1 = pqc_keygen_seeded(KeyType::ML_DSA_65, &seed, None).expect("seeded keygen 1");
        let pkey2 = pqc_keygen_seeded(KeyType::ML_DSA_65, &seed, None).expect("seeded keygen 2");
        let priv1 = pkey1.private_key_to_pkcs8().expect("priv1");
        let priv2 = pkey2.private_key_to_pkcs8().expect("priv2");
        assert_eq!(
            priv1, priv2,
            "same seed must produce identical ML-DSA private key"
        );

        let pub1 = pkey1.public_key_to_der().expect("pub1");
        let pub2 = pkey2.public_key_to_der().expect("pub2");
        assert_eq!(
            pub1, pub2,
            "same seed must produce identical ML-DSA public key"
        );
    }

    #[test]
    fn pqc_keygen_draws_seed_from_kms_rng_for_ml_kem_and_ml_dsa() {
        let rng = super::super::KmsRng::new();

        // Two key generations with RNG must yield distinct keys
        let (priv1, _, _) = pqc_keygen("ML-KEM-768", Some(&rng), None).expect("keygen 1");
        let (priv2, _, _) = pqc_keygen("ML-KEM-768", Some(&rng), None).expect("keygen 2");
        assert_ne!(
            priv1.as_slice(),
            priv2.as_slice(),
            "randomly seeded keys must differ"
        );

        let (priv_dsa1, _, _) = pqc_keygen("ML-DSA-65", Some(&rng), None).expect("dsa 1");
        let (priv_dsa2, _, _) = pqc_keygen("ML-DSA-65", Some(&rng), None).expect("dsa 2");
        assert_ne!(
            priv_dsa1.as_slice(),
            priv_dsa2.as_slice(),
            "randomly seeded keys must differ"
        );
    }

    #[test]
    fn pqc_keygen_ignores_rng_for_slh_dsa() {
        let rng = super::super::KmsRng::new();

        // Calling with Some(&rng) for SLH-DSA should succeed (generating unseeded)
        let (priv_slh, pub_slh, bits) =
            pqc_keygen("SLH-DSA-SHA2-128s", Some(&rng), None).expect("slh-dsa keygen");
        assert!(!priv_slh.is_empty());
        assert_ne!(pub_slh.len(), 0);
        assert!(bits > 0);
    }

    // ── Propquery tests (SP 800-227 / RS4 readiness) ─────────────────────────

    #[test]
    fn pqc_keygen_with_propquery_default_succeeds() {
        // Passing standard default provider properties explicitly should succeed
        let (priv_kem, pub_kem, bits) = pqc_keygen("ML-KEM-768", None, Some("provider=default"))
            .expect("default propquery kem");
        assert!(!priv_kem.is_empty());
        assert_ne!(pub_kem.len(), 0);
        assert!(bits > 0);

        let (priv_dsa, pub_dsa, _) =
            pqc_keygen("ML-DSA-65", None, Some("provider=default")).expect("default propquery dsa");
        assert!(!priv_dsa.is_empty());
        assert_ne!(pub_dsa.len(), 0);
    }

    #[test]
    fn pqc_keygen_with_nonexistent_propquery_fails() {
        // A property query requiring a non-existent provider property must fail cleanly
        let result = pqc_keygen("ML-KEM-768", None, Some("nonexistent_property=yes"));
        assert!(
            result.is_err(),
            "keygen with impossible propquery must return Err"
        );
    }

    #[test]
    fn pqc_keygen_raw_with_propquery_succeeds() {
        let (priv_raw, pub_raw, bits) =
            pqc_keygen_raw("X25519MLKEM768", None, Some("provider=default"))
                .expect("raw default propquery");
        assert!(!priv_raw.is_empty());
        assert_ne!(pub_raw.len(), 0);
        assert!(bits > 0);

        let result = pqc_keygen_raw("X25519MLKEM768", None, Some("nonexistent_property=yes"));
        assert!(
            result.is_err(),
            "raw keygen with impossible propquery must return Err"
        );
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn pqc_keygen_seeded_with_propquery_fips_rejects_without_fips_provider() {
        // When "fips=yes" is requested but the FIPS provider is not loaded, key generation
        // must return an Err.
        let result = pqc_keygen_seeded(KeyType::ML_KEM_768, &[0x77_u8; 64], Some(c"fips=yes"));
        assert!(
            result.is_err(),
            "requesting fips=yes without loaded FIPS provider must fail"
        );
    }

    // ── Official known-answer vectors ────────────────────────────────────────

    /// Seeded keygen must reproduce the ACVP raw public key and the expanded private key.
    fn check_keygen_official_vectors(vectors: Vec<crate::kat_vectors::PqcKeygenVector>) {
        for v in vectors {
            let (key_type, _) = seeded_key_type(v.parameter_set.as_str()).unwrap();
            let key = pqc_keygen_seeded(key_type, &v.seed, None).unwrap();
            assert_eq!(
                key.raw_public_key().unwrap(),
                v.pk,
                "{} ({}) pk",
                v.id,
                v.source
            );
            assert_eq!(
                key.raw_private_key().unwrap(),
                v.sk,
                "{} ({}) sk",
                v.id,
                v.source
            );
        }
    }

    #[test]
    fn test_ml_kem_keygen_official_vectors() {
        check_keygen_official_vectors(crate::kat_vectors::ml_kem_keygen_vectors().unwrap());
    }

    #[test]
    fn test_ml_dsa_keygen_official_vectors() {
        check_keygen_official_vectors(crate::kat_vectors::ml_dsa_keygen_vectors().unwrap());
    }

    #[test]
    fn test_ml_kem_decaps_official_vectors() {
        for v in crate::kat_vectors::ml_kem_decaps_vectors().unwrap() {
            let (key_type, _) = seeded_key_type(v.parameter_set.as_str()).unwrap();
            let key = pqc_keygen_seeded(key_type, &v.seed, None).unwrap();
            let decapsulated =
                ml_kem::ml_kem_decapsulate(&key.private_key_to_pkcs8().unwrap(), &v.c);
            if v.valid {
                assert_eq!(decapsulated.unwrap(), v.k, "{} ({})", v.id, v.source);
            } else {
                decapsulated.unwrap_err();
            }
        }
    }

    /// `ml_dsa_verify` is also the SLH-DSA verifier (OpenSSL picks the algorithm from the key).
    fn check_verify_official_vectors(groups: Vec<crate::kat_vectors::PqcVerifyGroup>) {
        for g in groups {
            let key = PKey::public_key_from_der(&g.public_key_spki).unwrap();
            for t in g.tests {
                let verified = ml_dsa::ml_dsa_verify(&key, &t.msg, &t.sig);
                // An Err on an invalid record counts as rejected.
                if t.valid {
                    assert!(verified.unwrap(), "{} ({})", t.id, g.source);
                } else {
                    assert!(!verified.unwrap_or(false), "{} ({})", t.id, g.source);
                }
            }
        }
    }

    #[test]
    fn test_ml_dsa_verify_official_vectors() {
        check_verify_official_vectors(crate::kat_vectors::ml_dsa_verify_groups().unwrap());
    }

    #[test]
    fn test_slh_dsa_verify_official_vectors() {
        check_verify_official_vectors(crate::kat_vectors::slh_dsa_verify_groups().unwrap());
    }
}
