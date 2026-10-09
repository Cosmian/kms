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
use openssl::pkey::{PKey, Private};
use zeroize::Zeroizing;

use crate::{
    crypto::{KeyPair, KmsRng},
    error::CryptoError,
};

/// RAII guard for an owned `EVP_PKEY` pointer — calls `EVP_PKEY_free` on drop.
///
/// Used for raw key loading and hybrid KEM operations where safe `PKey` wrappers
/// are not yet available (tracking Issue #1251).
pub(crate) struct PKeyGuard(pub(crate) *mut openssl_sys::EVP_PKEY);

impl PKeyGuard {
    pub(crate) const fn as_ptr(&self) -> *mut openssl_sys::EVP_PKEY {
        self.0
    }
}

impl Drop for PKeyGuard {
    #[expect(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid EVP_PKEY exclusively owned by this guard.
        unsafe {
            openssl_sys::EVP_PKEY_free(self.0);
        }
    }
}

/// RAII guard for an owned `EVP_PKEY_CTX` pointer — calls `EVP_PKEY_CTX_free` on drop.
///
/// Ensures context is freed even on error or early return during key generation.
struct PKeyCtxGuard(*mut openssl_sys::EVP_PKEY_CTX);

impl Drop for PKeyCtxGuard {
    #[expect(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid EVP_PKEY_CTX exclusively owned by this guard.
        unsafe {
            openssl_sys::EVP_PKEY_CTX_free(self.0);
        }
    }
}

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

/// Generate a seeded PQC key using `EVP_PKEY_CTX` with the `"seed"` parameter.
///
/// Used for ML-KEM (64-byte seed) and ML-DSA (32-byte seed) when a `KmsRng` is provided.
///
/// Upstream tracking: `rust-openssl` lacks safe bindings for `EVP_PKEY_CTX_new_from_name`,
/// `EVP_PKEY_keygen_init`, `EVP_PKEY_CTX_set_params`, and `EVP_PKEY_generate` (Issue #1251,
/// upstream PRs #2649, #2646, #2636, #2611).
#[expect(unsafe_code)]
fn pqc_keygen_seeded(
    name: &CString,
    seed: &[u8],
    propquery: Option<&CString>,
) -> Result<PKey<Private>, CryptoError> {
    // SAFETY: every pointer passed to OpenSSL (`name`, `propquery`, `seed`, params, `indicator`)
    // is valid for the duration of its call. `ctx` is freed by `PKeyCtxGuard`; `raw_pkey` is
    // either freed explicitly on indicator failure or ownership moves into `PKey`.
    unsafe {
        let propq_ptr = propquery.map_or(ptr::null(), |pq| pq.as_ptr());
        let ctx = EVP_PKEY_CTX_new_from_name(ptr::null_mut(), name.as_ptr(), propq_ptr);
        if ctx.is_null() {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_CTX_new_from_name failed for {name:?}: {}",
                openssl::error::ErrorStack::get()
            )));
        }
        let _ctx_guard = PKeyCtxGuard(ctx);

        if EVP_PKEY_keygen_init(ctx) <= 0 {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_keygen_init failed for {name:?}: {}",
                openssl::error::ErrorStack::get()
            )));
        }

        // Construct OSSL_PARAM array: [ {"seed", OSSL_PARAM_OCTET_STRING, seed.as_ptr(), seed.len()}, END ]
        // OSSL_PARAM_OCTET_STRING is 5, OSSL_PARAM_UNMODIFIED is (size_t)-1
        let params = [
            openssl_sys::OSSL_PARAM {
                key: c"seed".as_ptr(),
                data_type: 5, // OSSL_PARAM_OCTET_STRING
                data: seed.as_ptr().cast_mut().cast::<std::ffi::c_void>(),
                data_size: seed.len(),
                return_size: usize::MAX, // OSSL_PARAM_UNMODIFIED
            },
            openssl_sys::OSSL_PARAM {
                key: ptr::null(),
                data_type: 0,
                data: ptr::null_mut(),
                data_size: 0,
                return_size: 0,
            },
        ];

        if EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) <= 0 {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_CTX_set_params (seed) failed for {name:?}: {}",
                openssl::error::ErrorStack::get()
            )));
        }

        let mut raw_pkey: *mut openssl_sys::EVP_PKEY = ptr::null_mut();
        if EVP_PKEY_generate(ctx, &raw mut raw_pkey) <= 0 || raw_pkey.is_null() {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_generate failed for {name:?}: {}",
                openssl::error::ErrorStack::get()
            )));
        }

        // If FIPS provider was explicitly requested via propquery ("fips=yes"),
        // verify that the operation was approved by checking the FIPS indicator.
        if let Some(pq) = propquery {
            let pq_bytes = pq.as_bytes();
            if pq_bytes
                .split(|&b| b == b',' || b == b' ')
                .any(|part| part == b"fips=yes")
            {
                let mut indicator: std::ffi::c_int = 0;
                let get_params = [
                    openssl_sys::OSSL_PARAM {
                        key: c"fips-indicator".as_ptr(),
                        data_type: 1, // OSSL_PARAM_INTEGER
                        data: (&raw mut indicator).cast::<std::ffi::c_void>(),
                        data_size: std::mem::size_of::<std::ffi::c_int>(),
                        return_size: usize::MAX,
                    },
                    openssl_sys::OSSL_PARAM {
                        key: ptr::null(),
                        data_type: 0,
                        data: ptr::null_mut(),
                        data_size: 0,
                        return_size: 0,
                    },
                ];
                if EVP_PKEY_CTX_get_params(ctx, get_params.as_ptr()) <= 0 || indicator != 1 {
                    openssl_sys::EVP_PKEY_free(raw_pkey);
                    return Err(CryptoError::Default(format!(
                        "OpenSSL FIPS indicator check failed for {name:?}: key generation was not approved"
                    )));
                }
            }
        }

        Ok(PKey::from_ptr(raw_pkey))
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

/// Generate a PQC key pair using OpenSSL `EVP_PKEY_Q_keygen` (unseeded) or `pqc_keygen_seeded`.
///
/// When `rng` is `Some`:
/// - ML-KEM draws a 64-byte seed from `KmsRng` (FIPS 203 §7.1 / OpenSSL `ml_kem_kmgmt.c`).
/// - ML-DSA draws a 32-byte seed from `KmsRng` (FIPS 204 §6.1 / OpenSSL `ml_dsa_kmgmt.c`).
/// - SLH-DSA uses `EVP_PKEY_Q_keygen` unseeded because OpenSSL's SLH-DSA seed parameter is
///   documented as testing-only (`EVP_PKEY-SLH-DSA(7)`).
///
/// When `rng` is `None`, OpenSSL's internal DRBG generates the key material directly via
/// `EVP_PKEY_Q_keygen`.
///
/// Upstream tracking: `EVP_PKEY_Q_keygen` is used until safe bindings land in `rust-openssl`
/// (Issue #1251, upstream PRs #2649, #2646, #2636, #2611).
#[expect(unsafe_code)]
fn pqc_keygen(
    algorithm_name: &str,
    rng: Option<&KmsRng>,
    propquery: Option<&str>,
) -> Result<PqcKeygenResult, CryptoError> {
    let name = CString::new(algorithm_name)
        .map_err(|e| CryptoError::Default(format!("invalid algorithm name: {e}")))?;
    let propq_c = parse_propquery(propquery)?;
    let propq_ptr = propq_c.as_ref().map_or(ptr::null(), |pq| pq.as_ptr());

    let safe_pkey = if let Some(rng) = rng {
        if algorithm_name.starts_with("ML-KEM-") {
            let seed = generate_pqc_seed(rng, 64)?;
            pqc_keygen_seeded(&name, &seed, propq_c.as_ref())?
        } else if algorithm_name.starts_with("ML-DSA-") {
            let seed = generate_pqc_seed(rng, 32)?;
            pqc_keygen_seeded(&name, &seed, propq_c.as_ref())?
        } else {
            // SLH-DSA seed param is testing-only per EVP_PKEY-SLH-DSA(7); generate unseeded.
            // SAFETY: `name` and `propq_c` (when `Some`) are valid NUL-terminated CStrings that
            // outlive the call; the returned non-null key is owned by `PKey`.
            unsafe {
                let raw = openssl_sys::EVP_PKEY_Q_keygen(ptr::null_mut(), propq_ptr, name.as_ptr());
                if raw.is_null() {
                    return Err(CryptoError::Default(format!(
                        "EVP_PKEY_Q_keygen failed for {algorithm_name}: {}",
                        openssl::error::ErrorStack::get()
                    )));
                }
                PKey::from_ptr(raw)
            }
        }
    } else {
        // SAFETY: same as the SLH-DSA call above: valid CString pointers outliving the call.
        unsafe {
            let raw = openssl_sys::EVP_PKEY_Q_keygen(ptr::null_mut(), propq_ptr, name.as_ptr());
            if raw.is_null() {
                return Err(CryptoError::Default(format!(
                    "EVP_PKEY_Q_keygen failed for {algorithm_name}: {}",
                    openssl::error::ErrorStack::get()
                )));
            }
            PKey::from_ptr(raw)
        }
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
/// `rng` is unused for hybrid KEMs: OpenSSL 3.6.2 generates composite keys atomically
/// without exposing a seed parameter (see `mlx_kmgmt.c`).
///
/// Upstream tracking: `EVP_PKEY_Q_keygen` is used until safe bindings land in `rust-openssl`
/// (Issue #1251, upstream PRs #2649, #2646, #2636, #2611).
#[expect(unsafe_code)]
fn pqc_keygen_raw(
    algorithm_name: &str,
    rng: Option<&KmsRng>,
    propquery: Option<&str>,
) -> Result<PqcKeygenResult, CryptoError> {
    let name = CString::new(algorithm_name)
        .map_err(|e| CryptoError::Default(format!("invalid algorithm name: {e}")))?;
    let propq_c = parse_propquery(propquery)?;
    let propq_ptr = propq_c.as_ref().map_or(ptr::null(), |pq| pq.as_ptr());

    let _ = rng;

    // SAFETY: `name` and `propq_c` (when `Some`) are valid NUL-terminated CStrings that outlive
    // the call; a null propq selects OpenSSL defaults. The returned key is owned by `PKey`.
    unsafe {
        let raw = openssl_sys::EVP_PKEY_Q_keygen(ptr::null_mut(), propq_ptr, name.as_ptr());
        if raw.is_null() {
            return Err(CryptoError::Default(format!(
                "EVP_PKEY_Q_keygen failed for {algorithm_name}: {}",
                openssl::error::ErrorStack::get()
            )));
        }
        let safe_pkey: PKey<Private> = PKey::from_ptr(raw);
        let bits = safe_pkey.bits();
        let private_raw = safe_pkey
            .raw_private_key()
            .map_err(|e| CryptoError::Default(format!("raw_private_key failed: {e}")))?;
        let public_raw = safe_pkey
            .raw_public_key()
            .map_err(|e| CryptoError::Default(format!("raw_public_key failed: {e}")))?;

        Ok((Zeroizing::from(private_raw), public_raw, bits))
    }
}

// FFI declarations for OpenSSL 3.x keygen and raw key functions
// (not available in openssl-sys crate, tracking Issue #1251)
#[expect(unsafe_code)]
unsafe extern "C" {
    fn EVP_PKEY_CTX_new_from_name(
        libctx: *mut openssl_sys::OSSL_LIB_CTX,
        name: *const std::ffi::c_char,
        propquery: *const std::ffi::c_char,
    ) -> *mut openssl_sys::EVP_PKEY_CTX;

    fn EVP_PKEY_keygen_init(ctx: *mut openssl_sys::EVP_PKEY_CTX) -> std::ffi::c_int;

    fn EVP_PKEY_CTX_set_params(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        params: *const openssl_sys::OSSL_PARAM,
    ) -> std::ffi::c_int;

    fn EVP_PKEY_CTX_get_params(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        params: *const openssl_sys::OSSL_PARAM,
    ) -> std::ffi::c_int;

    fn EVP_PKEY_generate(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        ppkey: *mut *mut openssl_sys::EVP_PKEY,
    ) -> std::ffi::c_int;
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
///
/// Upstream tracking: `openssl::pkey::PKey::public_key_from_raw_bytes_ex` requires a `KeyType`
/// enum which does not support hybrid KEMs (Issue #1251).
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
    // SAFETY: `name` is a valid NUL-terminated CString and `raw_bytes` is non-empty (checked
    // above); a null libctx/propq selects OpenSSL defaults. Returned pointer is owned by `PKeyGuard`.
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
///
/// Upstream tracking: `openssl::pkey::PKey::private_key_from_raw_bytes_ex` requires a `KeyType`
/// enum which does not support hybrid KEMs (Issue #1251).
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
    // SAFETY: `name` is a valid NUL-terminated CString and `raw_bytes` is non-empty (checked
    // above); a null libctx/propq selects OpenSSL defaults. Returned pointer is owned by `PKeyGuard`.
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
        let name = CString::new("ML-KEM-768").expect("name");
        let seed = [0x42_u8; 64];

        let pkey1 = pqc_keygen_seeded(&name, &seed, None).expect("seeded keygen 1");
        let pkey2 = pqc_keygen_seeded(&name, &seed, None).expect("seeded keygen 2");
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
        let name = CString::new("ML-DSA-65").expect("name");
        let seed = [0x55_u8; 32];

        let pkey1 = pqc_keygen_seeded(&name, &seed, None).expect("seeded keygen 1");
        let pkey2 = pqc_keygen_seeded(&name, &seed, None).expect("seeded keygen 2");
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
        assert!(!pub_slh.is_empty());
        assert!(bits > 0);
    }

    // ── Propquery and FIPS indicator tests (SP 800-227 / RS4 readiness) ─────

    #[test]
    fn pqc_keygen_with_propquery_default_succeeds() {
        // Passing standard default provider properties explicitly should succeed
        let (priv_kem, pub_kem, bits) = pqc_keygen("ML-KEM-768", None, Some("provider=default"))
            .expect("default propquery kem");
        assert!(!priv_kem.is_empty());
        assert!(!pub_kem.is_empty());
        assert!(bits > 0);

        let (priv_dsa, pub_dsa, _) =
            pqc_keygen("ML-DSA-65", None, Some("provider=default")).expect("default propquery dsa");
        assert!(!priv_dsa.is_empty());
        assert!(!pub_dsa.is_empty());
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
        assert!(!pub_raw.is_empty());
        assert!(bits > 0);

        let result = pqc_keygen_raw("X25519MLKEM768", None, Some("nonexistent_property=yes"));
        assert!(
            result.is_err(),
            "raw keygen with impossible propquery must return Err"
        );
    }

    #[test]
    fn pqc_keygen_seeded_with_propquery_fips_rejects_without_fips_provider() {
        // When "fips=yes" is requested but the FIPS provider is not active / does not provide
        // the algorithm with an approved indicator, key generation must return an Err.
        let name = CString::new("ML-KEM-768").expect("name");
        let seed = [0x77_u8; 64];
        let propq = CString::new("fips=yes").expect("propq");

        let result = pqc_keygen_seeded(&name, &seed, Some(&propq));
        assert!(
            result.is_err(),
            "requesting fips=yes without loaded FIPS provider must fail"
        );
    }
}
