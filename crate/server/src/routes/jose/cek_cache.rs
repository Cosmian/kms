//! CEK (Content Encryption Key) caching for the JOSE RSA-OAEP path.
//!
//! RFC 7516 §5.1 mandates a fresh random CEK for each encryption and wraps it with
//! the recipient's RSA public key (`encrypted_key`). Repeated decryptions of the
//! same JWE token perform this RSA-OAEP unwrap on every call. These helpers insert
//! the CEK into the server's `UnwrappedCache` after a successful unwrap so
//! subsequent requests for the same token skip the RSA private-key operation.
//!
//! ## Cache key
//!
//! `"jose_cek_{sha256_hex_of_encrypted_key_bytes}"` — unique per JWE token because
//! RSA-OAEP encryption is randomized (different nonce each run). The SHA-256 hash
//! keeps the key compact regardless of RSA key size (RSA-4096 produces a 512-byte
//! `encrypted_key`; the hash is always 32 bytes / 64 hex chars).
//!
//! ## Fingerprint source
//!
//! The KMIP `Object` of the RSA key used for wrapping/unwrapping is passed as
//! `kmip_key_object` and stored as the fingerprint source. If the key is re-imported
//! or re-wrapped the fingerprint changes and the stale cache entry is rejected by
//! `UnwrappedCache::peek()`.
//!
//! ## RFC 7516 §11.5 — implicit rejection
//!
//! Only successfully unwrapped CEKs are inserted. The random substitute CEK
//! generated on OAEP failure is **never** cached — it is ephemeral, per-request,
//! and must not be re-used.
//!
//! ## `dir` mode
//!
//! The `dir` path delegates directly to the KMIP `Encrypt`/`Decrypt` pipeline,
//! which already passes through `UnwrappedCache` via `get_unwrapped()`. No
//! additional caching is required for that path.

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::VENDOR_ID_COSMIAN,
    kmip_attributes::Attributes,
    kmip_objects::{Object, SymmetricKey},
    kmip_types::CryptographicAlgorithm,
    requests::create_symmetric_key_kmip_object,
};
use cosmian_logger::{debug, warn};
use zeroize::Zeroizing;

use crate::core::KMS;

/// Build the cache UID for a JOSE CEK from the raw `encrypted_key` bytes.
///
/// Uses SHA-256 so the map key is compact: 64 hex chars regardless of RSA size.
fn cek_cache_uid(encrypted_key_bytes: &[u8]) -> String {
    format!(
        "jose_cek_{}",
        hex::encode(openssl::sha::sha256(encrypted_key_bytes))
    )
}

/// Wrap raw CEK bytes in a minimal [`Object::SymmetricKey`] for storage in
/// `UnwrappedCache`.
///
/// Returns `None` and logs a warning on construction failure (should never
/// happen for well-formed AES-128/192/256 keys).
fn cek_to_kmip_object(cek: &[u8]) -> Option<Object> {
    // Derive bit length from byte length. Only standard AES sizes are valid.
    let cryptographic_length: i32 = match cek.len() {
        16 => 128,
        24 => 192,
        32 => 256,
        other => {
            warn!(
                "JOSE CEK cache: unexpected CEK length {other} bytes — not an AES-128/192/256 key"
            );
            return None;
        }
    };
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(cryptographic_length),
        ..Attributes::default()
    };
    match create_symmetric_key_kmip_object(VENDOR_ID_COSMIAN, cek, &attributes) {
        Ok(obj) => Some(obj),
        Err(e) => {
            warn!("JOSE CEK cache: failed to construct KMIP SymmetricKey: {e}");
            None
        }
    }
}

/// Extract the raw key bytes from a cached [`Object::SymmetricKey`].
///
/// Returns `None` if the object is not a symmetric key or if the key material
/// cannot be extracted (e.g., wrapped object unexpectedly stored).
fn kmip_object_to_cek(obj: Object) -> Option<Zeroizing<Vec<u8>>> {
    match obj {
        Object::SymmetricKey(SymmetricKey { key_block }) => key_block.key_bytes().ok(),
        _ => None,
    }
}

/// Look up a cached CEK for the given JWE `encrypted_key` ciphertext.
///
/// Returns `Some(cek_bytes)` on a cache hit, `None` on a miss or any error.
/// Errors are logged at `WARN` level and treated as cache misses — the cache
/// is best-effort and a miss is always safe.
///
/// `kmip_key_object` is the RSA key KMIP object used for fingerprint validation:
/// if the key has changed since the entry was inserted, `peek()` returns `None`.
pub(super) async fn peek_cek(
    kms: &KMS,
    encrypted_key_bytes: &[u8],
    kmip_key_object: &Object,
) -> Option<Zeroizing<Vec<u8>>> {
    let uid = cek_cache_uid(encrypted_key_bytes);
    let cached_obj = match kms
        .database
        .unwrapped_cache()
        .peek(&uid, kmip_key_object)
        .await
    {
        Ok(Some(obj)) => obj,
        Ok(None) => return None,
        Err(e) => {
            warn!("JOSE CEK cache peek error for {uid}: {e}");
            return None;
        }
    };
    let cek = kmip_object_to_cek(cached_obj);
    if cek.is_some() {
        debug!("JOSE CEK cache hit for {uid}");
    } else {
        warn!("JOSE CEK cache: unexpected object type for {uid}");
    }
    cek
}

/// Insert a successfully unwrapped CEK into the `UnwrappedCache`.
///
/// `kmip_key_object` is the RSA key KMIP object used as the fingerprint source.
/// Errors are logged at `WARN` level and silently ignored — the cache is
/// best-effort and a failed insert is not a correctness issue.
///
/// # RFC 7516 §11.5 — caller responsibility
///
/// Only call this function with a **genuine** unwrapped CEK. The random
/// substitute CEK used for implicit rejection must never be passed here.
pub(super) async fn insert_cek(
    kms: &KMS,
    encrypted_key_bytes: &[u8],
    kmip_key_object: &Object,
    cek: &[u8],
) {
    let uid = cek_cache_uid(encrypted_key_bytes);
    let Some(cek_obj) = cek_to_kmip_object(cek) else {
        return; // warning already emitted by cek_to_kmip_object
    };
    match kms
        .database
        .unwrapped_cache()
        .insert(uid.clone(), kmip_key_object, cek_obj)
        .await
    {
        Ok(()) => debug!("JOSE CEK cached for {uid}"),
        Err(e) => warn!("JOSE CEK cache insert error for {uid}: {e}"),
    }
}
