//! TTLV-based object fingerprinting shared by [`ObjectCache`] and [`UnwrappedCache`].
//!
//! Each cache instance embeds a [`Fingerprinter`] with its own `RandomState`
//! seed so fingerprints are never transferable between cache instances — an
//! attacker cannot craft a wrapped-key blob whose fingerprint equals the one
//! stored in a different cache.
//!
//! [`ObjectCache`]: super::object_cache::ObjectCache
//! [`UnwrappedCache`]: super::unwrapped_cache::UnwrappedCache

use std::hash::{BuildHasher, RandomState};

use cosmian_kmip::{
    KmipError,
    kmip_2_1::kmip_objects::Object,
    ttlv::{KmipFlavor, to_ttlv},
};
use zeroize::Zeroizing;

use crate::{DbError, error::DbResult};

/// Per-instance TTLV fingerprinter.
///
/// Serializes an [`Object`] to canonical TTLV bytes and hashes the result
/// with a per-instance random seed.  The seed is refreshed on every server
/// restart so fingerprints stored in one process are invalid in the next.
pub(crate) struct Fingerprinter {
    seed: RandomState,
}

impl Fingerprinter {
    /// Create a new fingerprinter with a fresh random seed.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            seed: RandomState::new(),
        }
    }

    /// Compute a fingerprint of `object`.
    ///
    /// Serializes `object` to TTLV v2 bytes and hashes the result with the
    /// instance seed.  The hash covers every object field, not only the raw
    /// key material, so attribute mutations are also detected.
    pub(crate) fn fingerprint(&self, object: &Object) -> DbResult<u64> {
        // Wrap the serialized bytes in a Zeroizing buffer so that any key
        // material captured during TTLV serialization is wiped from memory
        // as soon as this function returns.
        let bytes = Zeroizing::new(
            to_ttlv(object)
                .and_then(|ttlv| ttlv.to_bytes(KmipFlavor::Kmip2))
                .map_err(KmipError::from)
                .map_err(DbError::from)?,
        );
        Ok(self.seed.hash_one(bytes.as_slice()))
    }
}

impl Default for Fingerprinter {
    fn default() -> Self {
        Self::new()
    }
}
