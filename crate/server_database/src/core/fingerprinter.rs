//! TTLV-based object fingerprinting shared by [`ObjectCache`] and [`UnwrappedCache`].
//!
//! Each cache instance embeds a [`Fingerprinter`] with its own `RandomState`
//! seed so fingerprints are never transferable between cache instances — an
//! attacker cannot craft a wrapped-key blob whose fingerprint equals the one
//! stored in a different cache.
//!
//! [`ObjectCache`]: super::object_cache::ObjectCache
//! [`UnwrappedCache`]: super::unwrapped_cache::UnwrappedCache
use std::{
    hash::{BuildHasher, Hasher, RandomState},
    io,
};

use cosmian_kmip::kmip_2_1::kmip_objects::Object;

use crate::error::DbResult;

/// Per-instance object fingerprinter.
///
/// Streams JSON representation of [`Object`] directly into a hasher backed by a
/// per-instance random seed. The seed is refreshed on every server restart so
/// fingerprints stored in memory in one process are never valid in another.
/// Bypasses the intermediate TTLV tree and intermediate serialization buffer allocations.
pub(crate) struct Fingerprinter {
    seed: RandomState,
}

struct HasherWriter<H> {
    hasher: H,
}

impl<H: Hasher> io::Write for HasherWriter<H> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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
    /// Streams `object` serialized as JSON directly into the hasher, avoiding
    /// intermediate TTLV tree allocations and temporary buffer copies.
    pub(crate) fn fingerprint(&self, object: &Object) -> DbResult<u64> {
        let mut writer = HasherWriter {
            hasher: self.seed.build_hasher(),
        };
        serde_json::to_writer(&mut writer, object)?;
        Ok(writer.hasher.finish())
    }
}

impl Default for Fingerprinter {
    fn default() -> Self {
        Self::new()
    }
}
