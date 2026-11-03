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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn test_hasher_writer_chunked_vs_contiguous() {
        use std::collections::hash_map::DefaultHasher;

        let payload = b"Hello, world! This is a test of HasherWriter streaming.";
        let mut h1 = DefaultHasher::new();
        h1.write(payload);
        let digest1 = h1.finish();

        let mut h2 = DefaultHasher::new();
        let mut writer = HasherWriter { hasher: &mut h2 };
        for chunk in payload.chunks(7) {
            writer.write_all(chunk).unwrap();
        }
        let digest2 = h2.finish();

        assert_eq!(digest1, digest2);
    }
}
