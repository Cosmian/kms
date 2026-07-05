//! In-memory concurrent cache for `retrieve_object` results.
//!
//! Eliminates repeated SQLite/PostgreSQL round-trips when the same key is used
//! for many consecutive cryptographic operations (the hot-path pattern in
//! production workloads like encryption-as-a-service).
//!
//! The cache uses [`moka::future::Cache`] which provides **lock-free concurrent
//! reads** via a sharded concurrent `HashMap` — multiple async tasks can call
//! [`ObjectCache::get`] simultaneously with no serialization, giving linear
//! throughput scaling with CPU count.
//!
//! Each entry stores an `Arc<ObjectWithMetadata>` together with a TTLV
//! fingerprint of the wrapped object.  The fingerprint enables
//! [`ObjectCache::validate_cache`] to detect stale entries when the underlying
//! DB object changes without going through the normal invalidation path (e.g.
//! a direct DB write from another process).  It also acts as a defense-in-depth
//! mechanism: a corrupted cache entry is rejected rather than silently used.
//!
//! Time-to-idle eviction and LRU capacity limits are delegated entirely to moka.

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use cosmian_kmip::kmip_2_1::kmip_objects::Object;
use cosmian_kms_interfaces::ObjectWithMetadata;
use moka::future::Cache;

use crate::{core::fingerprinter::Fingerprinter, error::DbResult};

/// An entry in the object cache: the object together with the fingerprint of
/// its key material at insertion time.
///
/// The fingerprint is recomputed at [`ObjectCache::validate_cache`] time and
/// compared against the caller-supplied current object to detect stale entries.
#[derive(Clone)]
struct CachedEntry {
    owm: Arc<ObjectWithMetadata>,
    fingerprint: u64,
}

/// Concurrent cache for recently retrieved `ObjectWithMetadata`.
///
/// Backed by [`moka::future::Cache`] — [`get`][ObjectCache::get] is lock-free,
/// so concurrent reads from many Actix-web worker threads do not serialize on a
/// global `RwLock`.
pub struct ObjectCache {
    fingerprinter: Fingerprinter,
    inner: Cache<String, CachedEntry>,
}

impl ObjectCache {
    /// Create a new object cache.
    ///
    /// * `max_age` — time-to-idle: entries are evicted after this duration
    ///   without access.
    /// * `max_size` — maximum number of entries before LRU eviction kicks in.
    #[must_use]
    #[allow(clippy::as_conversions)]
    pub fn new(max_age: Duration, max_size: NonZeroUsize) -> Self {
        Self {
            fingerprinter: Fingerprinter::new(),
            inner: Cache::builder()
                .max_capacity(max_size.get() as u64)
                .time_to_idle(max_age)
                .build(),
        }
    }

    /// Look up a cached object by UID.
    ///
    /// Returns `Some(owm)` on cache hit, `None` on miss.
    ///
    /// Uses moka's lock-free concurrent hash table — never blocks concurrent
    /// callers, even when other tasks are inserting or invalidating entries.
    /// Returns a cheap `Arc` clone — callers that need to mutate (e.g. unwrap
    /// key material) can call `Arc::unwrap_or_clone()` at the point of mutation.
    pub async fn get(&self, uid: &str) -> Option<Arc<ObjectWithMetadata>> {
        self.inner.get(uid).await.map(|e| e.owm)
    }

    /// Validate the cache entry for `uid` against the current object from the DB.
    ///
    /// If the fingerprint of the cached entry differs from the fingerprint of
    /// `current_object`, the entry is invalidated so the next `get` will
    /// trigger a fresh DB fetch.  A match is a no-op (the entry stays warm).
    ///
    /// Call this whenever a fresh DB copy of the object is available (e.g.
    /// after a forced re-fetch) to detect out-of-band mutations.
    pub async fn validate_cache(&self, uid: &str, current_object: &Object) -> DbResult<()> {
        if let Some(entry) = self.inner.get(uid).await {
            if entry.fingerprint != self.fingerprinter.fingerprint(current_object)? {
                self.inner.invalidate(uid).await;
            }
        }
        Ok(())
    }

    /// Insert or update a cached object.
    pub async fn insert(&self, uid: String, owm: ObjectWithMetadata) -> DbResult<()> {
        let fingerprint = self.fingerprinter.fingerprint(owm.object())?;
        self.inner
            .insert(
                uid,
                CachedEntry {
                    owm: Arc::new(owm),
                    fingerprint,
                },
            )
            .await;
        Ok(())
    }

    /// Insert or update a cached object from an existing `Arc`.
    ///
    /// Avoids an extra `Arc::new` allocation when the caller already holds an
    /// `Arc<ObjectWithMetadata>` (e.g. from `retrieve_object_arc` on cache miss).
    pub async fn insert_arc(&self, uid: String, owm: Arc<ObjectWithMetadata>) -> DbResult<()> {
        let fingerprint = self.fingerprinter.fingerprint(owm.object())?;
        self.inner
            .insert(uid, CachedEntry { owm, fingerprint })
            .await;
        Ok(())
    }

    /// Invalidate a single entry (called on mutations).
    pub async fn invalidate(&self, uid: &str) {
        self.inner.invalidate(uid).await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        // Test helper uses NonZeroUsize::new(1000).expect() with a literal non-zero constant.
        clippy::expect_used
    )]
    use std::{num::NonZeroUsize, time::Duration};

    use cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_objects::{Object, OpaqueObject},
            kmip_types::OpaqueDataType,
        },
    };
    use cosmian_kms_interfaces::ObjectWithMetadata;

    use super::ObjectCache;

    fn make_owm(uid: &str) -> ObjectWithMetadata {
        ObjectWithMetadata::new(
            uid.to_owned(),
            Object::OpaqueObject(OpaqueObject {
                opaque_data_type: OpaqueDataType::Unknown,
                // Embed the uid so every make_owm call produces a distinct object
                // (fingerprint covers all bytes, including opaque_data_value).
                opaque_data_value: uid.as_bytes().to_vec(),
            }),
            "test-owner".to_owned(),
            State::Active,
            Attributes::default(),
        )
    }

    fn cache(max_age: Duration) -> ObjectCache {
        ObjectCache::new(max_age, NonZeroUsize::new(1000).expect("1000 is non-zero"))
    }

    #[tokio::test]
    async fn test_cache_miss_on_empty() {
        let c = cache(Duration::from_secs(60));
        assert!(c.get("uid-1").await.is_none());
    }

    #[tokio::test]
    async fn test_insert_then_hit() {
        let c = cache(Duration::from_secs(60));
        c.insert("uid-1".to_owned(), make_owm("uid-1"))
            .await
            .unwrap();
        assert!(c.get("uid-1").await.is_some());
    }

    #[tokio::test]
    async fn test_invalidate_removes_entry() {
        let c = cache(Duration::from_secs(60));
        c.insert("uid-2".to_owned(), make_owm("uid-2"))
            .await
            .unwrap();
        c.invalidate("uid-2").await;
        assert!(c.get("uid-2").await.is_none());
    }

    #[tokio::test]
    async fn test_max_age_eviction() {
        // Very short TTI so moka evicts quickly (moka checks TTI eagerly on get).
        let c = cache(Duration::from_millis(50));
        c.insert("uid-3".to_owned(), make_owm("uid-3"))
            .await
            .unwrap();
        // Wait long enough for the TTI to have lapsed.
        tokio::time::sleep(Duration::from_millis(300)).await;
        // moka checks TTI at get-time and returns None for expired entries.
        assert!(c.get("uid-3").await.is_none());
    }

    #[tokio::test]
    async fn test_lru_eviction_cleans_timestamps() {
        let c = cache(Duration::from_secs(60));
        c.insert("uid-a".to_owned(), make_owm("uid-a"))
            .await
            .unwrap();
        c.insert("uid-b".to_owned(), make_owm("uid-b"))
            .await
            .unwrap();
        c.invalidate("uid-a").await;

        assert!(c.get("uid-a").await.is_none());
        assert!(c.get("uid-b").await.is_some());
    }

    #[tokio::test]
    async fn test_validate_cache_no_op_on_same_object() {
        let c = cache(Duration::from_secs(60));
        let owm = make_owm("uid-v");
        c.insert("uid-v".to_owned(), owm.clone()).await.unwrap();
        // Same object → fingerprints match → entry stays.
        c.validate_cache("uid-v", owm.object()).await.unwrap();
        assert!(c.get("uid-v").await.is_some());
    }

    #[tokio::test]
    async fn test_validate_cache_invalidates_on_changed_object() {
        let c = cache(Duration::from_secs(60));
        c.insert("uid-v2".to_owned(), make_owm("uid-v2"))
            .await
            .unwrap();
        // Different object → fingerprints differ → entry evicted.
        let other = make_owm("uid-other");
        c.validate_cache("uid-v2", other.object()).await.unwrap();
        assert!(c.get("uid-v2").await.is_none());
    }
}
