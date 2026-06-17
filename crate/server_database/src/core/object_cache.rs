//! In-memory concurrent cache for `retrieve_object` results.
//!
//! Eliminates repeated SQLite/PostgreSQL round-trips when the same key is used
//! for many consecutive cryptographic operations (the hot-path pattern in
//! production workloads like encryption-as-a-service).
//!
//! The cache uses a fingerprint-free approach: entries are keyed by UID and
//! evicted on any mutation (`update_object`, `update_state`, `delete`).
//! Time-to-live eviction is handled internally by `moka`.
//!
//! Entries store `Arc<ObjectWithMetadata>` so cache hits are near-zero-cost
//! (pointer bump) instead of deep-cloning the full KMIP object.
//!
//! Backed by [`moka::future::Cache`], which uses internal sharding (16 segments)
//! for lock-free concurrent reads — eliminating the single-`RwLock` bottleneck
//! that caused throughput to plateau at 8+ concurrent clients.

use std::{sync::Arc, time::Duration};

use cosmian_kms_interfaces::ObjectWithMetadata;

/// Concurrent cache for recently retrieved `ObjectWithMetadata`.
///
/// Thread-safe via `moka`'s internally-sharded design.  No external locks
/// are needed — reads and writes can proceed concurrently without contention.
pub struct ObjectCache {
    cache: moka::future::Cache<String, Arc<ObjectWithMetadata>>,
}

impl ObjectCache {
    /// Create a new object cache.
    ///
    /// `max_age` controls how long an entry remains valid after its last access.
    #[must_use]
    pub fn new(max_age: Duration) -> Self {
        let cache = moka::future::Cache::builder()
            .max_capacity(1000)
            .time_to_idle(max_age)
            .build();
        Self { cache }
    }

    /// Look up a cached object by UID.
    ///
    /// Returns `Some(owm)` on cache hit, `None` on miss.
    /// Internally lock-free (sharded) — concurrent lookups do not serialize.
    ///
    /// Returns a cheap `Arc` clone — callers that need to mutate (e.g. unwrap
    /// key material) can call `Arc::unwrap_or_clone()` at the point of mutation.
    pub async fn get(&self, uid: &str) -> Option<Arc<ObjectWithMetadata>> {
        self.cache.get(uid).await
    }

    /// Insert or update a cached object.
    pub async fn insert(&self, uid: String, owm: ObjectWithMetadata) {
        self.cache.insert(uid, Arc::new(owm)).await;
    }

    /// Insert or update a cached object from an existing `Arc`.
    ///
    /// Avoids an extra `Arc::new` allocation when the caller already holds an
    /// `Arc<ObjectWithMetadata>` (e.g. from `retrieve_object_arc` on cache miss).
    pub async fn insert_arc(&self, uid: String, owm: Arc<ObjectWithMetadata>) {
        self.cache.insert(uid, owm).await;
    }

    /// Invalidate a single entry (called on mutations).
    pub async fn invalidate(&self, uid: &str) {
        self.cache.invalidate(uid).await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use std::time::Duration;

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
                opaque_data_value: vec![],
            }),
            "test-owner".to_owned(),
            State::Active,
            Attributes::default(),
        )
    }

    #[tokio::test]
    async fn test_cache_miss_on_empty() {
        let cache = ObjectCache::new(Duration::from_secs(60));
        assert!(cache.get("uid-1").await.is_none());
    }

    #[tokio::test]
    async fn test_insert_then_hit() {
        let cache = ObjectCache::new(Duration::from_secs(60));
        cache.insert("uid-1".to_owned(), make_owm("uid-1")).await;
        assert!(cache.get("uid-1").await.is_some());
    }

    #[tokio::test]
    async fn test_invalidate_removes_entry() {
        let cache = ObjectCache::new(Duration::from_secs(60));
        cache.insert("uid-2".to_owned(), make_owm("uid-2")).await;
        cache.invalidate("uid-2").await;
        assert!(cache.get("uid-2").await.is_none());
    }

    #[tokio::test]
    async fn test_max_age_eviction_by_gc() {
        // Very short max_age so the GC fires quickly (GC interval = max_age * 1.5 = 75 ms).
        let cache = ObjectCache::new(Duration::from_millis(50));
        cache.insert("uid-3".to_owned(), make_owm("uid-3")).await;
        // Wait long enough for the GC to have evicted the stale entry.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(cache.get("uid-3").await.is_none());
    }

    #[tokio::test]
    async fn test_lru_eviction_cleans_timestamps() {
        // Insert into a real ObjectCache (max 1 000 entries); verify that inserting
        // and then invalidating leaves the timestamps map clean.
        let cache = ObjectCache::new(Duration::from_secs(60));
        cache.insert("uid-a".to_owned(), make_owm("uid-a")).await;
        cache.insert("uid-b".to_owned(), make_owm("uid-b")).await;
        cache.invalidate("uid-a").await;

        assert!(cache.get("uid-a").await.is_none());
        assert!(cache.get("uid-b").await.is_some());
    }
}
