//! In-memory concurrent cache for `find_by_rotate_name` results.
//!
//! Every delegated PKCS#11 Sign/Verify call routes through
//! [`crate::Database::find_by_rotate_name`] to resolve which concrete UID is the
//! "latest" (or a specific) generation of a keyset — this happens even for a
//! plain `hsm::<slot>::<uuid>` unique identifier with no rotation history,
//! because a bare HSM UID is, by design, always treated as a (possibly
//! single-member) keyset reference (see `uid_utils::parse_keyset_identifier`).
//!
//! For an [`crate::stores::ObjectsStore`] backed by a PKCS#11 HSM, resolving this
//! query means a full `C_FindObjects` scan of the slot followed by a
//! `C_GetAttributeValue` round-trip for every object found — on *every single
//! cryptographic operation*. Under concurrent load this dominates both CPU
//! self-time (allocator + mutex churn building/tearing down the per-call result
//! `Vec`) and HSM session contention, and was measured to be the dominant
//! bottleneck in the HSM-delegated PKCS#11 sign/verify benchmark.
//!
//! This cache short-circuits repeated identical lookups with the same bounded
//! staleness window already used for [`super::object_cache::ObjectCache`]'s
//! cross-node revalidation (2 seconds): key rotation is a rare, explicit
//! administrative action, so a worst-case few-second delay before a freshly
//! rotated generation becomes visible to new Sign/Verify calls is an accepted
//! trade-off for removing a full HSM slot scan from the per-operation hot path.

use std::{num::NonZeroUsize, time::Duration};

use cosmian_kmip::kmip_2_1::kmip_attributes::Attributes;
use moka::future::Cache;

/// Bounded staleness window for cached `find_by_rotate_name` results.
///
/// Matches [`super::object_cache::DEFAULT_REVALIDATION_INTERVAL`]: the same
/// staleness budget this codebase already accepts for object-attribute
/// cross-node consistency.
pub(crate) const DEFAULT_TTL: Duration = Duration::from_secs(2);

/// Default maximum number of distinct `(name, generation, owner)` lookups held at once.
const DEFAULT_MAX_CAPACITY: usize = 10_000;

/// Composite cache key: a `find_by_rotate_name` call is fully determined by the
/// keyset name, the optional explicit generation filter, and the requesting owner.
#[derive(Clone, PartialEq, Eq, Hash)]
struct RotateNameKey {
    name: String,
    generation: Option<i32>,
    owner: String,
}

/// Concurrent, short-TTL cache for [`crate::Database::find_by_rotate_name`] results.
///
/// Backed by [`moka::future::Cache`] — lookups are lock-free, so concurrent
/// Sign/Verify calls on distinct HSM sessions never serialize on a shared lock.
pub struct RotateNameCache {
    inner: Cache<RotateNameKey, Vec<(String, Attributes)>>,
}

impl RotateNameCache {
    /// Create a new cache with the default TTL and capacity.
    #[must_use]
    pub fn new() -> Self {
        let max_capacity = NonZeroUsize::new(DEFAULT_MAX_CAPACITY).unwrap_or(NonZeroUsize::MIN);
        Self::with_config(DEFAULT_TTL, max_capacity)
    }

    /// Create a new cache with an explicit TTL and capacity (used in tests).
    #[must_use]
    #[allow(clippy::as_conversions)]
    pub fn with_config(ttl: Duration, max_capacity: NonZeroUsize) -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(max_capacity.get() as u64)
                .time_to_live(ttl)
                .build(),
        }
    }

    /// Look up a cached result for `(name, generation, owner)`.
    pub async fn get(
        &self,
        name: &str,
        generation: Option<i32>,
        owner: &str,
    ) -> Option<Vec<(String, Attributes)>> {
        let key = RotateNameKey {
            name: name.to_owned(),
            generation,
            owner: owner.to_owned(),
        };
        self.inner.get(&key).await
    }

    /// Insert a freshly computed result for `(name, generation, owner)`.
    pub async fn insert(
        &self,
        name: &str,
        generation: Option<i32>,
        owner: &str,
        results: Vec<(String, Attributes)>,
    ) {
        let key = RotateNameKey {
            name: name.to_owned(),
            generation,
            owner: owner.to_owned(),
        };
        self.inner.insert(key, results).await;
    }

    /// Invalidate every cached generation-filter variant for `name`/`owner`.
    ///
    /// Called after a rotation (rekey) so the next resolution sees the new
    /// generation immediately instead of waiting out the TTL. Since the
    /// generation filter is part of the key but rotations only add a new
    /// generation (they never need `invalidate_entries_if` to be exhaustive
    /// for correctness — the TTL bounds worst-case staleness regardless),
    /// this clears the unfiltered (`None`) entry that `resolve_keyset_to_single_uid`
    /// and `walk_keyset_chain` actually populate for `SingleLatest`/`Bare`/`Latest`
    /// lookups, which is the entry every delegated Sign/Verify call reads.
    pub async fn invalidate(&self, name: &str, owner: &str) {
        let key = RotateNameKey {
            name: name.to_owned(),
            generation: None,
            owner: owner.to_owned(),
        };
        self.inner.invalidate(&key).await;
    }
}

impl Default for RotateNameCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn attrs() -> Attributes {
        Attributes::default()
    }

    #[tokio::test]
    async fn hit_miss_and_key_isolation() {
        let cache = RotateNameCache::with_config(Duration::from_secs(60), NonZeroUsize::MIN);
        assert!(cache.get("keyset-a", None, "alice").await.is_none());

        cache
            .insert(
                "keyset-a",
                None,
                "alice",
                vec![("uid-1".to_owned(), attrs())],
            )
            .await;

        assert_eq!(
            cache.get("keyset-a", None, "alice").await,
            Some(vec![("uid-1".to_owned(), attrs())])
        );
        // Different owner, different generation, different name: all distinct keys.
        assert!(cache.get("keyset-a", None, "bob").await.is_none());
        assert!(cache.get("keyset-a", Some(1), "alice").await.is_none());
        assert!(cache.get("keyset-b", None, "alice").await.is_none());
    }

    #[tokio::test]
    async fn invalidate_clears_the_bare_entry() {
        let cache = RotateNameCache::with_config(Duration::from_secs(60), NonZeroUsize::MIN);
        cache
            .insert(
                "keyset-a",
                None,
                "alice",
                vec![("uid-1".to_owned(), attrs())],
            )
            .await;
        cache.invalidate("keyset-a", "alice").await;
        assert!(cache.get("keyset-a", None, "alice").await.is_none());
    }

    #[tokio::test]
    async fn entries_expire_after_ttl() {
        let cache = RotateNameCache::with_config(Duration::from_millis(20), NonZeroUsize::MIN);
        cache
            .insert(
                "keyset-a",
                None,
                "alice",
                vec![("uid-1".to_owned(), attrs())],
            )
            .await;
        assert!(cache.get("keyset-a", None, "alice").await.is_some());
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(cache.get("keyset-a", None, "alice").await.is_none());
    }
}
