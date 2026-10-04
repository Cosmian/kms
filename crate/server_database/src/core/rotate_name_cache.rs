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
//!
//! # Invalidation
//!
//! Local writes invalidate eagerly and by keyset *name* (every owner and every
//! generation filter), or by member UID when the name is not known (delete,
//! state change). Empty results are never cached, so a freshly created keyset
//! is visible immediately. Writes made by *other* KMS nodes sharing the same
//! database are only picked up once the TTL expires, which is why correctness-
//! critical paths (re-key eligibility and generation allocation) must bypass
//! this cache via `Database::find_by_rotate_name_uncached`.

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use cosmian_kmip::kmip_2_1::kmip_attributes::Attributes;
use cosmian_logger::warn;
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

type RotateNameResults = Arc<Vec<(String, Attributes)>>;

/// Concurrent, short-TTL cache for [`crate::Database::find_by_rotate_name`] results.
///
/// Backed by [`moka::future::Cache`] — lookups are lock-free, so concurrent
/// Sign/Verify calls on distinct HSM sessions never serialize on a shared lock.
pub struct RotateNameCache {
    inner: Cache<RotateNameKey, RotateNameResults>,
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
    pub fn with_config(ttl: Duration, max_capacity: NonZeroUsize) -> Self {
        let max_capacity = u64::try_from(max_capacity.get()).map_or(u64::MAX, |capacity| capacity);
        Self {
            inner: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_live(ttl)
                .support_invalidation_closures()
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
        self.inner.get(&key).await.map(|results| (*results).clone())
    }

    /// Insert a freshly computed result for `(name, generation, owner)`.
    ///
    /// Empty results are not cached: a keyset that does not exist yet must become
    /// visible as soon as its first member is created, not after the TTL.
    pub async fn insert(
        &self,
        name: &str,
        generation: Option<i32>,
        owner: &str,
        results: Vec<(String, Attributes)>,
    ) {
        if results.is_empty() {
            return;
        }
        let key = RotateNameKey {
            name: name.to_owned(),
            generation,
            owner: owner.to_owned(),
        };
        self.inner.insert(key, Arc::new(results)).await;
    }

    /// Invalidate every cached entry for keyset `name`, for all owners and all
    /// generation filters.
    ///
    /// Called after a rotation (rekey) so the next resolution sees the new
    /// generation immediately instead of waiting out the TTL.
    pub fn invalidate_name(&self, name: &str) {
        let name = name.to_owned();
        self.invalidate_if(move |key, _| key.name == name);
    }

    /// Invalidate every cached entry that may be affected by a local write to `uid`:
    /// entries for keyset `rotate_name` (when known) and any entry listing `uid` as a member.
    ///
    /// Used for writes where the keyset name is unknown or may have changed (delete,
    /// state change, attribute update), so that e.g. a destroyed or revoked generation
    /// is not returned as the keyset's latest member for the rest of the TTL.
    pub fn invalidate_member(&self, uid: &str, rotate_name: Option<&str>) {
        let uid = uid.to_owned();
        let rotate_name = rotate_name.map(ToOwned::to_owned);
        self.invalidate_if(move |key, results| {
            rotate_name.as_deref() == Some(key.name.as_str())
                || results.iter().any(|(member, _)| *member == uid)
        });
    }

    fn invalidate_if<F>(&self, predicate: F)
    where
        F: Fn(&RotateNameKey, &RotateNameResults) -> bool + Send + Sync + 'static,
    {
        if let Err(e) = self.inner.invalidate_entries_if(predicate) {
            // Only possible if invalidation closures were not enabled at build time;
            // fall back to dropping everything rather than serving stale results.
            warn!("RotateNameCache: predicate invalidation failed ({e}); clearing cache");
            self.inner.invalidate_all();
        }
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

    fn cache() -> RotateNameCache {
        RotateNameCache::with_config(
            Duration::from_secs(60),
            NonZeroUsize::new(100).unwrap_or(NonZeroUsize::MIN),
        )
    }

    async fn seed(cache: &RotateNameCache, name: &str, generation: Option<i32>, owner: &str) {
        cache
            .insert(
                name,
                generation,
                owner,
                vec![(format!("{name}-uid"), attrs())],
            )
            .await;
    }

    #[tokio::test]
    async fn hit_miss_and_key_isolation() {
        let cache = cache();
        assert!(cache.get("keyset-a", None, "alice").await.is_none());

        seed(&cache, "keyset-a", None, "alice").await;

        assert_eq!(
            cache.get("keyset-a", None, "alice").await,
            Some(vec![("keyset-a-uid".to_owned(), attrs())])
        );
        // Different owner, different generation, different name: all distinct keys.
        assert!(cache.get("keyset-a", None, "bob").await.is_none());
        assert!(cache.get("keyset-a", Some(1), "alice").await.is_none());
        assert!(cache.get("keyset-b", None, "alice").await.is_none());
    }

    #[tokio::test]
    async fn empty_results_are_not_cached() {
        let cache = cache();
        cache.insert("keyset-a", Some(2), "alice", vec![]).await;
        assert!(cache.get("keyset-a", Some(2), "alice").await.is_none());
    }

    #[tokio::test]
    async fn invalidate_name_clears_all_owners_and_generations() {
        let cache = cache();
        seed(&cache, "keyset-a", None, "alice").await;
        seed(&cache, "keyset-a", None, "bob").await;
        seed(&cache, "keyset-a", Some(0), "alice").await;
        seed(&cache, "keyset-b", None, "alice").await;

        cache.invalidate_name("keyset-a");

        assert!(cache.get("keyset-a", None, "alice").await.is_none());
        assert!(cache.get("keyset-a", None, "bob").await.is_none());
        assert!(cache.get("keyset-a", Some(0), "alice").await.is_none());
        assert!(cache.get("keyset-b", None, "alice").await.is_some());
    }

    #[tokio::test]
    async fn invalidate_member_clears_entries_listing_the_uid() {
        let cache = cache();
        seed(&cache, "keyset-a", None, "alice").await;
        seed(&cache, "keyset-b", None, "alice").await;

        cache.invalidate_member("keyset-a-uid", None);

        assert!(cache.get("keyset-a", None, "alice").await.is_none());
        assert!(cache.get("keyset-b", None, "alice").await.is_some());
    }

    #[tokio::test]
    async fn invalidate_member_clears_entries_for_the_given_name() {
        let cache = cache();
        seed(&cache, "keyset-a", Some(3), "bob").await;

        cache.invalidate_member("some-new-uid", Some("keyset-a"));

        assert!(cache.get("keyset-a", Some(3), "bob").await.is_none());
    }

    #[tokio::test]
    async fn entries_expire_after_ttl() {
        let cache = RotateNameCache::with_config(Duration::from_millis(20), NonZeroUsize::MIN);
        seed(&cache, "keyset-a", None, "alice").await;
        assert!(cache.get("keyset-a", None, "alice").await.is_some());
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(cache.get("keyset-a", None, "alice").await.is_none());
    }
}
