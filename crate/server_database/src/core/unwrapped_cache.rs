use std::{num::NonZeroUsize, time::Duration};

use cosmian_kmip::kmip_2_1::{
    kmip_objects::{Object, OpaqueObject},
    kmip_types::OpaqueDataType,
};
use cosmian_logger::trace;
use moka::future::Cache;
use zeroize::Zeroize;

use crate::{DbError, core::fingerprinter::Fingerprinter, error::DbResult};

/// Type of the data kept in the cache. It contains the unwrapped object and the
/// fingerprint of the wrapped object it originates from. The fingerprint has two
/// functionalities:
///
/// 1. it allows detecting when the wrapped object is modified DB-side and to
///    invalidate the cache accordingly;
///
/// 2. it prevents cache corruption from tricking the server into using an
///    incorrect unwrapped object, hence acting as a defense-in-depth mechanism.
///
/// Field order matches [`super::ObjectCache`]'s internal entry: value first,
/// fingerprint second.
#[derive(Clone)]
pub struct CachedObject {
    unwrapped_object: Object,
    fingerprint: u64,
}

impl CachedObject {
    #[must_use]
    pub const fn new(unwrapped_object: Object, fingerprint: u64) -> Self {
        Self {
            unwrapped_object,
            fingerprint,
        }
    }

    #[must_use]
    pub const fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    #[must_use]
    pub const fn unwrapped_object(&self) -> &Object {
        &self.unwrapped_object
    }
}

impl Drop for CachedObject {
    fn drop(&mut self) {
        // Explicitly zero all sensitive key material before releasing memory.
        // `Object::zeroize()` zeros in-place via `Zeroizing<Vec<u8>>` (ByteString,
        // TransparentSymmetricKey) and `SafeBigInt::drop()` (all private-key variants),
        // then the replacement with an empty OpaqueObject ensures the slot can never
        // serve key material again even if the allocator does not overwrite freed pages.
        self.unwrapped_object.zeroize();
        self.unwrapped_object = Object::OpaqueObject(OpaqueObject {
            opaque_data_type: OpaqueDataType::Unknown,
            opaque_data_value: Vec::new(),
        });
    }
}

/// The cache of unwrapped objects
pub struct UnwrappedCache {
    fingerprinter: Fingerprinter,
    inner: Cache<String, CachedObject>,
    /// When `true` all `peek` / `insert` calls are no-ops; every unwrap goes
    /// straight through to the KEK or HSM, leaving no plaintext key material
    /// in process memory beyond a single operation.
    disabled: bool,
}

impl UnwrappedCache {
    /// Create a new cache with configurable settings.
    ///
    /// * `max_age` — time-to-idle: entries are evicted after this duration without access.
    /// * `max_size` — maximum number of entries before LRU eviction kicks in.
    /// * `max_ttl` — optional absolute time-to-live; when set, an entry expires at
    ///   `min(last_access + max_age, insert_time + max_ttl)`.  Use this to cap
    ///   plaintext key residency for continuously-accessed (hot) keys.
    /// * `disabled` — when `true`, bypasses the cache entirely.
    #[must_use]
    #[allow(clippy::as_conversions)]
    pub fn new(
        max_age: Duration,
        max_size: NonZeroUsize,
        max_ttl: Option<Duration>,
        disabled: bool,
    ) -> Self {
        let mut builder = Cache::builder()
            .max_capacity(max_size.get() as u64)
            .time_to_idle(max_age);
        if let Some(ttl) = max_ttl {
            builder = builder.time_to_live(ttl);
        }
        Self {
            fingerprinter: Fingerprinter::new(),
            inner: builder.build(),
            disabled,
        }
    }

    /// Return the fingerprint of this object.
    ///
    /// Delegates to the shared [`Fingerprinter`].
    fn fingerprint(&self, object: &Object) -> DbResult<u64> {
        self.fingerprinter.fingerprint(object)
    }

    /// Validate the cache for a given object.
    ///
    /// If the object fingerprint is different, the cache is invalidated and the
    /// value is removed.
    pub async fn validate_cache(&self, uid: &str, object: &Object) -> DbResult<()> {
        if let Some(cached_object) = self.inner.get(uid).await {
            if cached_object.fingerprint() != self.fingerprint(object)? {
                trace!("Invalidating the cache for {}", uid);
                self.inner.invalidate(uid).await;
            }
        }
        Ok(())
    }

    /// Clear a value from the cache.
    pub async fn clear_cache(&self, uid: &str) {
        self.inner.invalidate(uid).await;
    }

    /// Returns the unwrapped object cached under the given UID if it exists and
    /// its fingerprint matches the one of the given wrapped object.
    ///
    /// Returns `Ok(None)` immediately when the cache is disabled.
    pub async fn peek(&self, uid: &str, wrapped_object: &Object) -> DbResult<Option<Object>> {
        if self.disabled {
            return Ok(None);
        }
        match self.inner.get(uid).await {
            Some(cached_object) => {
                if cached_object.fingerprint() == self.fingerprint(wrapped_object)? {
                    Ok(Some(cached_object.unwrapped_object().clone()))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Caches the unwrapped version of the given object under this UID.
    ///
    /// The fingerprint of the wrapped object is stored alongside the unwrapped
    /// object to ensure it is never used to answer requests for another wrapped
    /// object.
    ///
    /// Is a no-op when the cache is disabled.
    pub async fn insert(
        &self,
        uid: String,
        wrapped_object: &Object,
        unwrapped_object: Object,
    ) -> DbResult<()> {
        if self.disabled {
            return Ok(());
        }
        if wrapped_object == &unwrapped_object {
            return Err(DbError::UnwrappedCache(
                "wrapped and unwrapped objects should be different".to_owned(),
            ));
        }

        self.inner
            .insert(
                uid,
                CachedObject::new(unwrapped_object, self.fingerprint(wrapped_object)?),
            )
            .await;
        Ok(())
    }

    /// Returns `true` if the cache contains an entry for `uid`.
    ///
    /// Only used in tests to check cache state without requiring a `wrapped_object`.
    #[cfg(test)]
    pub async fn contains(&self, uid: &str) -> bool {
        self.inner.get(uid).await.is_some()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic_in_result_fn,
        clippy::unwrap_in_result,
        clippy::assertions_on_result_states,
        clippy::assertions_on_constants,
        // Test helpers use NonZeroUsize::new(N).expect() with literal non-zero constants.
        clippy::expect_used
    )]
    use std::{
        collections::{HashMap, HashSet},
        num::NonZeroUsize,
        time::Duration,
    };

    use cosmian_kmip::kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN, kmip_attributes::Attributes,
        kmip_types::CryptographicAlgorithm, requests::create_symmetric_key_kmip_object,
    };
    use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
        CsRng,
        reexport::rand_core::{RngCore, SeedableRng},
    };
    use cosmian_kms_interfaces::UserId;
    use cosmian_logger::log_init;
    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::{Database, core::main_db_params::MainDbParams, error::DbResult};

    #[tokio::test]
    async fn test_lru_cache() -> DbResult<()> {
        log_init(option_env!("RUST_LOG"));

        let dir = TempDir::new()?;

        let main_db_params = MainDbParams::Sqlite(dir.path().to_owned(), None);
        let database = Database::instantiate(
            &main_db_params,
            true,
            HashMap::new(),
            Duration::from_millis(100),
            NonZeroUsize::new(100).expect("100 is non-zero"),
            None,  // cache_max_ttl
            false, // disable_unwrapped_cache
            None,  // recorder
            None,  // ceremony_keys
        )
        .await?;

        let mut rng = CsRng::from_entropy();

        // create a symmetric key with tags
        let mut symmetric_key_bytes = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key_bytes);
        // create a symmetric key
        let symmetric_key = create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            &symmetric_key_bytes,
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Attributes::default()
            },
        )?;

        // insert into DB
        let owner = "eyJhbGciOiJSUzI1Ni";
        let uid = Uuid::new_v4().to_string();
        let uid_ = database
            .create(
                Some(uid.clone()),
                &UserId::from(owner),
                &symmetric_key,
                symmetric_key.attributes()?,
                &HashSet::new(),
            )
            .await?;
        assert_eq!(&uid, &uid_);

        // The key should not be in the cache
        assert!(
            database
                .unwrapped_cache()
                .peek(&uid, &symmetric_key)
                .await?
                .is_none()
        );

        // fetch the key
        let owm = database.retrieve_object(&uid).await?;
        match owm {
            Some(obj) => assert_eq!(obj.id(), &uid),
            None => assert!(false, "expected object to be present"),
        }
        // Non-wrapped keys must NOT be placed in the unwrapped cache.
        assert!(!database.unwrapped_cache.contains(&uid).await);

        Ok(())
    }

    #[tokio::test]
    async fn test_garbage_collection() -> DbResult<()> {
        // log_init(Some("debug"));
        log_init(option_env!("RUST_LOG"));

        // Create a cache with a short GC interval and max age
        let cache = super::UnwrappedCache::new(
            Duration::from_millis(100), // Keys expire after 100 ms, GC runs every 150 ms.
            NonZeroUsize::new(100).expect("100 is non-zero"),
            None,
            false,
        );

        // Insert an item
        let uid = "test_item".to_owned();

        let unwrapped_object = create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            &[0; 32],
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Attributes::default()
            },
        )?;

        let wrapped_object = create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            &[0; 32],
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Attributes::default()
            },
        )?;

        cache
            .insert(uid.clone(), &wrapped_object, unwrapped_object.clone())
            .await?;

        // Verify it's in the cache
        assert_eq!(
            cache.peek(&uid, &wrapped_object).await?,
            Some(unwrapped_object)
        );

        // Wait for the item to be garbage collected
        tokio::time::sleep(Duration::from_millis(350)).await;

        // The item should be gone
        assert!(cache.peek(&uid, &wrapped_object).await?.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_gc_thread_shutdown() -> DbResult<()> {
        // log_init(Some("debug"));
        log_init(option_env!("RUST_LOG"));

        // Create a scope to ensure the cache is dropped
        {
            let cache = super::UnwrappedCache::new(
                Duration::from_millis(100),
                NonZeroUsize::new(100).expect("100 is non-zero"),
                None,
                false,
            );

            let uid = "test_item".to_owned();

            let wrapped_object = create_symmetric_key_kmip_object(
                VENDOR_ID_COSMIAN,
                &[0; 32],
                &Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    ..Attributes::default()
                },
            )?;

            let unwrapped_object = create_symmetric_key_kmip_object(
                VENDOR_ID_COSMIAN,
                &[0; 32],
                &Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    ..Attributes::default()
                },
            )?;

            cache
                .insert(uid.clone(), &wrapped_object, unwrapped_object.clone())
                .await?;

            // Verify it's in the cache
            assert_eq!(
                cache.peek(&uid, &wrapped_object).await?,
                Some(unwrapped_object),
            );
        };

        // Cache has been dropped here, thread should be shutting down
        // Give some time for the thread to process the shutdown signal
        tokio::time::sleep(Duration::from_millis(50)).await;

        // We can't directly test that the thread has been terminated,
        // but this test ensures the Drop implementation is called properly
        Ok(())
    }
}
