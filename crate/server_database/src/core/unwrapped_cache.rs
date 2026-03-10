use std::{
    collections::HashMap,
    hash::{BuildHasher, Hash, Hasher, RandomState},
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

use cosmian_kmip::{
    KmipError,
    kmip_2_1::kmip_objects::Object,
    ttlv::{KmipFlavor, to_ttlv},
};
use cosmian_logger::{debug, trace, warn};
use lru::LruCache;
#[cfg(test)]
use tokio::sync::RwLockReadGuard;
use tokio::sync::{
    RwLock,
    mpsc::{self, Receiver, Sender},
    oneshot,
};

use crate::{DbError, error::DbResult};

/// Type of the data kept in the cache. It contains the unwrapped object and the
/// fingerprint of the wrapped object it originates from. The fingerpint has two
/// functionalities:
///
/// 1. it allows detecting when the wrapped object is modified DB-side and to
///    invalidate the cache accordingly;
///
/// 2. it prevents cache corruption from tricking the server into using an
///    incorrect unwrapped object, hence acting as a defense-in-depth mechanism.
#[derive(Clone)]
pub struct CachedObject {
    fingerprint: u64,
    unwrapped_object: Object,
}

impl CachedObject {
    pub const fn new(key_signature: u64, unwrapped_object: Object) -> Self {
        Self {
            fingerprint: key_signature,
            unwrapped_object,
        }
    }

    pub const fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    pub const fn unwrapped_object(&self) -> &Object {
        &self.unwrapped_object
    }
}

/// The cache of unwrapped objects
pub struct UnwrappedCache {
    seed: RandomState,
    cache: Arc<RwLock<LruCache<String, CachedObject>>>,
    access_timestamps: Arc<RwLock<HashMap<String, Instant>>>,
    access_sender: Sender<String>,
    gc_interval: Duration,
    max_age: Duration,
    shutdown_sender: Option<oneshot::Sender<()>>,
}

impl UnwrappedCache {
    /// Create a new cache with a configurable max age setting.
    /// The max age is the time after which an object is considered stale.
    /// The garbage collection interval is set to `max_age x 1.5`
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new(max_age: Duration) -> Self {
        // SAFETY: 100 is a non-zero constant
        #[allow(clippy::expect_used)]
        let max_size = NonZeroUsize::new(100).expect("100 is not zero. This will never trigger");

        let (tx, rx) = mpsc::channel(100_000);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let cache = Arc::new(RwLock::new(LruCache::new(max_size)));
        let access_timestamps = Arc::new(RwLock::new(HashMap::new()));
        let gc_interval = max_age + max_age / 2;

        let unwrapped_cache = Self {
            seed: RandomState::new(),
            cache,
            access_timestamps,
            access_sender: tx,
            gc_interval,
            max_age,
            shutdown_sender: Some(shutdown_tx),
        };

        unwrapped_cache.spawn_gc_thread(rx, shutdown_rx);
        unwrapped_cache
    }

    /// Spawns a thread to handle garbage collection.
    fn spawn_gc_thread(&self, mut rx: Receiver<String>, mut shutdown_rx: oneshot::Receiver<()>) {
        let timestamps = self.access_timestamps.clone();
        let cache = self.cache.clone();
        let interval = self.gc_interval;
        let max_age = self.max_age;

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    // Check for shutdown signal
                    shutdown = &mut shutdown_rx => {
                        if shutdown.is_ok() {
                            debug!("Cache garbage collection thread shutting down");
                            break;
                        }
                    }

                    // Process access timestamp updates
                    Some(key) = rx.recv() => {
                        let mut timestamps_lock = timestamps.write().await;
                        timestamps_lock.insert(key, Instant::now());
                    }

                    // Run garbage collection at the configured interval
                    _ = interval_timer.tick() => {
                        debug!("Running cache garbage collection");
                        let now = Instant::now();
                        let mut keys_to_remove = Vec::new();

                        // Find stale keys
                        {
                            let timestamps_lock = timestamps.read().await;
                            for (key, last_access) in timestamps_lock.iter() {
                                if now.duration_since(*last_access) > max_age {
                                    keys_to_remove.push(key.clone());
                                }
                            }
                        }

                        // Remove stale keys
                        if !keys_to_remove.is_empty() {
                            let mut timestamps_lock = timestamps.write().await;
                            let mut cache_lock = cache.write().await;

                            for key in &keys_to_remove {
                                timestamps_lock.remove(key);
                                cache_lock.pop(key);
                            }

                            debug!("Garbage collected {} stale cache entries", keys_to_remove.len());
                        }
                    }
                }
            }

            debug!("Cache garbage collection thread terminated");
        });
    }

    // Record a timestamp for a cache access
    async fn record_access(&self, uid: &str) -> DbResult<()> {
        if let Err(e) = self.access_sender.send(uid.to_owned()).await {
            warn!("Failed to send cache access timestamp: {}", e);
            return Err(DbError::UnwrappedCache(e.to_string()));
        }
        Ok(())
    }

    /// Return the fingerprint of this object.
    fn fingerprint(&self, object: &Object) -> DbResult<u64> {
        to_ttlv(&object)
            .and_then(|ttlv| ttlv.to_bytes(KmipFlavor::Kmip2))
            .map_err(KmipError::from)
            .map_err(DbError::from)
            .map(|bytes| {
                // SAFETY: the fingerprint is 64-bit strong, but uses a trully
                // random secret seed per instance thus making the fingerprint
                // unguessable which prevents attackers from leveraging
                // pre-computation to create targeted collisions leading to
                // undetectable cache corruption.
                let mut hasher = self.seed.build_hasher();
                bytes.hash(&mut hasher);
                hasher.finish()
            })
    }

    /// Validate the cache for a given object.
    ///
    /// If the object fingerprint is different, the cache is invalidated and the
    /// value is removed.
    pub async fn validate_cache(&self, uid: &str, object: &Object) -> DbResult<()> {
        let mut cache = self.cache.write().await;
        match cache.peek(uid) {
            Some(cached_object) => {
                if cached_object.fingerprint() != self.fingerprint(object)? {
                    trace!("Invalidating the cache for {}", uid);
                    cache.pop(uid);
                }
            }
            None => {}
        }
        Ok(())
    }

    /// Clear a value from the cache.
    pub async fn clear_cache(&self, uid: &str) {
        self.cache.write().await.pop(uid);
        self.access_timestamps.write().await.remove(uid);
    }

    /// Returns the unwrapped object cached under the given UID if it exists and
    /// its fingerprint matches the one of the given wrapped object.
    pub async fn peek(&self, uid: &str, wrapped_object: &Object) -> DbResult<Option<Object>> {
        let cache_read = self.cache.read();
        match cache_read.await.peek(uid) {
            Some(cached_object) => {
                self.record_access(uid).await?;
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
    pub async fn insert(
        &self,
        uid: String,
        wrapped_object: &Object,
        unwrapped_object: Object,
    ) -> DbResult<()> {
        if wrapped_object == &unwrapped_object {
            return Err(DbError::UnwrappedCache(
                "wrapped and unwrapped objects should be different".to_string(),
            ));
        }

        self.cache.write().await.put(
            uid.clone(),
            CachedObject {
                fingerprint: self.fingerprint(wrapped_object)?,
                unwrapped_object,
            },
        );

        self.access_timestamps
            .write()
            .await
            .insert(uid, Instant::now());

        Ok(())
    }

    #[cfg(test)]
    pub async fn get_cache(&self) -> RwLockReadGuard<'_, LruCache<String, CachedObject>> {
        self.cache.read().await
    }
}

impl Drop for UnwrappedCache {
    fn drop(&mut self) {
        // Send shutdown signal to the GC thread when the cache is dropped
        if let Some(shutdown_tx) = self.shutdown_sender.take() {
            // We can't do much if sending fails, just ignore the error
            // This would happen if the receiver was already dropped
            let _ = shutdown_tx.send(());
            debug!("Sent shutdown signal to cache garbage collection thread");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic_in_result_fn,
        clippy::unwrap_in_result,
        clippy::assertions_on_result_states,
        clippy::assertions_on_constants
    )]
    use std::{
        collections::{HashMap, HashSet},
        time::Duration,
    };

    use cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attributes, kmip_types::CryptographicAlgorithm,
        requests::create_symmetric_key_kmip_object,
    };
    use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
        CsRng,
        reexport::rand_core::{RngCore, SeedableRng},
    };
    use cosmian_logger::log_init;
    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::{Database, core::main_db_params::MainDbParams, error::DbResult};

    #[tokio::test]
    async fn test_lru_cache() -> DbResult<()> {
        // log_init(Some("debug"));
        log_init(option_env!("RUST_LOG"));

        let dir = TempDir::new()?;

        let main_db_params = MainDbParams::Sqlite(dir.path().to_owned(), None);
        let database = Database::instantiate(
            &main_db_params,
            true,
            HashMap::new(),
            Duration::from_millis(100),
        )
        .await?;

        let mut rng = CsRng::from_entropy();

        // create a symmetric key with tags
        let mut symmetric_key_bytes = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key_bytes);
        // create a symmetric key
        let symmetric_key = create_symmetric_key_kmip_object(
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
                owner,
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
                .await
                .unwrap()
                .is_none()
        );

        // fetch the key
        let owm = database.retrieve_object(&uid).await?;
        match owm {
            Some(obj) => assert_eq!(obj.id(), &uid),
            None => assert!(false, "expected object to be present"),
        }
        {
            let cache = database.unwrapped_cache.get_cache();
            // the unwrapped version should not be in the cache
            assert!(cache.await.peek(&uid).is_none());
        };

        Ok(())
    }

    #[tokio::test]
    async fn test_garbage_collection() -> DbResult<()> {
        // log_init(Some("debug"));
        log_init(option_env!("RUST_LOG"));

        // Create a cache with a short GC interval and max age
        let cache = super::UnwrappedCache::new(
            Duration::from_millis(100), // Keys expire after 100 ms, GC runs every 150 ms.
        );

        // Insert an item
        let uid = "test_item".to_owned();

        let unwrapped_object = create_symmetric_key_kmip_object(
            &[0; 32],
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Attributes::default()
            },
        )?;

        let wrapped_object = create_symmetric_key_kmip_object(
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
            let cache = super::UnwrappedCache::new(Duration::from_millis(100));

            let uid = "test_item".to_owned();

            let wrapped_object = create_symmetric_key_kmip_object(
                &[0; 32],
                &Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    ..Attributes::default()
                },
            )?;

            let unwrapped_object = create_symmetric_key_kmip_object(
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
