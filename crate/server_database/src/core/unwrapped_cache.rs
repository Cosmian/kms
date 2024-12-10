use std::num::NonZeroUsize;

use cosmian_kmip::kmip::kmip_objects::Object;
use lru::LruCache;
use tokio::sync::RwLock;
#[cfg(test)]
use tokio::sync::RwLockReadGuard;
use tracing::trace;

use crate::error::DbResult;

/// This is the object kept in the Main LRU cache
/// It contains the unwrapped object and the key signature
#[derive(Clone)]
pub struct CachedUnwrappedObject {
    key_signature: u64,
    unwrapped_object: Object,
}

impl CachedUnwrappedObject {
    #[must_use]
    pub const fn new(key_signature: u64, unwrapped_object: Object) -> Self {
        Self {
            key_signature,
            unwrapped_object,
        }
    }

    #[must_use]
    pub const fn key_signature(&self) -> u64 {
        self.key_signature
    }

    #[must_use]
    pub const fn unwrapped_object(&self) -> &Object {
        &self.unwrapped_object
    }
}

/// The cache of unwrapped objects
/// The key is the uid of the object
/// The value is the unwrapped object
/// The value is a `Err(KmsError)` if the object cannot be unwrapped
pub struct UnwrappedCache {
    cache: RwLock<LruCache<String, DbResult<CachedUnwrappedObject>>>,
}

impl Default for UnwrappedCache {
    fn default() -> Self {
        Self::new()
    }
}

impl UnwrappedCache {
    #[must_use]
    pub fn new() -> Self {
        #[allow(unsafe_code)]
        let max = unsafe { NonZeroUsize::new_unchecked(100) };
        Self {
            cache: RwLock::new(LruCache::new(max)),
        }
    }

    /// Validate the cache for a given object
    /// If the key signature is different, the cache is invalidated
    /// and the value is removed.
    pub async fn validate_cache(&self, uid: &str, object: &Object) {
        if let Ok(key_signature) = object.key_signature() {
            let mut cache = self.cache.write().await;
            // invalidate the value in cache if the signature is different
            match cache.peek(uid) {
                Some(Ok(cached_object)) => {
                    if *cached_object.key_signature() != key_signature {
                        trace!("Invalidating the cache for {}", uid);
                        cache.pop(uid);
                    }
                }
                Some(Err(_)) => {
                    // Note: this forces invalidation every time
                    // but trying to unwrap a key that fails to unwrap
                    // should be an exceptional case
                    trace!("Invalidating the cache for {}", uid);
                    cache.pop(uid);
                }
                None => {}
            }
        }
    }

    /// Clear a value from the cache
    pub async fn clear_cache(&self, uid: &str) {
        self.cache.write().await.pop(uid);
    }

    /// Peek into the cache
    pub async fn peek(&self, uid: &str) -> Option<DbResult<CachedUnwrappedObject>> {
        self.cache.read().await.peek(uid).cloned()
    }

    /// Insert into the cache
    pub async fn insert(&self, uid: String, unwrapped_object: DbResult<CachedUnwrappedObject>) {
        self.cache.write().await.put(uid, unwrapped_object);
    }

    #[cfg(test)]
    pub async fn get_cache(
        &self,
    ) -> RwLockReadGuard<'_, LruCache<String, DbResult<CachedUnwrappedObject>>> {
        self.cache.read().await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cloudproof::reexport::crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng,
    };
    use cosmian_kmip::kmip::kmip_types::CryptographicAlgorithm;
    use cosmian_kms_crypto::crypto::symmetric::create_symmetric_key_kmip_object;
    use cosmian_logger::log_init;
    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::{core::main_db_params::MainDbParams, error::DbResult, Database};

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_lru_cache() -> DbResult<()> {
        log_init(option_env!("RUST_LOG"));

        let dir = TempDir::new()?;

        let main_db_params = MainDbParams::Sqlite(dir.path().to_owned());
        let database = Database::instantiate(&main_db_params, true, None, "").await?;

        let mut rng = CsRng::from_entropy();

        // create a symmetric key with tags
        let mut symmetric_key_bytes = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key_bytes);
        // create a symmetric key
        let symmetric_key = create_symmetric_key_kmip_object(
            &symmetric_key_bytes,
            CryptographicAlgorithm::AES,
            false,
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
                None,
            )
            .await?;
        assert_eq!(&uid, &uid_);

        // The key should not be in the cache
        assert!(database.unwrapped_cache().peek(&uid).await.is_none());

        // fetch the key
        let owm = database.retrieve_object(&uid, None).await?;
        assert!(owm.is_some());
        assert_eq!(owm.unwrap().id(), &uid);
        {
            let cache = database.unwrapped_cache.get_cache();
            // the unwrapped version should not be in the cache
            assert!(cache.await.peek(&uid).is_none());
        }

        Ok(())
    }
}
