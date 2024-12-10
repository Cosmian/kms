//! This module contains the core database functionalities, including object management,
//! permission checks, and caching mechanisms for unwrapped keys.
mod database_objects;
mod database_permissions;

use std::{collections::HashMap, sync::Arc};

use cloudproof::reexport::crypto_core::FixedSizeCBytes;
use cosmian_kms_crypto::secret::Secret;
use cosmian_kms_interfaces::HSM;
use tokio::sync::RwLock;

use crate::{error::DbResult, stores::HsmStore};

mod main_db_params;
pub use main_db_params::{AdditionalObjectStoresParams, MainDbParams};
mod object_with_metadata;
mod unwrapped_cache;
pub use object_with_metadata::ObjectWithMetadata;

pub use crate::core::unwrapped_cache::{CachedUnwrappedObject, UnwrappedCache};
use crate::stores::{
    CachedSqlCipher, MySqlPool, ObjectsStore, PermissionsStore, PgPool, RedisWithFindex,
    SqlitePool, REDIS_WITH_FINDEX_MASTER_KEY_LENGTH,
};

/// The `Database` struct represents the core database functionalities, including object management,
/// permission checks, and caching mechanisms for unwrapped keys.
pub struct Database {
    /// A map of uid prefixes to Object Store
    /// The "no-prefix" DB is registered under the empty string
    objects: RwLock<HashMap<String, Arc<dyn ObjectsStore + Sync + Send>>>,
    /// The permissions store is used to check if a user has the right to perform an operation
    //TODO use this store to check permissions in retrieve, update, delete, etc.
    permissions: Arc<dyn PermissionsStore + Sync + Send>,
    /// The Unwrapped cache keeps the unwrapped version of keys in memory.
    /// This cache avoids calls to HSMs for each operation
    unwrapped_cache: UnwrappedCache,
}

impl Database {
    pub async fn instantiate(
        main_db_params: &MainDbParams,
        clear_db_on_start: bool,
        //TODO once ObjectStore is refactored into the `plugins` crate, a map of prefix-> Object Stores can be passed here
        hsm: Option<Arc<dyn HSM + Sync + Send>>,
        hsm_admin: &str,
    ) -> DbResult<Self> {
        // main database
        let db = Self::instantiate_main_database(main_db_params, clear_db_on_start).await?;
        if let Some(hsm) = hsm {
            db.register_objects_store("hsm", Arc::new(HsmStore::new(hsm, hsm_admin)))
                .await;
        }
        Ok(db)
    }

    async fn instantiate_main_database(
        main_db_params: &MainDbParams,
        clear_db_on_start: bool,
    ) -> DbResult<Self> {
        Ok(match main_db_params {
            MainDbParams::Sqlite(db_path) => {
                let db = Arc::new(
                    SqlitePool::instantiate(&db_path.join("kms.db"), clear_db_on_start).await?,
                );
                Self::new(db.clone(), db)
            }
            MainDbParams::SqliteEnc(db_path) => {
                let db = Arc::new(CachedSqlCipher::instantiate(db_path, clear_db_on_start)?);
                Self::new(db.clone(), db)
            }
            MainDbParams::Postgres(url) => {
                let db = Arc::new(PgPool::instantiate(url.as_str(), clear_db_on_start).await?);
                Self::new(db.clone(), db)
            }
            MainDbParams::Mysql(url) => {
                let db = Arc::new(MySqlPool::instantiate(url.as_str(), clear_db_on_start).await?);
                Self::new(db.clone(), db)
            }
            MainDbParams::RedisFindex(url, master_key, label) => {
                // There is no reason to keep a copy of the key in the shared config
                // So we are going to create a "zeroizable" copy which will be passed to Redis with Findex
                // and zeroize the one in the shared config
                let new_master_key =
                    Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::from_unprotected_bytes(
                        &mut master_key.to_bytes(),
                    );
                // `master_key` implements ZeroizeOnDrop so there is no need
                // to manually zeroize.
                let db = Arc::new(
                    RedisWithFindex::instantiate(url.as_str(), new_master_key, label).await?,
                );
                Self::new(db.clone(), db)
            }
        })
    }

    pub const fn unwrapped_cache(&self) -> &UnwrappedCache {
        &self.unwrapped_cache
    }

    /// Create a new Objects Store
    ///  - `default_database` is the default database for objects without a prefix
    pub(crate) fn new(
        default_objects_database: Arc<dyn ObjectsStore + Sync + Send>,
        permissions_database: Arc<dyn PermissionsStore + Sync + Send>,
    ) -> Self {
        Self {
            objects: RwLock::new(HashMap::from([(String::new(), default_objects_database)])),
            permissions: permissions_database,
            unwrapped_cache: UnwrappedCache::new(),
        }
    }
}
