//! This module contains the core database functionalities, including object management,
//! permission checks, and caching mechanisms for unwrapped keys.
mod database_objects;
mod database_permissions;

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
#[cfg(feature = "non-fips")]
use cosmian_kms_crypto::reexport::cosmian_crypto_core::Secret;
use cosmian_kms_interfaces::{ObjectsStore, PermissionsStore};
#[cfg(feature = "non-fips")]
use redis::AsyncCommands;
use tokio::sync::RwLock;

use crate::error::DbResult;

mod main_db_params;
pub use main_db_params::{AdditionalObjectStoresParams, MainDbParams};
mod unwrapped_cache;

pub use crate::core::unwrapped_cache::{CachedUnwrappedObject, UnwrappedCache};
#[cfg(feature = "non-fips")]
use crate::stores::RedisWithFindex;
use crate::stores::{MySqlPool, PgPool, SqlitePool};
// mTLS proxy removed; rely on native client TLS support in pools

/// The `Database` struct represents the core database functionalities, including object management,
/// permission checks, and caching mechanisms for unwrapped keys.
pub struct Database {
    /// A map of uid prefixes to Object Store
    /// The "no-prefix" DB is registered under the empty string
    objects: RwLock<HashMap<String, Arc<dyn ObjectsStore + Sync + Send>>>,
    /// The permissions store is used to check if a user has the right to perform an operation
    permissions: Arc<dyn PermissionsStore + Sync + Send>,
    /// The Unwrapped cache keeps the unwrapped version of keys in memory.
    /// This cache avoids calls to HSMs for each operation
    unwrapped_cache: UnwrappedCache,

    /// The database kind for the default store (sqlite/postgres/mysql/redis-findex).
    kind: MainDbKind,

    /// A lightweight health probe for the default store.
    ///
    /// This enables server-side `/health` checks without exposing internal store types.
    health: Arc<dyn DatabaseHealth + Sync + Send>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainDbKind {
    Sqlite,
    Postgres,
    Mysql,
    #[cfg(feature = "non-fips")]
    RedisFindex,
}

#[async_trait]
trait DatabaseHealth {
    async fn check(&self) -> Result<(), String>;
}

impl Database {
    /// Create a new `Database` instance.
    ///
    /// This function initializes the database with the given parameters, including the main database
    /// connection, the permissions store, and the cache max age.
    ///
    /// # Arguments
    /// - `main_db_params` is the parameters for the main database.
    /// - `clear_db_on_start` indicates whether to clear the database on startup.
    /// - `object_stores` is a map of object stores with their prefixes.
    /// - `cache_max_age` is the maximum age of unwrapped objects in the cache.
    pub async fn instantiate(
        main_db_params: &MainDbParams,
        clear_db_on_start: bool,
        object_stores: HashMap<String, Arc<dyn ObjectsStore + Sync + Send>>,
        cache_max_age: Duration,
    ) -> DbResult<Self> {
        // main/default database
        let db = Self::instantiate_main_database(main_db_params, clear_db_on_start, cache_max_age)
            .await?;
        for (prefix, store) in object_stores {
            db.register_objects_store(&prefix, store).await;
        }
        Ok(db)
    }

    async fn instantiate_main_database(
        main_db_params: &MainDbParams,
        clear_db_on_start: bool,
        cache_max_age: Duration,
    ) -> DbResult<Self> {
        // Permissions are stored in the same backend as objects for the main database.
        // The `SqlitePool`/`PgPool`/`MySqlPool` types implement both `ObjectsStore` and
        // `PermissionsStore`, so we can reuse the same `Arc`.
        match main_db_params {
            MainDbParams::Sqlite(db_path, max_conns) => {
                let db = Arc::new(
                    SqlitePool::instantiate(&db_path.join("kms.db"), clear_db_on_start, *max_conns)
                        .await?,
                );
                let health = Arc::new(SqliteHealthProbe::new(db.clone()));
                Ok(Self::new(
                    db.clone(),
                    db,
                    cache_max_age,
                    MainDbKind::Sqlite,
                    health,
                ))
            }
            MainDbParams::Postgres(url, max_conns) => {
                let db = Arc::new(
                    PgPool::instantiate(url.as_str(), clear_db_on_start, *max_conns).await?,
                );
                let health = Arc::new(PgHealthProbe::new(db.clone()));
                Ok(Self::new(
                    db.clone(),
                    db,
                    cache_max_age,
                    MainDbKind::Postgres,
                    health,
                ))
            }
            MainDbParams::Mysql(url, max_conns) => {
                let db = Arc::new(
                    MySqlPool::instantiate(url.as_str(), clear_db_on_start, *max_conns).await?,
                );
                let health = Arc::new(MySqlHealthProbe::new(db.clone()));
                Ok(Self::new(
                    db.clone(),
                    db,
                    cache_max_age,
                    MainDbKind::Mysql,
                    health,
                ))
            }
            #[cfg(feature = "non-fips")]
            MainDbParams::RedisFindex(url, master_key) => {
                // There is no reason to keep a copy of the key in the shared config
                // So we are going to create a "zeroizable" copy which will be passed to Redis with Findex
                // and zeroize the one in the shared config
                use cosmian_kms_crypto::reexport::cosmian_crypto_core::FixedSizeCBytes;

                use crate::stores::REDIS_WITH_FINDEX_MASTER_KEY_LENGTH;

                let new_master_key =
                    Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::from_unprotected_bytes(
                        &mut master_key.to_bytes(),
                    );
                // `master_key` implements ZeroizeOnDrop so there is no need
                // to manually zeroize.
                let db = Arc::new(
                    RedisWithFindex::instantiate(url.as_str(), new_master_key, clear_db_on_start)
                        .await?,
                );
                let health = Arc::new(RedisFindexHealthProbe::new(db.clone()));
                Ok(Self::new(
                    db.clone(),
                    db,
                    cache_max_age,
                    MainDbKind::RedisFindex,
                    health,
                ))
            }
        }
    }

    pub const fn unwrapped_cache(&self) -> &UnwrappedCache {
        &self.unwrapped_cache
    }

    /// Create a new Objects Store
    ///
    /// This function registers a new object store with the given prefix.
    /// The prefix is used to identify the object store in the database.
    /// The default object store is registered with an empty string as the prefix.
    ///
    /// # Arguments
    /// - `default_database` is the default database for objects without a prefix
    /// - `permissions_database` is the database for permissions
    /// - `cache_max_age` is the maximum age of unwrapped objects in the cache.
    fn new(
        default_objects_database: Arc<dyn ObjectsStore + Sync + Send>,
        permissions_database: Arc<dyn PermissionsStore + Sync + Send>,
        cache_max_age: Duration,
        kind: MainDbKind,
        health: Arc<dyn DatabaseHealth + Sync + Send>,
    ) -> Self {
        Self {
            objects: RwLock::new(HashMap::from([(String::new(), default_objects_database)])),
            permissions: permissions_database,
            unwrapped_cache: UnwrappedCache::new(cache_max_age),
            kind,
            health,
        }
    }

    #[must_use]
    pub const fn main_db_kind(&self) -> MainDbKind {
        self.kind
    }

    pub async fn health_check(&self) -> Result<(), String> {
        self.health.check().await
    }
}

struct SqliteHealthProbe {
    store: Arc<SqlitePool>,
}

impl SqliteHealthProbe {
    #[allow(clippy::missing_const_for_fn)]
    fn new(store: Arc<SqlitePool>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl DatabaseHealth for SqliteHealthProbe {
    async fn check(&self) -> Result<(), String> {
        self.store.health_check().await.map_err(|e| e.to_string())
    }
}

struct PgHealthProbe {
    store: Arc<PgPool>,
}

impl PgHealthProbe {
    #[allow(clippy::missing_const_for_fn)]
    fn new(store: Arc<PgPool>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl DatabaseHealth for PgHealthProbe {
    async fn check(&self) -> Result<(), String> {
        self.store.health_check().await.map_err(|e| e.to_string())
    }
}

struct MySqlHealthProbe {
    store: Arc<MySqlPool>,
}

impl MySqlHealthProbe {
    #[allow(clippy::missing_const_for_fn)]
    fn new(store: Arc<MySqlPool>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl DatabaseHealth for MySqlHealthProbe {
    async fn check(&self) -> Result<(), String> {
        self.store.health_check().await.map_err(|e| e.to_string())
    }
}

#[cfg(feature = "non-fips")]
struct RedisFindexHealthProbe {
    store: Arc<RedisWithFindex>,
}

#[cfg(feature = "non-fips")]
impl RedisFindexHealthProbe {
    #[allow(clippy::missing_const_for_fn)]
    fn new(store: Arc<RedisWithFindex>) -> Self {
        Self { store }
    }
}

#[cfg(feature = "non-fips")]
#[async_trait::async_trait]
impl DatabaseHealth for RedisFindexHealthProbe {
    async fn check(&self) -> Result<(), String> {
        let mut mgr = self.store.mgr.clone();
        let pong: String = mgr.ping().await.map_err(|e| e.to_string())?;
        #[allow(clippy::manual_ignore_case_cmp)]
        if pong.eq_ignore_ascii_case("PONG") {
            Ok(())
        } else {
            Err(format!("unexpected redis ping response: {pong}"))
        }
    }
}
