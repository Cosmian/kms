//! This module contains the core database functionalities, including object management,
//! permission checks, and caching mechanisms for unwrapped keys.
mod database_objects;
pub(crate) use database_objects::extract_serial_hex_from_object;
mod database_permissions;
mod db_metrics;
use std::{collections::HashMap, future::Future, num::NonZeroUsize, sync::Arc, time::Duration};

use async_trait::async_trait;
#[cfg(feature = "non-fips")]
use cosmian_kms_crypto::reexport::cosmian_crypto_core::Secret;
use cosmian_kms_interfaces::{ObjectsStore, PermissionsStore};
pub use db_metrics::DbMetricsRecorder;
#[cfg(feature = "non-fips")]
use redis::AsyncCommands;
use tokio::sync::RwLock;

use crate::{CeremonyKeys, error::DbResult};

mod main_db_params;
pub use main_db_params::{AdditionalObjectStoresParams, MainDbParams, redact_connection_string};
pub(crate) mod fingerprinter;
mod object_cache;
mod rotate_name_cache;
mod unwrapped_cache;

pub use crate::core::{
    object_cache::ObjectCache,
    rotate_name_cache::RotateNameCache,
    unwrapped_cache::{CachedObject, UnwrappedCache},
};
#[cfg(feature = "non-fips")]
use crate::stores::RedisWithFindex;
use crate::stores::{MySqlPool, PgPool, SqlitePool};

/// Sizing and expiry settings shared by the unwrapped-key and object caches.
#[derive(Clone, Copy, Debug)]
pub struct CacheParams {
    /// Time-to-idle of cache entries.
    pub max_age: Duration,
    /// Maximum number of entries before LRU eviction.
    pub max_size: NonZeroUsize,
    /// Optional absolute time-to-live of entries.
    pub max_ttl: Option<Duration>,
    /// Disable the unwrapped-key cache.
    pub disabled: bool,
}

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

    /// LRU cache for `retrieve_object` results, eliminating repeated DB round-trips
    /// when the same key is used for consecutive cryptographic operations.
    object_cache: ObjectCache,

    /// Short-TTL cache for `find_by_rotate_name` results, eliminating repeated
    /// full HSM-slot scans (or SQL round-trips) when the same keyset is resolved
    /// on every delegated Sign/Verify call (see `rotate_name_cache` module docs).
    rotate_name_cache: RotateNameCache,

    /// The database kind for the default store (sqlite/postgres/mysql/redis-findex).
    kind: MainDbKind,

    /// A lightweight health probe for the default store.
    ///
    /// This enables server-side `/health` checks without exposing internal store types.
    health: Arc<dyn DatabaseHealth + Sync + Send>,

    /// Optional OTEL metrics recorder injected at construction time.
    ///
    /// When `None`, all metric recording is skipped without any overhead.
    /// The concrete implementation lives in the `server` crate to avoid a
    /// dependency cycle.
    recorder: Option<Arc<dyn DbMetricsRecorder>>,

    /// Ceremony record encryption keys (derived from `ceremony_secret`).
    ///
    /// When `Some`, ceremony records are AES-256-GCM sealed before storage and
    /// verified on read. When `None`, ceremony operations will fail if attempted.
    pub(crate) ceremony_keys: Option<Arc<CeremonyKeys>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainDbKind {
    Sqlite,
    Postgres,
    Mysql,
    #[cfg(feature = "non-fips")]
    RedisFindex,
}

impl MainDbKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgresql",
            Self::Mysql => "mysql",
            #[cfg(feature = "non-fips")]
            Self::RedisFindex => "redis",
        }
    }
}

/// A live KMS node advertised by the cluster heartbeat table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterNode {
    /// Process-specific identifier generated at server startup.
    pub node_id: String,
    /// KMS package version reported by the node.
    pub version: String,
    /// Last heartbeat as a Unix timestamp in seconds.
    pub last_heartbeat: i64,
    /// Whether this node is the active cluster leader.
    pub is_leader: bool,
}

#[async_trait]
trait DatabaseHealth {
    async fn check(&self) -> Result<(), String>;

    async fn try_acquire_cron_lock(
        &self,
        lock_name: &str,
    ) -> DbResult<Option<Box<dyn ClusterLockGuard>>>;

    async fn record_cluster_heartbeat(
        &self,
        node_id: &str,
        version: &str,
        last_heartbeat: i64,
        is_leader: bool,
        stale_before: i64,
    ) -> DbResult<()>;

    async fn list_cluster_nodes(&self, minimum_heartbeat: i64) -> DbResult<Vec<ClusterNode>>;
}

/// Dedicated connections reserved for cron locks. Each held lock pins one connection, and cron
/// jobs run concurrently, so this must exceed the number of distinct lock names (currently 5);
/// otherwise a long job would block the leader-election heartbeat.
pub(crate) const CRON_LOCK_CONNECTIONS: usize = 8;

#[async_trait]
pub(crate) trait ClusterLockGuard: Send {
    async fn release(self: Box<Self>) -> DbResult<()>;
}

struct NoopClusterLockGuard;

#[async_trait]
impl ClusterLockGuard for NoopClusterLockGuard {
    async fn release(self: Box<Self>) -> DbResult<()> {
        Ok(())
    }
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
    /// - `cache` holds the unwrapped-object and object cache settings.
    pub async fn instantiate(
        main_db_params: &MainDbParams,
        clear_db_on_start: bool,
        object_stores: HashMap<String, Arc<dyn ObjectsStore + Sync + Send>>,
        cache: CacheParams,
        recorder: Option<Arc<dyn DbMetricsRecorder>>,
        ceremony_keys: Option<Arc<CeremonyKeys>>,
    ) -> DbResult<Self> {
        // main/default database
        let mut db = Self::instantiate_main_database(
            main_db_params,
            clear_db_on_start,
            cache,
            ceremony_keys,
        )
        .await?;
        db.recorder = recorder;
        for (prefix, store) in object_stores {
            db.register_objects_store(&prefix, store).await;
        }
        Ok(db)
    }

    async fn instantiate_main_database(
        main_db_params: &MainDbParams,
        clear_db_on_start: bool,
        cache: CacheParams,
        ceremony_keys: Option<Arc<CeremonyKeys>>,
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
                    cache,
                    MainDbKind::Sqlite,
                    health,
                    ceremony_keys,
                ))
            }
            MainDbParams::Postgres(url, max_conns) => {
                let db = Arc::new(PgPool::instantiate(url, clear_db_on_start, *max_conns).await?);
                let health = Arc::new(PgHealthProbe::new(db.clone()));
                Ok(Self::new(
                    db.clone(),
                    db,
                    cache,
                    MainDbKind::Postgres,
                    health,
                    ceremony_keys,
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
                    cache,
                    MainDbKind::Mysql,
                    health,
                    ceremony_keys,
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
                    cache,
                    MainDbKind::RedisFindex,
                    health,
                    ceremony_keys,
                ))
            }
        }
    }

    pub const fn unwrapped_cache(&self) -> &UnwrappedCache {
        &self.unwrapped_cache
    }

    pub const fn object_cache(&self) -> &ObjectCache {
        &self.object_cache
    }

    /// Cache of [`Self::find_by_rotate_name`] results.
    pub const fn rotate_name_cache(&self) -> &RotateNameCache {
        &self.rotate_name_cache
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
    /// - `cache` configures the unwrapped-objects and object caches.
    fn new(
        default_objects_database: Arc<dyn ObjectsStore + Sync + Send>,
        permissions_database: Arc<dyn PermissionsStore + Sync + Send>,
        cache: CacheParams,
        kind: MainDbKind,
        health: Arc<dyn DatabaseHealth + Sync + Send>,
        ceremony_keys: Option<Arc<CeremonyKeys>>,
    ) -> Self {
        Self {
            objects: RwLock::new(HashMap::from([(String::new(), default_objects_database)])),
            permissions: permissions_database,
            unwrapped_cache: UnwrappedCache::new(
                cache.max_age,
                cache.max_size,
                cache.max_ttl,
                cache.disabled,
            ),
            object_cache: ObjectCache::new(cache.max_age, cache.max_size, cache.max_ttl),
            rotate_name_cache: RotateNameCache::new(),
            kind,
            health,
            recorder: None,
            ceremony_keys,
        }
    }

    #[must_use]
    pub const fn main_db_kind(&self) -> MainDbKind {
        self.kind
    }

    /// Replace the ceremony encryption keys after post-init resolution.
    ///
    /// Used when `ceremony_key_id` is set: the raw AES key is fetched from the
    /// object store after the database is initialized, and the derived
    /// `CeremonyKeys` are installed here before the server starts handling
    /// requests.
    pub fn set_ceremony_keys(&mut self, keys: Arc<CeremonyKeys>) {
        self.ceremony_keys = Some(keys);
    }

    pub async fn health_check(&self) -> Result<(), String> {
        self.health.check().await
    }

    /// Run one scheduled job only when this server acquires its database lock.
    ///
    /// `SQLite` uses a no-op lock because it is single-node only.
    ///
    /// shortcut: Redis remains uncoordinated; add a Redis lease if multi-node Redis cron support
    /// becomes part of the supported cluster backends.
    pub async fn with_cron_lock<F, Fut>(&self, lock_name: &str, action: F) -> DbResult<bool>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        let Some(lock) = self.health.try_acquire_cron_lock(lock_name).await? else {
            return Ok(false);
        };
        action().await;
        lock.release().await?;
        Ok(true)
    }

    /// Persist this server's heartbeat and remove expired node records.
    pub async fn record_cluster_heartbeat(
        &self,
        node_id: &str,
        version: &str,
        last_heartbeat: i64,
        is_leader: bool,
        stale_before: i64,
    ) -> DbResult<()> {
        self.health
            .record_cluster_heartbeat(node_id, version, last_heartbeat, is_leader, stale_before)
            .await
    }

    /// List cluster nodes whose heartbeat is newer than `minimum_heartbeat`.
    pub async fn list_cluster_nodes(&self, minimum_heartbeat: i64) -> DbResult<Vec<ClusterNode>> {
        self.health.list_cluster_nodes(minimum_heartbeat).await
    }

    /// Count all non-destroyed objects across all registered stores.
    ///
    /// Returns the total number of objects (all types) whose state is not `Destroyed`.
    pub async fn count_all_non_destroyed_objects(&self) -> DbResult<u64> {
        let map = self.objects.read().await;
        let mut total = 0_u64;
        for store in map.values() {
            total += store.count_all_non_destroyed().await?;
        }
        Ok(total)
    }

    /// Count non-destroyed key objects across all registered stores.
    ///
    /// Returns the number of key objects (symmetric, asymmetric) whose state is not `Destroyed`.
    pub async fn count_non_destroyed_key_objects(&self) -> DbResult<u64> {
        let map = self.objects.read().await;
        let mut total = 0_u64;
        for store in map.values() {
            total += store.count_non_destroyed_keys().await?;
        }
        Ok(total)
    }

    /// Reconcile all object-count metrics across all registered stores.
    ///
    /// For Redis-findex this rewrites the O(1) counter keys from a full SCAN;
    /// for SQL backends this is a no-op.
    pub async fn reconcile_all_object_counts(&self) -> DbResult<()> {
        let map = self.objects.read().await;
        for store in map.values() {
            store.reconcile_counts().await?;
        }
        Ok(())
    }
}

struct SqliteHealthProbe {
    store: Arc<SqlitePool>,
}

impl SqliteHealthProbe {
    const fn new(store: Arc<SqlitePool>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl DatabaseHealth for SqliteHealthProbe {
    async fn check(&self) -> Result<(), String> {
        self.store.health_check().await.map_err(|e| e.to_string())
    }

    async fn try_acquire_cron_lock(
        &self,
        _lock_name: &str,
    ) -> DbResult<Option<Box<dyn ClusterLockGuard>>> {
        Ok(Some(Box::new(NoopClusterLockGuard)))
    }

    async fn record_cluster_heartbeat(
        &self,
        node_id: &str,
        version: &str,
        last_heartbeat: i64,
        is_leader: bool,
        stale_before: i64,
    ) -> DbResult<()> {
        self.store
            .record_cluster_heartbeat(node_id, version, last_heartbeat, is_leader, stale_before)
            .await
    }

    async fn list_cluster_nodes(&self, minimum_heartbeat: i64) -> DbResult<Vec<ClusterNode>> {
        self.store.list_cluster_nodes(minimum_heartbeat).await
    }
}

struct PgHealthProbe {
    store: Arc<PgPool>,
}

impl PgHealthProbe {
    const fn new(store: Arc<PgPool>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl DatabaseHealth for PgHealthProbe {
    async fn check(&self) -> Result<(), String> {
        self.store.health_check().await.map_err(|e| e.to_string())
    }

    async fn try_acquire_cron_lock(
        &self,
        lock_name: &str,
    ) -> DbResult<Option<Box<dyn ClusterLockGuard>>> {
        self.store.try_acquire_cron_lock(lock_name).await
    }

    async fn record_cluster_heartbeat(
        &self,
        node_id: &str,
        version: &str,
        last_heartbeat: i64,
        is_leader: bool,
        stale_before: i64,
    ) -> DbResult<()> {
        self.store
            .record_cluster_heartbeat(node_id, version, last_heartbeat, is_leader, stale_before)
            .await
    }

    async fn list_cluster_nodes(&self, minimum_heartbeat: i64) -> DbResult<Vec<ClusterNode>> {
        self.store.list_cluster_nodes(minimum_heartbeat).await
    }
}

struct MySqlHealthProbe {
    store: Arc<MySqlPool>,
}

impl MySqlHealthProbe {
    const fn new(store: Arc<MySqlPool>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl DatabaseHealth for MySqlHealthProbe {
    async fn check(&self) -> Result<(), String> {
        self.store.health_check().await.map_err(|e| e.to_string())
    }

    async fn try_acquire_cron_lock(
        &self,
        lock_name: &str,
    ) -> DbResult<Option<Box<dyn ClusterLockGuard>>> {
        self.store.try_acquire_cron_lock(lock_name).await
    }

    async fn record_cluster_heartbeat(
        &self,
        node_id: &str,
        version: &str,
        last_heartbeat: i64,
        is_leader: bool,
        stale_before: i64,
    ) -> DbResult<()> {
        self.store
            .record_cluster_heartbeat(node_id, version, last_heartbeat, is_leader, stale_before)
            .await
    }

    async fn list_cluster_nodes(&self, minimum_heartbeat: i64) -> DbResult<Vec<ClusterNode>> {
        self.store.list_cluster_nodes(minimum_heartbeat).await
    }
}

#[cfg(feature = "non-fips")]
struct RedisFindexHealthProbe {
    store: Arc<RedisWithFindex>,
}

#[cfg(feature = "non-fips")]
impl RedisFindexHealthProbe {
    const fn new(store: Arc<RedisWithFindex>) -> Self {
        Self { store }
    }
}

#[cfg(feature = "non-fips")]
#[async_trait::async_trait]
impl DatabaseHealth for RedisFindexHealthProbe {
    async fn check(&self) -> Result<(), String> {
        let mut mgr = self.store.mgr.clone();
        let pong: String = mgr.ping().await.map_err(|e| e.to_string())?;
        // `eq_ignore_ascii_case` is clearer here than a case-insensitive match
        if pong.eq_ignore_ascii_case("PONG") {
            Ok(())
        } else {
            Err(format!("unexpected redis ping response: {pong}"))
        }
    }

    async fn try_acquire_cron_lock(
        &self,
        _lock_name: &str,
    ) -> DbResult<Option<Box<dyn ClusterLockGuard>>> {
        Ok(Some(Box::new(NoopClusterLockGuard)))
    }

    async fn record_cluster_heartbeat(
        &self,
        _node_id: &str,
        _version: &str,
        _last_heartbeat: i64,
        _is_leader: bool,
        _stale_before: i64,
    ) -> DbResult<()> {
        Ok(())
    }

    async fn list_cluster_nodes(&self, _minimum_heartbeat: i64) -> DbResult<Vec<ClusterNode>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;

    use tokio::time::{sleep, timeout};

    use super::*;

    async fn instantiate(params: &MainDbParams, clear_db_on_start: bool) -> Database {
        Database::instantiate(
            params,
            clear_db_on_start,
            HashMap::new(),
            CacheParams {
                max_age: Duration::from_secs(60),
                max_size: NonZeroUsize::new(1).expect("nonzero cache size"),
                max_ttl: None,
                disabled: false,
            },
            None,
            None,
        )
        .await
        .expect("instantiate database")
    }

    async fn assert_heartbeats(database: &Database) {
        database
            .record_cluster_heartbeat("node-a", "1.0", 100, true, 0)
            .await
            .expect("record leader heartbeat");
        database
            .record_cluster_heartbeat("node-b", "1.0", 101, false, 0)
            .await
            .expect("record follower heartbeat");

        let nodes = database
            .list_cluster_nodes(0)
            .await
            .expect("list cluster nodes");
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().any(|n| n.node_id == "node-a" && n.is_leader));
        assert!(nodes.iter().any(|n| n.node_id == "node-b" && !n.is_leader));

        database
            .record_cluster_heartbeat("node-b", "1.0", 1_000, true, 500)
            .await
            .expect("elect node-b and prune stale node");
        let nodes = database
            .list_cluster_nodes(500)
            .await
            .expect("list live cluster nodes");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "node-b");
        assert!(nodes[0].is_leader);
    }

    /// Two servers sharing one database must never run the same job at the same time.
    async fn assert_cron_lock_exclusion(params: &MainDbParams) {
        let node_a = instantiate(params, true).await;
        let node_b = instantiate(params, false).await;

        let ran_by_a = node_a
            .with_cron_lock("job", || async {
                assert!(
                    !node_b
                        .with_cron_lock("job", || async {})
                        .await
                        .expect("contend for held lock")
                );
                // A job holding its lock must not block other lock names on the same server.
                let other = timeout(
                    Duration::from_secs(5),
                    node_a.with_cron_lock("other-job", || async {}),
                )
                .await
                .expect("a held lock must not starve other cron jobs")
                .expect("acquire another lock name");
                assert!(other);
            })
            .await
            .expect("acquire and release lock");
        assert!(ran_by_a);
        assert!(
            node_b
                .with_cron_lock("job", || async {})
                .await
                .expect("acquire released lock")
        );

        // A cancelled job (server shutdown) must free its lock for the other nodes.
        timeout(
            Duration::from_millis(200),
            node_a.with_cron_lock("job", pending::<()>),
        )
        .await
        .expect_err("a never-ending job must time out");
        let mut acquired = false;
        for _ in 0..50 {
            if node_b
                .with_cron_lock("job", || async {})
                .await
                .expect("retry after cancelled job")
            {
                acquired = true;
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        assert!(acquired, "cancelled job left its lock held");
    }

    #[tokio::test]
    async fn sqlite_cluster_heartbeat_and_cron_lock_round_trip() {
        let directory = tempfile::tempdir().expect("create temporary database directory");
        let params = MainDbParams::Sqlite(directory.path().to_path_buf(), Some(1));
        let database = instantiate(&params, false).await;

        assert!(
            database
                .with_cron_lock("test-job", || async {})
                .await
                .expect("run no-op SQLite cron lock")
        );
        assert_heartbeats(&database).await;
    }

    // docker run --name postgres -e POSTGRES_USER=kms -e POSTGRES_PASSWORD=kms -e POSTGRES_DB=kms -p 5432:5432 -d postgres
    #[ignore = "Requires a running PostgreSQL instance"]
    #[tokio::test]
    async fn postgres_cluster_heartbeat_and_cron_lock() {
        let url = option_env!("KMS_POSTGRES_URL")
            .unwrap_or("postgres://kms:kms@127.0.0.1:5432/kms")
            .to_owned();
        let params = MainDbParams::Postgres(url, None);
        assert_cron_lock_exclusion(&params).await;
        assert_heartbeats(&instantiate(&params, false).await).await;
    }

    // docker run --name mysql --env MYSQL_DATABASE=kms --env MYSQL_USER=kms --env MYSQL_PASSWORD=kms --env MYSQL_ROOT_PASSWORD=cosmian -p 3306:3306 -d mysql:8.0.42
    #[ignore = "Requires a running MySQL or MariaDB instance"]
    #[tokio::test]
    async fn mysql_cluster_heartbeat_and_cron_lock() {
        let url = option_env!("KMS_MYSQL_URL").unwrap_or("mysql://kms:kms@localhost:3306/kms");
        let params = MainDbParams::Mysql(url.parse().expect("valid MySQL URL"), None);
        assert_cron_lock_exclusion(&params).await;
        assert_heartbeats(&instantiate(&params, false).await).await;
    }
}

#[cfg(test)]
mod characterization_tests {
    //! Characterization tests pinning the BASE error behavior of the non-sqlite arms of
    //! `Database::instantiate` when the server is unreachable (no live server needed).

    use std::{collections::HashMap, num::NonZeroUsize, time::Duration};

    use url::Url;

    use super::{CacheParams, Database, MainDbParams};

    /// The ONLY place that calls `Database::instantiate` (its signature changes upstream).
    async fn instantiate_err(params: MainDbParams) -> String {
        Database::instantiate(
            &params,
            false,
            HashMap::new(),
            CacheParams {
                max_age: Duration::from_secs(1),
                max_size: NonZeroUsize::new(100).unwrap(),
                max_ttl: None,
                disabled: false,
            },
            None,
            None,
        )
        .await
        .err()
        .unwrap()
        .to_string()
    }

    #[tokio::test]
    async fn characterization_instantiate_postgres_unreachable_returns_error() {
        let err = instantiate_err(MainDbParams::Postgres(
            "postgres://127.0.0.1:1/kms".to_owned(),
            Some(1),
        ))
        .await;
        assert_eq!(
            err,
            "Sql error: Error occurred while creating a new object: error connecting to server"
        );
    }

    #[tokio::test]
    async fn characterization_instantiate_mysql_unreachable_returns_error() {
        let err = instantiate_err(MainDbParams::Mysql(
            Url::parse("mysql://user:pass@127.0.0.1:1/kms").unwrap(),
            Some(1),
        ))
        .await;
        // the refusal text and errno are OS specific (61/111 on macOS/Linux, 10061 on Windows)
        assert!(err.starts_with("Sql error: Input/output error: Input/output error: "));
    }
}
