use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{KmipOperation, kmip_attributes::Attributes, kmip_objects::Object},
};
use cosmian_kms_interfaces::{
    AtomicOperation, InterfaceError, InterfaceResult, ObjectWithMetadata, ObjectsStore,
    PermissionsStore,
};
use deadpool_postgres::{Config as PgConfig, ManagerConfig, Pool, RecyclingMethod};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};
use postgres_openssl::MakeTlsConnector;
use rawsql::Loader;
use serde_json::Value;
use tokio_postgres::{
    NoTls,
    types::{Json, ToSql},
};
use uuid::Uuid;

use crate::{
    db_error,
    error::{DbError, DbResult},
    migrate_block_cipher_mode_if_needed,
    stores::{
        PGSQL_QUERIES,
        migrate::{DbState, Migrate},
        sql::database::SqlDatabase,
    },
};

// Retry parameters for transient PostgreSQL errors (deadlocks, serialization,
// and connection failures during failover).
const PG_MAX_RETRIES: u32 = 6;

fn is_pg_retryable_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    // Deadlock / serialization (SQLSTATE 40P01, 40001)
    lower.contains("deadlock detected")
        || lower.contains("40p01")
        || lower.contains("serialization failure")
        || lower.contains("40001")
        // Connection errors (failover / network)
        || lower.contains("connection refused")
        || lower.contains("connection reset")
        || lower.contains("connection closed")
        || lower.contains("broken pipe")
        || lower.contains("server closed the connection unexpectedly")
        || lower.contains("terminating connection")
        || lower.contains("could not connect to server")
        || lower.contains("08003") // SQLSTATE connection_does_not_exist
        || lower.contains("08006") // SQLSTATE connection_failure
        || lower.contains("57p01") // SQLSTATE admin_shutdown
        || lower.contains("08001") // SQLSTATE connection_exception
        || lower.contains("08004") // SQLSTATE connection_rejected
        || lower.contains("57p02") // SQLSTATE crash_shutdown
        || lower.contains("57p03") // SQLSTATE cannot_connect_now
}

fn pg_retry_backoff_ms(attempt: u32) -> u64 {
    let cap = attempt.min(PG_MAX_RETRIES);
    50_u64 * (1_u64 << cap)
}

/// Get a client from the pool, retrying on transient connection errors.
/// Used by Migrate trait methods for startup resilience.
async fn pg_get_client(pool: &deadpool_postgres::Pool) -> DbResult<deadpool_postgres::Object> {
    for attempt in 0..PG_MAX_RETRIES {
        match pool.get().await {
            Ok(client) => return Ok(client),
            Err(e) if is_pg_retryable_error(&e.to_string()) && attempt + 1 < PG_MAX_RETRIES => {
                let delay = pg_retry_backoff_ms(attempt);
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
            Err(e) => return Err(DbError::from(e)),
        }
    }
    Err(DbError::DatabaseError("too many retry attempts".to_owned()))
}

/// Single-attempt connection acquisition for use inside `pg_retry_tx!`.
/// On retryable failure, sleeps (backoff) then returns Err so the outer loop
/// can check retryability and continue. On non-retryable failure, returns Err
/// immediately.
async fn pg_get_client_for_tx(
    pool: &deadpool_postgres::Pool,
    attempt: u32,
) -> DbResult<deadpool_postgres::Object> {
    match pool.get().await {
        Ok(client) => Ok(client),
        Err(e) if is_pg_retryable_error(&e.to_string()) && attempt + 1 < PG_MAX_RETRIES => {
            let delay = pg_retry_backoff_ms(attempt);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            Err(DbError::from(e))
        }
        Err(e) => Err(DbError::from(e)),
    }
}

/// Retry an operation on transient connection errors (e.g. during failover).
/// Each attempt gets a fresh connection from the pool so multi-host URLs can resolve
/// to the new primary.
macro_rules! pg_retry {
    ($pool:expr, |$client:ident| $body:expr) => {{
        let mut last_err: Option<InterfaceError> = None;
        for attempt in 0..PG_MAX_RETRIES {
            match $pool.get().await {
                Ok($client) => {
                    let result: InterfaceResult<_> = (async { $body }).await;
                    match result {
                        Ok(v) => return Ok(v),
                        Err(e) => {
                            if is_pg_retryable_error(&e.to_string()) && attempt + 1 < PG_MAX_RETRIES
                            {
                                let delay_ms = pg_retry_backoff_ms(attempt);
                                tokio::time::sleep(std::time::Duration::from_millis(delay_ms))
                                    .await;
                                last_err = Some(e);
                                continue;
                            }
                            return Err(e);
                        }
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    if is_pg_retryable_error(&msg) && attempt + 1 < PG_MAX_RETRIES {
                        let delay_ms = pg_retry_backoff_ms(attempt);
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                        last_err = Some(InterfaceError::from(DbError::from(e)));
                        continue;
                    }
                    return Err(InterfaceError::from(DbError::from(e)));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            InterfaceError::from(DbError::DatabaseError("too many retry attempts".to_owned()))
        }))
    }};
}

/// Retry a transactional operation on transient errors.
/// Gets a fresh connection and starts a new transaction on each retry.
/// Uses `pg_get_client_for_tx` for connection acquisition with backoff.
macro_rules! pg_retry_tx {
    ($pool:expr, |$tx:ident| $body:expr) => {{
        for attempt in 0..PG_MAX_RETRIES {
            let mut client = match pg_get_client_for_tx(&$pool, attempt).await {
                Ok(c) => c,
                Err(e) => {
                    if is_pg_retryable_error(&e.to_string()) && attempt + 1 < PG_MAX_RETRIES {
                        continue;
                    }
                    return Err(InterfaceError::from(e));
                }
            };
            let $tx = match client.transaction().await {
                Ok(tx) => tx,
                Err(e) => {
                    if is_pg_retryable_error(&e.to_string()) && attempt + 1 < PG_MAX_RETRIES {
                        let delay_ms = pg_retry_backoff_ms(attempt);
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(InterfaceError::from(DbError::from(e)));
                }
            };
            match (async { $body }).await {
                Ok(v) => match $tx.commit().await {
                    Ok(()) => return Ok(v),
                    Err(e) => {
                        let msg = e.to_string();
                        if is_pg_retryable_error(&msg) && attempt + 1 < PG_MAX_RETRIES {
                            let delay_ms = pg_retry_backoff_ms(attempt);
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                        return Err(InterfaceError::from(DbError::from(e)));
                    }
                },
                Err(e) => {
                    if is_pg_retryable_error(&e.to_string()) && attempt + 1 < PG_MAX_RETRIES {
                        let delay_ms = pg_retry_backoff_ms(attempt);
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(InterfaceError::from(e));
                }
            }
        }
        Err(InterfaceError::from(DbError::DatabaseError(
            "too much contention: too many attempts".to_owned(),
        )))
    }};
}

macro_rules! get_pgsql_query {
    ($name:literal) => {
        PGSQL_QUERIES
            .get($name)
            .ok_or_else(|| db_error!("{} SQL query can't be found", $name))?
    };
}

#[derive(Clone)]
pub(crate) struct PgPool {
    pool: Pool,
}

impl PgPool {
    pub(crate) async fn instantiate(
        connection_url: &str,
        clear_database: bool,
        max_connections: Option<u32>,
    ) -> DbResult<Self> {
        // Extract query parameters manually instead of using Url::parse(),
        // which cannot handle multi-host PostgreSQL connection strings
        // (e.g. "postgresql://user:pass@host1:5432,host2:5432/db?target_session_attrs=read-write").
        let query_params = extract_query_params(connection_url);

        // Build a URL that strips only SSL-related params (handled via MakeTlsConnector)
        // but preserves other params like target_session_attrs for tokio-postgres.
        let clean_url_str = rebuild_url_without_ssl_params(connection_url, &query_params);

        let mut cfg = PgConfig::new();
        cfg.url = Some(clean_url_str);
        cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });

        // Pool sizing defaults: conservative pool tuned to CPU.
        // Keep behavior consistent with the MySQL backend.
        let default_conns: usize = num_cpus::get().saturating_mul(2).min(10);
        let max_conns: usize = max_connections
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(default_conns);
        cfg.pool = Some(deadpool_postgres::PoolConfig {
            max_size: max_conns,
            ..Default::default()
        });

        // Check sslmode parameter (disable, allow, prefer, require, verify-ca, verify-full)
        let sslmode = query_params.get("sslmode").map_or("prefer", String::as_str);

        let pool = if sslmode == "disable" {
            // Explicitly no TLS
            cfg.create_pool(None, NoTls)
                .map_err(|e| DbError::DatabaseError(e.to_string()))?
        } else {
            // Build TLS connector for require, verify-ca, verify-full, prefer, allow
            let mut builder = SslConnector::builder(SslMethod::tls())
                .map_err(|e| DbError::DatabaseError(format!("TLS setup failed: {e}")))?;

            // Set verification mode based on sslmode
            match sslmode {
                "verify-full" => {
                    // verify-full: verify certificate AND hostname
                    builder.set_verify(SslVerifyMode::PEER);
                }
                "verify-ca" => {
                    // verify-ca: verify certificate but NOT hostname
                    builder.set_verify(SslVerifyMode::PEER);
                    // For verify-ca, we don't want hostname verification
                    // This is handled by not setting any hostname verification parameters
                }
                _ => {
                    // require, prefer, allow: connect with TLS but don't verify cert
                    builder.set_verify(SslVerifyMode::NONE);
                }
            }

            // Load CA cert if provided (sslrootcert)
            if let Some(ca_file) = query_params.get("sslrootcert") {
                builder
                    .set_ca_file(ca_file.as_str())
                    .map_err(|e| DbError::DatabaseError(format!("Failed to load CA: {e}")))?;
            }

            // Load client cert/key for mutual TLS (sslcert, sslkey)
            if let Some(cert_file) = query_params.get("sslcert") {
                builder
                    .set_certificate_file(cert_file.as_str(), SslFiletype::PEM)
                    .map_err(|e| {
                        DbError::DatabaseError(format!("Failed to load client cert: {e}"))
                    })?;
            }
            if let Some(key_file) = query_params.get("sslkey") {
                builder
                    .set_private_key_file(key_file.as_str(), SslFiletype::PEM)
                    .map_err(|e| {
                        DbError::DatabaseError(format!("Failed to load client key: {e}"))
                    })?;
            }

            let connector = MakeTlsConnector::new(builder.build());
            cfg.create_pool(None, connector)
                .map_err(|e| DbError::DatabaseError(e.to_string()))?
        };

        let client = pool.get().await.map_err(DbError::from)?;
        // Bootstrap schema if needed: create tables if they don't exist
        let tmp_loader = Self { pool: pool.clone() };
        for name in [
            "create-table-parameters",
            "create-table-objects",
            "create-table-read_access",
            "create-table-tags",
        ] {
            let sql = tmp_loader.get_query(name)?;
            client.batch_execute(sql).await.map_err(DbError::from)?;
        }
        // Ensure attributes column is jsonb (and convert if needed)
        client
            .batch_execute(
                "ALTER TABLE objects ALTER COLUMN attributes TYPE jsonb USING attributes::jsonb;",
            )
            .await
            .map_err(DbError::from)?;

        // Optionally clear any existing data (useful for tests)
        if clear_database {
            for name in [
                // Remove dependent rows first to avoid potential constraints if present
                "clean-table-read_access",
                "clean-table-tags",
                "clean-table-objects",
            ] {
                let sql = tmp_loader.get_query(name)?;
                client.batch_execute(sql).await.map_err(DbError::from)?;
            }
            let tmp = Self { pool: pool.clone() };
            tmp.set_current_db_version(env!("CARGO_PKG_VERSION"))
                .await?;
            tmp.set_db_state(DbState::Ready).await?;
        }
        Ok(Self { pool })
    }

    pub(crate) async fn health_check(&self) -> DbResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DbError::DatabaseError(e.to_string()))?;
        client
            .query_one("SELECT 1", &[])
            .await
            .map(|_| ())
            .map_err(|e| DbError::DatabaseError(e.to_string()))
    }
}

impl SqlDatabase for PgPool {
    fn get_loader(&self) -> &Loader {
        &PGSQL_QUERIES
    }
}

#[async_trait(?Send)]
impl ObjectsStore for PgPool {
    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
    ) -> InterfaceResult<String> {
        async fn transact(
            tx: &tokio_postgres::Transaction<'_>,
            uid: &str,
            owner: &str,
            object: &Object,
            attributes: &Attributes,
            tags: &HashSet<String>,
        ) -> DbResult<String> {
            let object_json = serde_json::to_string(object).map_err(DbError::from)?;
            let attributes_json = serde_json::to_value(attributes).map_err(DbError::from)?;
            let state = attributes.state.unwrap_or(State::PreActive).to_string();
            let stmt = tx
                .prepare(get_pgsql_query!("insert-objects"))
                .await
                .map_err(DbError::from)?;
            let attrs_param = Json(&attributes_json);
            tx.execute(&stmt, &[&uid, &object_json, &attrs_param, &state, &owner])
                .await
                .map_err(DbError::from)?;
            if !tags.is_empty() {
                let transaction_stmt = tx
                    .prepare(get_pgsql_query!("insert-tags"))
                    .await
                    .map_err(DbError::from)?;
                for tag in tags {
                    tx.execute(&transaction_stmt, &[&uid, tag])
                        .await
                        .map_err(DbError::from)?;
                }
            }
            Ok(uid.to_owned())
        }

        let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());
        pg_retry_tx!(self.pool, |tx| {
            transact(&tx, &uid, owner, object, attributes, tags).await
        })
    }

    async fn retrieve(&self, uid: &str) -> InterfaceResult<Option<ObjectWithMetadata>> {
        pg_retry!(self.pool, |client| {
            let stmt = client
                .prepare(get_pgsql_query!("select-object"))
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let rows = client
                .query(&stmt, &[&uid])
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            if let Some(row) = rows.first() {
                let id: String = row.get(0);
                let object_json: String = row.get(1);
                let object: Object = serde_json::from_str(&object_json)
                    .map_err(|e| InterfaceError::from(DbError::from(e)))?;
                let object = migrate_block_cipher_mode_if_needed(object);
                let attributes_val: Value = row.get(2);
                let attributes: Attributes = serde_json::from_value(attributes_val)
                    .map_err(|e| InterfaceError::from(DbError::from(e)))?;
                let owner: String = row.get(3);
                let state_str: String = row.get(4);
                let state = State::try_from(state_str.as_str())
                    .map_err(|e| InterfaceError::from(DbError::from(e)))?;
                Ok(Some(ObjectWithMetadata::new(
                    id, object, owner, state, attributes,
                )))
            } else {
                Ok(None)
            }
        })
    }

    async fn retrieve_tags(&self, uid: &str) -> InterfaceResult<HashSet<String>> {
        pg_retry!(self.pool, |client| {
            let stmt = client
                .prepare(get_pgsql_query!("select-tags"))
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let rows = client
                .query(&stmt, &[&uid])
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
        })
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
    ) -> InterfaceResult<()> {
        async fn transact(
            tx: &tokio_postgres::Transaction<'_>,
            uid: &str,
            object: &Object,
            attributes: &Attributes,
            tags: Option<&HashSet<String>>,
        ) -> DbResult<()> {
            let object_json = serde_json::to_string(object).map_err(DbError::from)?;
            let attributes_json = serde_json::to_value(attributes).map_err(DbError::from)?;
            let stmt = tx
                .prepare(get_pgsql_query!("update-object-with-object"))
                .await
                .map_err(DbError::from)?;
            let attrs_param = Json(&attributes_json);
            tx.execute(&stmt, &[&object_json, &attrs_param, &uid])
                .await
                .map_err(DbError::from)?;
            if let Some(tags) = tags {
                let delete_stmt = tx
                    .prepare(get_pgsql_query!("delete-tags"))
                    .await
                    .map_err(DbError::from)?;
                tx.execute(&delete_stmt, &[&uid])
                    .await
                    .map_err(DbError::from)?;
                let insert_stmt = tx
                    .prepare(get_pgsql_query!("insert-tags"))
                    .await
                    .map_err(DbError::from)?;
                for tag in tags {
                    tx.execute(&insert_stmt, &[&uid, tag])
                        .await
                        .map_err(DbError::from)?;
                }
            }
            Ok(())
        }

        pg_retry_tx!(self.pool, |tx| {
            transact(&tx, uid, object, attributes, tags).await
        })
    }

    async fn update_state(&self, uid: &str, state: State) -> InterfaceResult<()> {
        pg_retry!(self.pool, |client| {
            let stmt = client
                .prepare(get_pgsql_query!("update-object-with-state"))
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let s = state.to_string();
            client
                .execute(&stmt, &[&s, &uid])
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            Ok(())
        })
    }

    async fn delete(&self, uid: &str) -> InterfaceResult<()> {
        async fn transact(tx: &tokio_postgres::Transaction<'_>, uid: &str) -> DbResult<()> {
            let d1 = tx
                .prepare(get_pgsql_query!("delete-object"))
                .await
                .map_err(DbError::from)?;
            tx.execute(&d1, &[&uid]).await.map_err(DbError::from)?;
            let d2 = tx
                .prepare(get_pgsql_query!("delete-tags"))
                .await
                .map_err(DbError::from)?;
            tx.execute(&d2, &[&uid]).await.map_err(DbError::from)?;
            Ok(())
        }
        pg_retry_tx!(self.pool, |tx| transact(&tx, uid).await)
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
    ) -> InterfaceResult<Vec<String>> {
        async fn transact(
            tx: &tokio_postgres::Transaction<'_>,
            user: &str,
            operations: &[AtomicOperation],
        ) -> DbResult<Vec<String>> {
            let mut uids = Vec::with_capacity(operations.len());
            for op in operations {
                match op {
                    AtomicOperation::Create((uid, object, attributes, tags)) => {
                        // inline create within same transaction
                        let object_json = serde_json::to_string(object).map_err(DbError::from)?;
                        let attributes_json =
                            serde_json::to_value(attributes).map_err(DbError::from)?;
                        let state = attributes.state.unwrap_or(State::PreActive).to_string();
                        let stmt = tx
                            .prepare(get_pgsql_query!("insert-objects"))
                            .await
                            .map_err(DbError::from)?;
                        let attrs_param = Json(&attributes_json);
                        tx.execute(&stmt, &[&uid, &object_json, &attrs_param, &state, &user])
                            .await
                            .map_err(DbError::from)?;
                        if !tags.is_empty() {
                            let insert_stmt = tx
                                .prepare(get_pgsql_query!("insert-tags"))
                                .await
                                .map_err(DbError::from)?;
                            for tag in tags {
                                tx.execute(&insert_stmt, &[&uid, tag])
                                    .await
                                    .map_err(DbError::from)?;
                            }
                        }
                        uids.push(uid.clone());
                    }
                    AtomicOperation::UpdateObject((uid, object, attributes, tags)) => {
                        let object_json = serde_json::to_string(object).map_err(DbError::from)?;
                        let attributes_json =
                            serde_json::to_value(attributes).map_err(DbError::from)?;
                        let stmt = tx
                            .prepare(get_pgsql_query!("update-object-with-object"))
                            .await
                            .map_err(DbError::from)?;
                        let attrs_param = Json(&attributes_json);
                        tx.execute(&stmt, &[&object_json, &attrs_param, &uid])
                            .await
                            .map_err(DbError::from)?;
                        if let Some(tags) = tags {
                            let delete_stmt = tx
                                .prepare(get_pgsql_query!("delete-tags"))
                                .await
                                .map_err(DbError::from)?;
                            tx.execute(&delete_stmt, &[&uid])
                                .await
                                .map_err(DbError::from)?;
                            let insert_stmt = tx
                                .prepare(get_pgsql_query!("insert-tags"))
                                .await
                                .map_err(DbError::from)?;
                            for tag in tags {
                                tx.execute(&insert_stmt, &[&uid, tag])
                                    .await
                                    .map_err(DbError::from)?;
                            }
                        }
                        uids.push(uid.clone());
                    }
                    AtomicOperation::UpdateState((uid, state)) => {
                        let stmt = tx
                            .prepare(get_pgsql_query!("update-object-with-state"))
                            .await
                            .map_err(DbError::from)?;
                        let st = state.to_string();
                        tx.execute(&stmt, &[&st, &uid])
                            .await
                            .map_err(DbError::from)?;
                        uids.push(uid.clone());
                    }
                    AtomicOperation::Upsert((uid, object, attributes, tags, state)) => {
                        let object_json = serde_json::to_string(object).map_err(DbError::from)?;
                        let attributes_json =
                            serde_json::to_value(attributes).map_err(DbError::from)?;
                        let stmt = tx
                            .prepare(get_pgsql_query!("upsert-object"))
                            .await
                            .map_err(DbError::from)?;
                        let st = state.to_string();
                        let attrs_param = Json(&attributes_json);
                        tx.execute(&stmt, &[&uid, &object_json, &attrs_param, &st, &user])
                            .await
                            .map_err(DbError::from)?;
                        if let Some(tags) = tags {
                            let delete_stmt = tx
                                .prepare(get_pgsql_query!("delete-tags"))
                                .await
                                .map_err(DbError::from)?;
                            tx.execute(&delete_stmt, &[&uid])
                                .await
                                .map_err(DbError::from)?;
                            let insert_stmt = tx
                                .prepare(get_pgsql_query!("insert-tags"))
                                .await
                                .map_err(DbError::from)?;
                            for tag in tags {
                                tx.execute(&insert_stmt, &[&uid, tag])
                                    .await
                                    .map_err(DbError::from)?;
                            }
                        }
                        uids.push(uid.clone());
                    }
                    AtomicOperation::Delete(uid) => {
                        let d1 = tx
                            .prepare(get_pgsql_query!("delete-object"))
                            .await
                            .map_err(DbError::from)?;
                        tx.execute(&d1, &[&uid]).await.map_err(DbError::from)?;
                        let d2 = tx
                            .prepare(get_pgsql_query!("delete-tags"))
                            .await
                            .map_err(DbError::from)?;
                        tx.execute(&d2, &[&uid]).await.map_err(DbError::from)?;
                        uids.push(uid.clone());
                    }
                }
            }
            Ok(uids)
        }

        pg_retry_tx!(self.pool, |tx| transact(&tx, user, operations).await)
    }

    async fn is_object_owned_by(&self, uid: &str, owner: &str) -> InterfaceResult<bool> {
        pg_retry!(self.pool, |client| {
            let stmt = client
                .prepare(get_pgsql_query!("has-row-objects"))
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let row = client
                .query_opt(&stmt, &[&uid, &owner])
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            Ok(row.is_some())
        })
    }

    async fn list_uids_for_tags(&self, tags: &HashSet<String>) -> InterfaceResult<HashSet<String>> {
        pg_retry!(self.pool, |client| {
            // Use ANY($1) with text[] to avoid dynamic placeholder lifetimes
            let sql = "SELECT id FROM tags WHERE tag = ANY($1::text[]) GROUP BY id HAVING COUNT(DISTINCT tag) = $2::int";
            let mut tag_vec: Vec<String> = tags.iter().cloned().collect();
            tag_vec.sort();
            let tag_refs: Vec<&str> = tag_vec.iter().map(String::as_str).collect();
            let len_i32: i32 =
                i32::try_from(tags.len()).map_err(|e| InterfaceError::Db(e.to_string()))?;
            let rows = client
                .query(sql, &[&&tag_refs[..], &len_i32])
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let mut out = HashSet::new();
            for r in rows {
                out.insert(r.get::<_, String>(0));
            }
            Ok(out)
        })
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        user: &str,
        user_must_be_owner: bool,
        vendor_id: &str,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        pg_retry!(self.pool, |client| {
            let locate = crate::stores::sql::locate_query::query_from_attributes::<
                crate::stores::sql::locate_query::PgSqlPlaceholder,
            >(
                researched_attributes,
                state,
                user,
                user_must_be_owner,
                vendor_id,
            );
            cosmian_logger::debug!("PG find query: {}", locate.sql);
            let stmt = client
                .prepare(&locate.sql)
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let mut owned: Vec<Box<dyn ToSql + Sync>> = Vec::with_capacity(locate.params.len());
            for p in locate.params {
                match p {
                    crate::stores::sql::locate_query::LocateParam::Text(s) => {
                        owned.push(Box::new(s));
                    }
                    crate::stores::sql::locate_query::LocateParam::I64(i) => {
                        owned.push(Box::new(i));
                    }
                }
            }
            let params: Vec<&(dyn ToSql + Sync)> =
                owned.iter().map(std::convert::AsRef::as_ref).collect();
            let rows = client
                .query(&stmt, &params)
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let mut out = Vec::new();
            for row in rows {
                let uid: String = row.get(0);
                let state_str: String = row.get(1);
                let state = State::try_from(state_str.as_str())
                    .map_err(|e| InterfaceError::from(DbError::from(e)))?;
                let attrs_val: Value = row.get(2);
                let attrs: Attributes = serde_json::from_value(attrs_val)
                    .map_err(|e| InterfaceError::from(DbError::from(e)))?;
                out.push((uid, state, attrs));
            }
            Ok(out)
        })
    }
}

#[async_trait(?Send)]
impl Migrate for PgPool {
    async fn get_db_state(&self) -> DbResult<Option<DbState>> {
        let client = pg_get_client(&self.pool).await?;
        let sql = get_pgsql_query!("select-parameter");
        let row_opt = client
            .query_opt(sql, &[&"db_state"])
            .await
            .map_err(DbError::from)?;
        if let Some(row) = row_opt {
            let s: String = row.get(0);
            Ok(Some(serde_json::from_str(&s)?))
        } else {
            Ok(None)
        }
    }

    async fn set_db_state(&self, state: DbState) -> DbResult<()> {
        let client = pg_get_client(&self.pool).await?;
        let sql = get_pgsql_query!("upsert-parameter");
        let state_json = serde_json::to_string(&state)?;
        client
            .execute(sql, &[&"db_state", &state_json])
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn get_current_db_version(&self) -> DbResult<Option<String>> {
        let client = pg_get_client(&self.pool).await?;
        let sql = get_pgsql_query!("select-parameter");
        let row_opt = client
            .query_opt(sql, &[&"db_version"])
            .await
            .map_err(DbError::from)?;
        Ok(row_opt.map(|row| row.get::<usize, String>(0)))
    }

    async fn set_current_db_version(&self, version: &str) -> DbResult<()> {
        let client = pg_get_client(&self.pool).await?;
        let sql = get_pgsql_query!("upsert-parameter");
        client
            .execute(sql, &[&"db_version", &version])
            .await
            .map_err(DbError::from)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl PermissionsStore for PgPool {
    async fn list_user_operations_granted(
        &self,
        user: &str,
    ) -> InterfaceResult<HashMap<String, (String, State, HashSet<KmipOperation>)>> {
        pg_retry!(self.pool, |client| {
            let stmt = client
                .prepare(get_pgsql_query!("select-objects-access-obtained"))
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let rows = client
                .query(&stmt, &[&user])
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let mut map = HashMap::with_capacity(rows.len());
            for row in rows {
                let id: String = row.get(0);
                let owner: String = row.get(1);
                let state_str: String = row.get(2);
                let state = State::try_from(state_str.as_str())
                    .map_err(|e| InterfaceError::Db(e.to_string()))?;
                let perms_val: Value = row.get(3);
                let perms: HashSet<KmipOperation> = serde_json::from_value(perms_val)
                    .map_err(|e| InterfaceError::Db(e.to_string()))?;
                map.insert(id, (owner, state, perms));
            }
            Ok(map)
        })
    }

    async fn list_object_operations_granted(
        &self,
        uid: &str,
    ) -> InterfaceResult<HashMap<String, HashSet<KmipOperation>>> {
        pg_retry!(self.pool, |client| {
            let stmt = client
                .prepare(get_pgsql_query!("select-rows-read_access-with-object-id"))
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let rows = client
                .query(&stmt, &[&uid])
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let mut map = HashMap::with_capacity(rows.len());
            for row in rows {
                let userid: String = row.get(0);
                let v: Value = row.get(1);
                let ops: HashSet<KmipOperation> =
                    serde_json::from_value(v).map_err(|e| InterfaceError::Db(e.to_string()))?;
                map.insert(userid, ops);
            }
            Ok(map)
        })
    }

    async fn grant_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()> {
        // Merge with existing permissions (this read is itself retried)
        let existing = self.list_user_operations_on_object(uid, user, true).await?;
        let mut combined = existing;
        combined.extend(operations);
        pg_retry!(self.pool, |client| {
            let json = serde_json::to_value(&combined)
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let stmt = client
                .prepare(get_pgsql_query!("upsert-row-read_access"))
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            client
                .execute(&stmt, &[&uid, &user, &json])
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            Ok(())
        })
    }

    async fn remove_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()> {
        let current = self.list_user_operations_on_object(uid, user, true).await?;
        let remaining: HashSet<KmipOperation> = current.difference(&operations).copied().collect();
        pg_retry!(self.pool, |client| {
            if remaining.is_empty() {
                let d = client
                    .prepare(get_pgsql_query!("delete-rows-read_access"))
                    .await
                    .map_err(|e| InterfaceError::from(DbError::from(e)))?;
                client
                    .execute(&d, &[&uid, &user])
                    .await
                    .map_err(|e| InterfaceError::from(DbError::from(e)))?;
                return Ok(());
            }
            let json = serde_json::to_value(&remaining)
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let u = client
                .prepare(get_pgsql_query!("update-rows-read_access-with-permission"))
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            client
                .execute(&u, &[&uid, &user, &json])
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            Ok(())
        })
    }

    async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
    ) -> InterfaceResult<HashSet<KmipOperation>> {
        pg_retry!(self.pool, |client| {
            let stmt = client
                .prepare(get_pgsql_query!("select-user-accesses-for-object"))
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let mut perms: HashSet<KmipOperation> = match client
                .query_opt(&stmt, &[&uid, &user])
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?
            {
                Some(row) => {
                    let v: Value = row.get(0);
                    serde_json::from_value(v).map_err(|e| InterfaceError::from(DbError::from(e)))?
                }
                None => HashSet::new(),
            };
            if !no_inherited_access && user != "*" {
                if let Some(row) = client
                    .query_opt(&stmt, &[&uid, &"*"])
                    .await
                    .map_err(|e| InterfaceError::from(DbError::from(e)))?
                {
                    let v: Value = row.get(0);
                    let all: HashSet<KmipOperation> = serde_json::from_value(v)
                        .map_err(|e| InterfaceError::from(DbError::from(e)))?;
                    perms.extend(all);
                }
            }
            Ok(perms)
        })
    }
}

// ---------------------------------------------------------------------------
// Multi-host URL helpers
// ---------------------------------------------------------------------------

/// SSL-related query parameters that are handled via `MakeTlsConnector`
/// and must be stripped from the URL before passing to `deadpool-postgres`.
const SSL_PARAMS: &[&str] = &["sslmode", "sslrootcert", "sslcert", "sslkey"];

/// Extract query parameters from a `PostgreSQL` connection URL by splitting on `?`/`&`.
/// This avoids `Url::parse()` which cannot handle multi-host connection strings.
fn extract_query_params(url: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    if let Some(query_start) = url.find('?') {
        let query = &url[query_start + 1..];
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                params.insert(key.to_owned(), value.to_owned());
            }
        }
    }
    params
}

/// Rebuild the connection URL, removing only SSL-related query parameters.
/// Other parameters like `target_session_attrs` are preserved for `tokio-postgres`.
fn rebuild_url_without_ssl_params(url: &str, params: &HashMap<String, String>) -> String {
    let base = url.split('?').next().unwrap_or(url);
    let non_ssl_params: Vec<String> = params
        .iter()
        .filter(|(k, _)| !SSL_PARAMS.contains(&k.as_str()))
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    if non_ssl_params.is_empty() {
        base.to_owned()
    } else {
        format!("{}?{}", base, non_ssl_params.join("&"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_query_params_single_host() {
        let url = "postgresql://kms:kms@localhost:5432/kms?sslmode=require";
        let params = extract_query_params(url);
        assert_eq!(params.get("sslmode"), Some(&"require".to_owned()));
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn test_extract_query_params_multi_host() {
        let url = "postgresql://kms:kms@host1:5432,host2:5432/kms?target_session_attrs=read-write&sslmode=require";
        let params = extract_query_params(url);
        assert_eq!(
            params.get("target_session_attrs"),
            Some(&"read-write".to_owned())
        );
        assert_eq!(params.get("sslmode"), Some(&"require".to_owned()));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn test_extract_query_params_no_params() {
        let url = "postgresql://kms:kms@localhost:5432/kms";
        let params = extract_query_params(url);
        assert!(params.is_empty());
    }

    #[test]
    fn test_rebuild_url_strips_only_ssl_params() {
        let url = "postgresql://kms:kms@host1:5432,host2:5432/kms?target_session_attrs=read-write&sslmode=require&sslrootcert=/path/ca.pem";
        let params = extract_query_params(url);
        let clean = rebuild_url_without_ssl_params(url, &params);
        assert_eq!(
            clean,
            "postgresql://kms:kms@host1:5432,host2:5432/kms?target_session_attrs=read-write"
        );
    }

    #[test]
    fn test_rebuild_url_all_ssl_params_stripped() {
        let url = "postgresql://kms:kms@localhost:5432/kms?sslmode=require&sslcert=/c.pem&sslkey=/k.pem&sslrootcert=/ca.pem";
        let params = extract_query_params(url);
        let clean = rebuild_url_without_ssl_params(url, &params);
        assert_eq!(clean, "postgresql://kms:kms@localhost:5432/kms");
    }

    #[test]
    fn test_rebuild_url_preserves_non_ssl_params() {
        let url = "postgresql://kms:kms@localhost:5432/kms?target_session_attrs=read-write&application_name=cosmian_kms";
        let params = extract_query_params(url);
        let clean = rebuild_url_without_ssl_params(url, &params);
        // Both non-SSL params should be preserved (order may vary)
        assert!(clean.contains("target_session_attrs=read-write"));
        assert!(clean.contains("application_name=cosmian_kms"));
        assert!(clean.starts_with("postgresql://kms:kms@localhost:5432/kms?"));
    }

    #[test]
    fn test_rebuild_url_no_params() {
        let url = "postgresql://kms:kms@localhost:5432/kms";
        let params = extract_query_params(url);
        let clean = rebuild_url_without_ssl_params(url, &params);
        assert_eq!(clean, url);
    }

    #[test]
    fn test_multi_host_url_preserved_in_rebuild() {
        let url = "postgresql://kms:kms@host1:5432,host2:5433,host3:5434/kms?target_session_attrs=read-write";
        let params = extract_query_params(url);
        let clean = rebuild_url_without_ssl_params(url, &params);
        assert_eq!(clean, url);
    }

    #[test]
    fn test_pg_retry_backoff_ms() {
        assert_eq!(pg_retry_backoff_ms(0), 50); // 50 * 2^0
        assert_eq!(pg_retry_backoff_ms(1), 100); // 50 * 2^1
        assert_eq!(pg_retry_backoff_ms(5), 1600); // 50 * 2^5
        assert_eq!(pg_retry_backoff_ms(6), 3200); // 50 * 2^6 (capped at PG_MAX_RETRIES)
        assert_eq!(pg_retry_backoff_ms(100), 3200); // capped
    }

    #[test]
    fn test_is_pg_retryable_error_deadlock_serialization() {
        assert!(is_pg_retryable_error("ERROR: deadlock detected"));
        assert!(is_pg_retryable_error("SQLSTATE 40P01"));
        assert!(is_pg_retryable_error("serialization failure"));
        assert!(is_pg_retryable_error("SQLSTATE 40001"));
    }

    #[test]
    fn test_is_pg_retryable_error_connection() {
        assert!(is_pg_retryable_error("connection refused"));
        assert!(is_pg_retryable_error("connection reset by peer"));
        assert!(is_pg_retryable_error("connection closed"));
        assert!(is_pg_retryable_error("broken pipe"));
        assert!(is_pg_retryable_error(
            "server closed the connection unexpectedly"
        ));
        assert!(is_pg_retryable_error(
            "terminating connection due to administrator command"
        ));
        assert!(is_pg_retryable_error("could not connect to server"));
    }

    #[test]
    fn test_is_pg_retryable_error_sqlstate_codes() {
        assert!(is_pg_retryable_error("SQLSTATE 08001"));
        assert!(is_pg_retryable_error("SQLSTATE 08003"));
        assert!(is_pg_retryable_error("SQLSTATE 08004"));
        assert!(is_pg_retryable_error("SQLSTATE 08006"));
        assert!(is_pg_retryable_error("SQLSTATE 57P01"));
        assert!(is_pg_retryable_error("SQLSTATE 57P02"));
        assert!(is_pg_retryable_error("SQLSTATE 57P03"));
    }

    #[test]
    fn test_is_pg_retryable_error_case_insensitive() {
        assert!(is_pg_retryable_error("DEADLOCK DETECTED"));
        assert!(is_pg_retryable_error("Connection Refused"));
    }

    #[test]
    fn test_is_pg_retryable_error_substring_match() {
        assert!(is_pg_retryable_error(
            "error connecting: SQLSTATE 08001 connection exception"
        ));
        assert!(is_pg_retryable_error(
            "db error: ERROR: deadlock detected while waiting for lock"
        ));
    }

    #[test]
    fn test_is_pg_retryable_error_non_retryable() {
        assert!(!is_pg_retryable_error("unique constraint violation"));
        assert!(!is_pg_retryable_error("syntax error"));
        assert!(!is_pg_retryable_error("permission denied"));
        assert!(!is_pg_retryable_error(""));
    }
}
