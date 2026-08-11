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
use cosmian_logger::reexport::tracing;
use deadpool_postgres::{GenericClient, Pool, RecyclingMethod};
use rawsql::Loader;
use serde_json::Value;
use tokio_postgres::types::{Json, ToSql};
use uuid::Uuid;

use crate::{
    db_error,
    error::{DbError, DbResult},
    migrate_block_cipher_mode_if_needed,
    stores::{
        PGSQL_QUERIES,
        migrate::{DbState, Migrate, WRAPPING_KEY_BACKFILL_PARAM},
        sql::{
            database::SqlDatabase,
            pg_pool::build_pool,
            pg_retry::{PG_MAX_RETRIES, is_pg_retryable_error, pg_retry_backoff_ms},
        },
    },
};

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
/// to the new primary. With `RecyclingMethod::Verified` the pool itself discards
/// dead connections during `pool.get()`, so every retry receives a live connection.
macro_rules! pg_retry {
    ($pool:expr, | $client:ident | $body:expr) => {{
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
                                tracing::warn!(
                                    attempt,
                                    delay_ms,
                                    error = %e,
                                    "PostgreSQL retryable error — retrying"
                                );
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
                        tracing::warn!(
                            attempt,
                            delay_ms,
                            error = %msg,
                            "PostgreSQL pool error — retrying"
                        );
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
/// With `RecyclingMethod::Verified` the pool discards dead connections at
/// `pool.get()` time, guaranteeing a live connection for every retry.
macro_rules! pg_retry_tx {
    ($pool:expr, | $tx:ident | $body:expr) => {{
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
                        tracing::warn!(
                            attempt,
                            delay_ms,
                            error = %e,
                            "PostgreSQL BEGIN failed — retrying"
                        );
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
                            tracing::warn!(
                                attempt,
                                delay_ms,
                                error = %msg,
                                "PostgreSQL COMMIT failed — retrying"
                            );
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                        return Err(InterfaceError::from(DbError::from(e)));
                    }
                },
                Err(e) => {
                    if is_pg_retryable_error(&e.to_string()) && attempt + 1 < PG_MAX_RETRIES {
                        let delay_ms = pg_retry_backoff_ms(attempt);
                        tracing::warn!(
                            attempt,
                            delay_ms,
                            error = %e,
                            "PostgreSQL transaction body failed — retrying"
                        );
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
        // Verified runs `simple_query("")` on every recycled connection. This fails
        // immediately at the OS level (ECONNRESET) for any dead connection, even in the race
        // window where `is_closed()` still returns `false`. Without this, a dropped dead
        // connection is pushed back to the idle pool without any check, and the next
        // `pool.get()` re-validates only via `is_closed()` — which races against the
        // tokio-postgres background task that sets the flag. Verified eliminates that race
        // and ensures failover to a live host. The object store pool is shared by every Actix
        // worker, so the extra round trip is worth it (unlike the single-writer audit sink).
        let pool = build_pool(connection_url, max_connections, RecyclingMethod::Verified)?;

        let mut client = pool.get().await.map_err(DbError::from)?;
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
        // Add wrapping_key_id column if not present (idempotent).
        client
            .batch_execute(
                "ALTER TABLE objects ADD COLUMN IF NOT EXISTS wrapping_key_id VARCHAR(128);",
            )
            .await
            .map_err(DbError::from)?;
        // Create the read-path indexes (idempotent). PostgreSQL supports
        // `CREATE INDEX IF NOT EXISTS`, so these are safe to run on every start.
        for name in [
            "create-index-objects-owner",
            "create-index-objects-state",
            "create-index-read_access-userid",
            "create-index-objects-wrapping-key-id",
        ] {
            let sql = tmp_loader.get_query(name)?;
            client.batch_execute(sql).await.map_err(DbError::from)?;
        }
        // One-time `wrapping_key_id` backfill for pre-existing objects, gated by a
        // completion marker so the O(N) scan runs at most once per database. The
        // scan, updates and marker share a transaction: an interrupted run leaves
        // the marker unset and re-executes cleanly on the next boot.
        let backfill_done = client
            .query_opt(
                get_pgsql_query!("select-parameter"),
                &[&WRAPPING_KEY_BACKFILL_PARAM],
            )
            .await
            .map_err(DbError::from)?
            .map(|row| row.get::<usize, String>(0))
            == Some("true".to_owned());
        if !backfill_done {
            let tx = client.transaction().await.map_err(DbError::from)?;
            let update_stmt = tx
                .prepare(get_pgsql_query!("update-wrapping-key-id"))
                .await
                .map_err(DbError::from)?;
            let null_rows = tx
                .query(get_pgsql_query!("select-objects-null-wrapping-key"), &[])
                .await
                .map_err(DbError::from)?;
            for row in &null_rows {
                let id: String = row.get(0);
                let object_json: String = row.get(1);
                match serde_json::from_str::<Object>(&object_json) {
                    Ok(obj) => {
                        if let Some(wrapping_uid) = obj.wrapping_key_uid() {
                            tx.execute(&update_stmt, &[&wrapping_uid, &id])
                                .await
                                .map_err(DbError::from)?;
                        }
                    }
                    Err(e) => tracing::warn!(
                        uid = %id,
                        error = %e,
                        "wrapping_key_id backfill: skipping object that failed to deserialize"
                    ),
                }
            }
            tx.execute(
                get_pgsql_query!("upsert-parameter"),
                &[&WRAPPING_KEY_BACKFILL_PARAM, &"true"],
            )
            .await
            .map_err(DbError::from)?;
            tx.commit().await.map_err(DbError::from)?;
        }

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
            tx: &deadpool_postgres::Transaction<'_>,
            uid: &str,
            owner: &str,
            object: &Object,
            attributes: &Attributes,
            tags: &HashSet<String>,
        ) -> DbResult<String> {
            let object_json = serde_json::to_string(object).map_err(DbError::from)?;
            let attributes_json = serde_json::to_value(attributes).map_err(DbError::from)?;
            let state = attributes.state.unwrap_or(State::PreActive).to_string();
            let wrapping_key_id = object.wrapping_key_uid();
            let stmt = tx
                .prepare_cached(get_pgsql_query!("insert-objects"))
                .await
                .map_err(DbError::from)?;
            let attrs_param = Json(&attributes_json);
            tx.execute(
                &stmt,
                &[
                    &uid,
                    &object_json,
                    &attrs_param,
                    &state,
                    &owner,
                    &wrapping_key_id,
                ],
            )
            .await
            .map_err(DbError::from)?;
            if !tags.is_empty() {
                let transaction_stmt = tx
                    .prepare_cached(get_pgsql_query!("insert-tags"))
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
                .prepare_cached(get_pgsql_query!("select-object"))
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
                .prepare_cached(get_pgsql_query!("select-tags"))
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
            tx: &deadpool_postgres::Transaction<'_>,
            uid: &str,
            object: &Object,
            attributes: &Attributes,
            tags: Option<&HashSet<String>>,
        ) -> DbResult<()> {
            let object_json = serde_json::to_string(object).map_err(DbError::from)?;
            let attributes_json = serde_json::to_value(attributes).map_err(DbError::from)?;
            let wrapping_key_id = object.wrapping_key_uid();
            let stmt = tx
                .prepare_cached(get_pgsql_query!("update-object-with-object"))
                .await
                .map_err(DbError::from)?;
            let attrs_param = Json(&attributes_json);
            tx.execute(&stmt, &[&object_json, &attrs_param, &wrapping_key_id, &uid])
                .await
                .map_err(DbError::from)?;
            if let Some(tags) = tags {
                let delete_stmt = tx
                    .prepare_cached(get_pgsql_query!("delete-tags"))
                    .await
                    .map_err(DbError::from)?;
                tx.execute(&delete_stmt, &[&uid])
                    .await
                    .map_err(DbError::from)?;
                let insert_stmt = tx
                    .prepare_cached(get_pgsql_query!("insert-tags"))
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
                .prepare_cached(get_pgsql_query!("update-object-with-state"))
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
        async fn transact(tx: &deadpool_postgres::Transaction<'_>, uid: &str) -> DbResult<()> {
            let d1 = tx
                .prepare_cached(get_pgsql_query!("delete-object"))
                .await
                .map_err(DbError::from)?;
            tx.execute(&d1, &[&uid]).await.map_err(DbError::from)?;
            let d2 = tx
                .prepare_cached(get_pgsql_query!("delete-tags"))
                .await
                .map_err(DbError::from)?;
            tx.execute(&d2, &[&uid]).await.map_err(DbError::from)?;
            let d3 = tx
                .prepare_cached(get_pgsql_query!("delete-read-access-for-object"))
                .await
                .map_err(DbError::from)?;
            tx.execute(&d3, &[&uid]).await.map_err(DbError::from)?;
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
            tx: &deadpool_postgres::Transaction<'_>,
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
                        let wrapping_key_id = object.wrapping_key_uid();
                        let stmt = tx
                            .prepare_cached(get_pgsql_query!("insert-objects"))
                            .await
                            .map_err(DbError::from)?;
                        let attrs_param = Json(&attributes_json);
                        tx.execute(
                            &stmt,
                            &[
                                &uid,
                                &object_json,
                                &attrs_param,
                                &state,
                                &user,
                                &wrapping_key_id,
                            ],
                        )
                        .await
                        .map_err(DbError::from)?;
                        if !tags.is_empty() {
                            let insert_stmt = tx
                                .prepare_cached(get_pgsql_query!("insert-tags"))
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
                        let wrapping_key_id = object.wrapping_key_uid();
                        let stmt = tx
                            .prepare_cached(get_pgsql_query!("update-object-with-object"))
                            .await
                            .map_err(DbError::from)?;
                        let attrs_param = Json(&attributes_json);
                        tx.execute(&stmt, &[&object_json, &attrs_param, &wrapping_key_id, &uid])
                            .await
                            .map_err(DbError::from)?;
                        if let Some(tags) = tags {
                            let delete_stmt = tx
                                .prepare_cached(get_pgsql_query!("delete-tags"))
                                .await
                                .map_err(DbError::from)?;
                            tx.execute(&delete_stmt, &[&uid])
                                .await
                                .map_err(DbError::from)?;
                            let insert_stmt = tx
                                .prepare_cached(get_pgsql_query!("insert-tags"))
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
                            .prepare_cached(get_pgsql_query!("update-object-with-state"))
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
                        let wrapping_key_id = object.wrapping_key_uid();
                        let stmt = tx
                            .prepare_cached(get_pgsql_query!("upsert-object"))
                            .await
                            .map_err(DbError::from)?;
                        let st = state.to_string();
                        let attrs_param = Json(&attributes_json);
                        tx.execute(
                            &stmt,
                            &[
                                &uid,
                                &object_json,
                                &attrs_param,
                                &st,
                                &user,
                                &wrapping_key_id,
                            ],
                        )
                        .await
                        .map_err(DbError::from)?;
                        if let Some(tags) = tags {
                            let delete_stmt = tx
                                .prepare_cached(get_pgsql_query!("delete-tags"))
                                .await
                                .map_err(DbError::from)?;
                            tx.execute(&delete_stmt, &[&uid])
                                .await
                                .map_err(DbError::from)?;
                            let insert_stmt = tx
                                .prepare_cached(get_pgsql_query!("insert-tags"))
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
                            .prepare_cached(get_pgsql_query!("delete-object"))
                            .await
                            .map_err(DbError::from)?;
                        tx.execute(&d1, &[&uid]).await.map_err(DbError::from)?;
                        let d2 = tx
                            .prepare_cached(get_pgsql_query!("delete-tags"))
                            .await
                            .map_err(DbError::from)?;
                        tx.execute(&d2, &[&uid]).await.map_err(DbError::from)?;
                        let d3 = tx
                            .prepare_cached(get_pgsql_query!("delete-read-access-for-object"))
                            .await
                            .map_err(DbError::from)?;
                        tx.execute(&d3, &[&uid]).await.map_err(DbError::from)?;
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
                .prepare_cached(get_pgsql_query!("has-row-objects"))
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
            let mut tag_vec: Vec<String> = tags.iter().cloned().collect();
            tag_vec.sort();
            let tag_refs: Vec<&str> = tag_vec.iter().map(String::as_str).collect();
            let len_i32: i32 =
                i32::try_from(tags.len()).map_err(|e| InterfaceError::Db(e.to_string()))?;
            let stmt = client
                .prepare_cached(get_pgsql_query!("list-uids-for-tags"))
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let rows = client
                .query(&stmt, &[&&tag_refs[..], &len_i32])
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

    async fn find_wrapped_by(
        &self,
        wrapping_key_uid: &str,
        user: &str,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        pg_retry!(self.pool, |client| {
            let sql = get_pgsql_query!("find-wrapped-by");
            let rows = client
                .query(sql, &[&wrapping_key_uid, &user])
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

    async fn find_due_for_rotation(
        &self,
        now: time::OffsetDateTime,
    ) -> InterfaceResult<Vec<(String, String)>> {
        pg_retry!(self.pool, |client| {
            let sql = crate::stores::sql::locate_query::find_due_for_rotation_query::<
                crate::stores::sql::locate_query::PgSqlPlaceholder,
            >();
            let rows = client
                .query(&sql, &[])
                .await
                .map_err(|e| InterfaceError::from(DbError::from(e)))?;
            let mut due = Vec::new();
            for row in rows {
                let uid: String = row.get(0);
                let owner: String = row.get(1);
                let attrs_val: Value = row.get(2);
                let attrs: Attributes = serde_json::from_value(attrs_val).unwrap_or_default();
                if crate::stores::sql::locate_query::is_due_for_rotation(&attrs, now) {
                    due.push((uid, owner));
                }
            }
            Ok(due)
        })
    }

    async fn find_by_rotate_name(
        &self,
        name: &str,
        generation: Option<i32>,
        owner: &str,
    ) -> InterfaceResult<Vec<(String, Attributes)>> {
        let name = name.to_owned();
        let owner = owner.to_owned();
        pg_retry!(self.pool, |client| {
            let locate = crate::stores::sql::locate_query::find_by_rotate_name_query::<
                crate::stores::sql::locate_query::PgSqlPlaceholder,
            >(&name, generation, &owner);
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
            let mut results = Vec::new();
            for row in rows {
                let uid: String = row.get(0);
                let attrs_val: Value = row.get(1);
                let attrs: Attributes = serde_json::from_value(attrs_val).unwrap_or_default();
                results.push((uid, attrs));
            }
            Ok(results)
        })
    }

    /// Returns the total count of live (non-destroyed) objects in this `PostgreSQL` store.
    ///
    /// This is a **metrics-only** privileged query: it scans the full `objects` table
    /// without any user or permission filter, so the result always reflects the true
    /// server-wide inventory. It must never be used to answer client requests.
    ///
    /// The state strings `'Destroyed'` and `'Destroyed_Compromised'` are the Rust
    /// enum variant names as serialised to the DB by `strum::Display`.
    async fn count_all_non_destroyed(&self) -> InterfaceResult<u64> {
        let sql = get_pgsql_query!("count-non-destroyed-objects");
        let client = pg_get_client(&self.pool)
            .await
            .map_err(InterfaceError::from)?;
        let row = client
            .query_one(sql, &[])
            .await
            .map_err(DbError::from)
            .map_err(InterfaceError::from)?;
        let count: i64 = row.get(0);
        Ok(u64::try_from(count).unwrap_or(0))
    }

    async fn count_non_destroyed_keys(&self) -> InterfaceResult<u64> {
        let sql = get_pgsql_query!("count-non-destroyed-keys-pg");
        let client = pg_get_client(&self.pool)
            .await
            .map_err(InterfaceError::from)?;
        let row = client
            .query_one(sql, &[])
            .await
            .map_err(DbError::from)
            .map_err(InterfaceError::from)?;
        let count: i64 = row.get(0);
        Ok(u64::try_from(count).unwrap_or(0))
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
                .prepare_cached(get_pgsql_query!("select-objects-access-obtained"))
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
                .prepare_cached(get_pgsql_query!("select-rows-read_access-with-object-id"))
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
                .prepare_cached(get_pgsql_query!("upsert-row-read_access"))
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
                    .prepare_cached(get_pgsql_query!("delete-rows-read_access"))
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
                .prepare_cached(get_pgsql_query!("update-rows-read_access-with-permission"))
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
                .prepare_cached(get_pgsql_query!("select-user-accesses-for-object"))
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
