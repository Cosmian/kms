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
use url::Url;
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

// Deadlock/serialization handling parameters for PostgreSQL
const PG_DEADLOCK_MAX_RETRIES: u32 = 6;

fn is_pg_deadlock_or_serialization(msg: &str) -> bool {
    // Detect common PostgreSQL errors
    // - deadlock detected (SQLSTATE 40P01)
    // - serialization failure (SQLSTATE 40001)
    let lower = msg.to_ascii_lowercase();
    lower.contains("deadlock detected")
        || lower.contains("40p01")
        || lower.contains("serialization failure")
        || lower.contains("40001")
}

fn pg_deadlock_backoff_ms(attempt: u32) -> u64 {
    let cap = attempt.min(PG_DEADLOCK_MAX_RETRIES);
    50_u64 * (1_u64 << cap)
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
        // Parse URL to check for TLS parameters
        let url = Url::parse(connection_url)
            .map_err(|e| DbError::DatabaseError(format!("Invalid PostgreSQL URL: {e}")))?;
        let query_params: HashMap<_, _> = url.query_pairs().collect();

        // Build a clean URL without any query parameters
        // deadpool-postgres doesn't recognize URL query parameters like sslmode, sslrootcert, etc.
        // We handle TLS configuration entirely through the MakeTlsConnector
        let mut clean_url = url.clone();
        clean_url.set_query(None);

        let clean_url_str = clean_url.to_string();

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
        let sslmode = query_params
            .get("sslmode")
            .map_or("prefer", std::convert::AsRef::as_ref);

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
                    .set_ca_file(ca_file.as_ref())
                    .map_err(|e| DbError::DatabaseError(format!("Failed to load CA: {e}")))?;
            }

            // Load client cert/key for mutual TLS (sslcert, sslkey)
            if let Some(cert_file) = query_params.get("sslcert") {
                builder
                    .set_certificate_file(cert_file.as_ref(), SslFiletype::PEM)
                    .map_err(|e| {
                        DbError::DatabaseError(format!("Failed to load client cert: {e}"))
                    })?;
            }
            if let Some(key_file) = query_params.get("sslkey") {
                builder
                    .set_private_key_file(key_file.as_ref(), SslFiletype::PEM)
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
        ) -> DbResult<()> {
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
            Ok(())
        }

        let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());
        for attempt in 0..PG_DEADLOCK_MAX_RETRIES {
            let mut client = self.pool.get().await.map_err(DbError::from)?;
            let tx = client.transaction().await.map_err(DbError::from)?;
            match transact(&tx, &uid, owner, object, attributes, tags).await {
                Ok(()) => match tx.commit().await {
                    Ok(()) => return Ok(uid.clone()),
                    Err(e) => {
                        let msg = e.to_string();
                        if is_pg_deadlock_or_serialization(&msg)
                            && attempt + 1 < PG_DEADLOCK_MAX_RETRIES
                        {
                            let delay_ms = pg_deadlock_backoff_ms(attempt);
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                        return Err(InterfaceError::from(DbError::from(e)));
                    }
                },
                Err(e) => {
                    if is_pg_deadlock_or_serialization(&e.to_string())
                        && attempt + 1 < PG_DEADLOCK_MAX_RETRIES
                    {
                        let delay_ms = pg_deadlock_backoff_ms(attempt);
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
    }

    async fn retrieve(&self, uid: &str) -> InterfaceResult<Option<ObjectWithMetadata>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
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
    }

    async fn retrieve_tags(&self, uid: &str) -> InterfaceResult<HashSet<String>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        let stmt = client
            .prepare(get_pgsql_query!("select-tags"))
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        let rows = client
            .query(&stmt, &[&uid])
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
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

        for attempt in 0..PG_DEADLOCK_MAX_RETRIES {
            let mut client = self.pool.get().await.map_err(DbError::from)?;
            let tx = client.transaction().await.map_err(DbError::from)?;
            match transact(&tx, uid, object, attributes, tags).await {
                Ok(()) => match tx.commit().await {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        let msg = e.to_string();
                        if is_pg_deadlock_or_serialization(&msg)
                            && attempt + 1 < PG_DEADLOCK_MAX_RETRIES
                        {
                            let delay_ms = pg_deadlock_backoff_ms(attempt);
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                        return Err(InterfaceError::from(DbError::from(e)));
                    }
                },
                Err(e) => {
                    if is_pg_deadlock_or_serialization(&e.to_string())
                        && attempt + 1 < PG_DEADLOCK_MAX_RETRIES
                    {
                        let delay_ms = pg_deadlock_backoff_ms(attempt);
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
    }

    async fn update_state(&self, uid: &str, state: State) -> InterfaceResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
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
        for attempt in 0..PG_DEADLOCK_MAX_RETRIES {
            let mut client = self.pool.get().await.map_err(DbError::from)?;
            let tx = client.transaction().await.map_err(DbError::from)?;
            match transact(&tx, uid).await {
                Ok(()) => match tx.commit().await {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        let msg = e.to_string();
                        if is_pg_deadlock_or_serialization(&msg)
                            && attempt + 1 < PG_DEADLOCK_MAX_RETRIES
                        {
                            let delay_ms = pg_deadlock_backoff_ms(attempt);
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                        return Err(InterfaceError::from(DbError::from(e)));
                    }
                },
                Err(e) => {
                    if is_pg_deadlock_or_serialization(&e.to_string())
                        && attempt + 1 < PG_DEADLOCK_MAX_RETRIES
                    {
                        let delay_ms = pg_deadlock_backoff_ms(attempt);
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

        for attempt in 0..PG_DEADLOCK_MAX_RETRIES {
            let mut client = self.pool.get().await.map_err(DbError::from)?;
            let tx = client.transaction().await.map_err(DbError::from)?;
            match transact(&tx, user, operations).await {
                Ok(v) => match tx.commit().await {
                    Ok(()) => return Ok(v),
                    Err(e) => {
                        let msg = e.to_string();
                        if is_pg_deadlock_or_serialization(&msg)
                            && attempt + 1 < PG_DEADLOCK_MAX_RETRIES
                        {
                            let delay_ms = pg_deadlock_backoff_ms(attempt);
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                        return Err(InterfaceError::from(DbError::from(e)));
                    }
                },
                Err(e) => {
                    if is_pg_deadlock_or_serialization(&e.to_string())
                        && attempt + 1 < PG_DEADLOCK_MAX_RETRIES
                    {
                        let delay_ms = pg_deadlock_backoff_ms(attempt);
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
    }

    async fn is_object_owned_by(&self, uid: &str, owner: &str) -> InterfaceResult<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        let stmt = client
            .prepare(get_pgsql_query!("has-row-objects"))
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        let row = client
            .query_opt(&stmt, &[&uid, &owner])
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        Ok(row.is_some())
    }

    async fn list_uids_for_tags(&self, tags: &HashSet<String>) -> InterfaceResult<HashSet<String>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
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
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        user: &str,
        user_must_be_owner: bool,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        let locate = crate::stores::sql::locate_query::query_from_attributes::<
            crate::stores::sql::locate_query::PgSqlPlaceholder,
        >(researched_attributes, state, user, user_must_be_owner);
        cosmian_logger::debug!("PG find query: {}", locate.sql);
        let stmt = client
            .prepare(&locate.sql)
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        let mut owned: Vec<Box<dyn ToSql + Sync>> = Vec::with_capacity(locate.params.len());
        for p in locate.params {
            match p {
                crate::stores::sql::locate_query::LocateParam::Text(s) => owned.push(Box::new(s)),
                crate::stores::sql::locate_query::LocateParam::I64(i) => owned.push(Box::new(i)),
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
    }
}

#[async_trait(?Send)]
impl Migrate for PgPool {
    async fn get_db_state(&self) -> DbResult<Option<DbState>> {
        let client = self.pool.get().await.map_err(DbError::from)?;
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
        let client = self.pool.get().await.map_err(DbError::from)?;
        let sql = get_pgsql_query!("upsert-parameter");
        let state_json = serde_json::to_string(&state)?;
        client
            .execute(sql, &[&"db_state", &state_json])
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn get_current_db_version(&self) -> DbResult<Option<String>> {
        let client = self.pool.get().await.map_err(DbError::from)?;
        let sql = get_pgsql_query!("select-parameter");
        let row_opt = client
            .query_opt(sql, &[&"db_version"])
            .await
            .map_err(DbError::from)?;
        Ok(row_opt.map(|row| row.get::<usize, String>(0)))
    }

    async fn set_current_db_version(&self, version: &str) -> DbResult<()> {
        let client = self.pool.get().await.map_err(DbError::from)?;
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
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
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
            let perms: HashSet<KmipOperation> =
                serde_json::from_value(perms_val).map_err(|e| InterfaceError::Db(e.to_string()))?;
            map.insert(id, (owner, state, perms));
        }
        Ok(map)
    }

    async fn list_object_operations_granted(
        &self,
        uid: &str,
    ) -> InterfaceResult<HashMap<String, HashSet<KmipOperation>>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
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
    }

    async fn grant_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        // Merge with existing permissions
        let existing = self.list_user_operations_on_object(uid, user, true).await?;
        let mut combined = existing;
        combined.extend(operations);
        let json =
            serde_json::to_value(&combined).map_err(|e| InterfaceError::from(DbError::from(e)))?;
        let stmt = client
            .prepare(get_pgsql_query!("upsert-row-read_access"))
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        client
            .execute(&stmt, &[&uid, &user, &json])
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        Ok(())
    }

    async fn remove_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        let current = self.list_user_operations_on_object(uid, user, true).await?;
        let remaining: HashSet<KmipOperation> = current.difference(&operations).copied().collect();
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
        let json =
            serde_json::to_value(&remaining).map_err(|e| InterfaceError::from(DbError::from(e)))?;
        let u = client
            .prepare(get_pgsql_query!("update-rows-read_access-with-permission"))
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        client
            .execute(&u, &[&uid, &user, &json])
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
        Ok(())
    }

    async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
    ) -> InterfaceResult<HashSet<KmipOperation>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::from(DbError::from(e)))?;
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
    }
}
