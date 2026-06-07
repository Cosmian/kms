// SQLite backend implementation using tokio-rusqlite
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{KmipOperation, kmip_attributes::Attributes, kmip_objects::Object},
};
use cosmian_kms_interfaces::{
    AtomicOperation, InterfaceError, InterfaceResult, ObjectWithMetadata, ObjectsStore,
    PermissionsStore, UserId,
};
use cosmian_logger::reexport::tracing;
use rawsql::Loader;
use rusqlite::{OptionalExtension, Row, params_from_iter};
use serde_json::Value;
use tokio_rusqlite::Connection;
use uuid::Uuid;

use super::locate_query::{
    SqlitePlaceholder, find_by_rotate_name_query, find_due_for_rotation_query,
    query_all_from_attributes, query_from_attributes,
};
use crate::{
    db_error,
    error::{DbError, DbResult},
    migrate_block_cipher_mode_if_needed,
    stores::{
        PGSQL_QUERIES, SQLITE_QUERIES,
        migrate::{DbState, Migrate, WRAPPING_KEY_BACKFILL_PARAM},
        sql::database::SqlDatabase,
    },
};

macro_rules! get_sqlite_query {
    ($name:literal) => {
        SQLITE_QUERIES
            .get($name)
            .or_else(|| PGSQL_QUERIES.get($name))
            .ok_or_else(|| db_error!("{} SQL query can't be found", $name))?
    };
}

#[derive(Clone)]
pub(crate) struct SqlitePool {
    /// Dedicated connection for write operations (create, update, delete).
    writer: Connection,
    /// Pool of connections for read operations (retrieve, find, list).
    /// `SQLite` WAL mode allows concurrent readers alongside a single writer.
    readers: Vec<Connection>,
    /// Round-robin counter for distributing reads across the pool.
    reader_idx: Arc<AtomicUsize>,
}

impl SqlitePool {
    /// Opens `count` connections to the same `SQLite` database and applies
    /// `PRAGMAs` to each. Returns them in a `Vec`.
    async fn open_connections(path: &Path, count: usize) -> DbResult<Vec<Connection>> {
        let mut conns = Vec::with_capacity(count);
        for _ in 0..count {
            let conn = Connection::open(path).await?;
            conn.call(
                |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    c.execute_batch(
                        // WAL mode: readers and the single writer never block each other.
                        "PRAGMA journal_mode=WAL;\
                         PRAGMA synchronous=NORMAL;\
                         PRAGMA busy_timeout=5000;\
                         PRAGMA cache_size=-65536;\
                         PRAGMA mmap_size=268435456;\
                         PRAGMA temp_store=MEMORY;",
                        // cache_size=-65536 → 64 MiB page cache per connection (negative
                        // value means KiB, positive means pages of 4 KiB each).
                        // mmap_size=268435456 → 256 MiB memory-mapped I/O window;
                        // eliminates pread() syscall overhead for read-hot pages.
                        // temp_store=MEMORY → sort/index temp tables stay in RAM.
                    )
                },
            )
            .await
            .map_err(DbError::from)?;
            conns.push(conn);
        }
        Ok(conns)
    }

    pub(crate) async fn instantiate(
        path: &Path,
        clear_database: bool,
        max_connections: Option<u32>,
    ) -> DbResult<Self> {
        // Determine reader pool size: default to 2×CPUs capped at 32,
        // matching the MySQL/PostgreSQL backend pool sizing strategy.
        // Note: total connections = num_readers + 1 (dedicated writer).
        let default_readers: usize = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .saturating_mul(2)
            .min(32);
        let num_readers: usize = max_connections
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(default_readers)
            .max(1);

        // Open the writer connection
        let writer_vec = Self::open_connections(path, 1).await?;
        let writer = writer_vec
            .into_iter()
            .next()
            .ok_or_else(|| DbError::DatabaseError("Failed to open writer connection".to_owned()))?;

        // Open the reader connections
        let readers = Self::open_connections(path, num_readers).await?;

        let pool = Self {
            writer,
            readers,
            reader_idx: Arc::new(AtomicUsize::new(0)),
        };

        // Bootstrap schema and optionally clear database on startup, using trait queries
        let create_parameters = pool.get_query("create-table-parameters")?.to_owned();
        let create_objects = pool.get_query("create-table-objects")?.to_owned();
        let create_read_access = pool.get_query("create-table-read_access")?.to_owned();
        let create_tags = pool.get_query("create-table-tags")?.to_owned();
        let idx_objects_owner = pool.get_query("create-index-objects-owner")?.to_owned();
        let idx_objects_state = pool.get_query("create-index-objects-state")?.to_owned();
        let idx_read_access_userid = pool
            .get_query("create-index-read_access-userid")?
            .to_owned();
        let create_crypto_officer_activations = pool
            .get_query("create-table-crypto_officer_activations")?
            .to_owned();
        let create_crls = pool.get_query("create-table-crls")?.to_owned();
        let clean_objects = pool.get_query("clean-table-objects")?.to_owned();
        let clean_read_access = pool.get_query("clean-table-read_access")?.to_owned();
        let clean_tags = pool.get_query("clean-table-tags")?.to_owned();
        let add_column_domain = pool.get_query("add-column-domain")?.to_owned();
        pool.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(&create_parameters, [])?;
                    tx.execute(&create_objects, [])?;
                    tx.execute(&create_read_access, [])?;
                    tx.execute(&create_tags, [])?;
                    tx.execute(&idx_objects_owner, [])?;
                    tx.execute(&idx_objects_state, [])?;
                    tx.execute(&idx_read_access_userid, [])?;
                    tx.execute(
                        &replace_dollars_with_qn(&create_crypto_officer_activations),
                        [],
                    )?;
                    // Migration: add domain column if missing (existing databases)
                    let has_domain: bool = tx.prepare("SELECT domain FROM objects LIMIT 0").is_ok();
                    if !has_domain {
                        tx.execute(&add_column_domain, [])?;
                    }
                    if clear_database {
                        tx.execute(&clean_objects, [])?;
                        tx.execute(&clean_read_access, [])?;
                        tx.execute(&clean_tags, [])?;
                    }
                    tx.commit()?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;

        // One-time migration for databases created before the `wrapping_key_id`
        // column existed. The column and its index are ensured on every start
        // (idempotent and cheap); the expensive O(N) backfill scan is gated by a
        // completion marker so it runs at most once per database instead of on
        // every startup (unwrapped objects keep a NULL value forever). The
        // column-add, index and backfill share a single transaction; the completion
        // marker is written separately afterwards. Because the backfill is idempotent,
        // an interrupted run (marker still unset) re-executes cleanly on the next boot.
        // Note: SQLite does not support `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`,
        // so we check PRAGMA table_info first.
        let backfill_done =
            pool.get_parameter(WRAPPING_KEY_BACKFILL_PARAM).await? == Some("true".to_owned());
        pool.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    let has_column: bool = {
                        let mut stmt = tx.prepare("PRAGMA table_info(objects)")?;
                        let mut rows = stmt.query([])?;
                        let mut found = false;
                        while let Some(row) = rows.next()? {
                            let col_name: String = row.get(1)?;
                            if col_name == "wrapping_key_id" {
                                found = true;
                                break;
                            }
                        }
                        found
                    };
                    if !has_column {
                        tx.execute_batch(
                            "ALTER TABLE objects ADD COLUMN wrapping_key_id VARCHAR(128);",
                        )?;
                    }
                    // Index supporting `find-wrapped-by` lookups and the backfill scan.
                    tx.execute_batch(
                        "CREATE INDEX IF NOT EXISTS idx_objects_wrapping_key_id \
                         ON objects (wrapping_key_id);",
                    )?;
                    if !backfill_done {
                        // Backfill: deserialize each object and extract its wrapping key UID.
                        let pairs: Vec<(String, String)> = {
                            let mut stmt = tx.prepare(
                                "SELECT id, object FROM objects WHERE wrapping_key_id IS NULL",
                            )?;
                            let mut rows = stmt.query([])?;
                            let mut out = Vec::new();
                            while let Some(row) = rows.next()? {
                                out.push((row.get(0)?, row.get(1)?));
                            }
                            out
                        };
                        for (id, object_json) in &pairs {
                            match serde_json::from_str::<Object>(object_json) {
                                Ok(obj) => {
                                    if let Some(wrapping_uid) = obj.wrapping_key_uid() {
                                        tx.execute(
                                            "UPDATE objects SET wrapping_key_id = ?1 WHERE id = ?2",
                                            rusqlite::params![wrapping_uid, id],
                                        )?;
                                    }
                                }
                                Err(e) => tracing::warn!(
                                    uid = %id,
                                    error = %e,
                                    "wrapping_key_id backfill: skipping object that failed to \
                                     deserialize"
                                ),
                            }
                        }
                    }
                    tx.commit()?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;
        if !backfill_done {
            pool.set_parameter(WRAPPING_KEY_BACKFILL_PARAM, "true")
                .await?;
        }

        // Migration: add activated_by column to crypto_officer_activations (idempotent).
        // SQLite does not support ADD COLUMN IF NOT EXISTS — check PRAGMA first.
        // Also create the unique partial index that prevents duplicate active records
        // per user (enforces n-of-n dual-control at the DB layer).
        pool.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let has_activated_by: bool = {
                        let mut stmt =
                            c.prepare("PRAGMA table_info(crypto_officer_activations)")?;
                        let mut rows = stmt.query([])?;
                        let mut found = false;
                        while let Some(row) = rows.next()? {
                            let col_name: String = row.get(1)?;
                            if col_name == "activated_by" {
                                found = true;
                                break;
                            }
                        }
                        found
                    };
                    if !has_activated_by {
                        c.execute_batch(
                            "ALTER TABLE crypto_officer_activations \
                             ADD COLUMN activated_by VARCHAR(255);",
                        )?;
                    }
                    // Unique partial index: at most one active record per user.
                    // SQLite supports partial indexes since 3.8.9 (2014-08-15).
                    c.execute_batch(
                        "CREATE UNIQUE INDEX IF NOT EXISTS idx_co_activations_active \
                         ON crypto_officer_activations (activated_by) \
                         WHERE revoked_at IS NULL;",
                    )?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;

        if clear_database {
            pool.set_current_db_version(env!("CARGO_PKG_VERSION"))
                .await?;
            pool.set_db_state(DbState::Ready).await?;
        }

        Ok(pool)
    }

    /// Returns a reader connection using round-robin distribution.
    fn reader(&self) -> &Connection {
        let idx = self.reader_idx.fetch_add(1, Ordering::Relaxed) % self.readers.len();
        #[allow(clippy::indexing_slicing)]
        // SAFETY: idx is computed modulo readers.len(), which is always >= 1.
        &self.readers[idx]
    }

    /// Read a value from the `parameters` table by name, or `None` if absent.
    async fn get_parameter(&self, name: &'static str) -> DbResult<Option<String>> {
        let select_param = replace_dollars_with_qn(get_sqlite_query!("select-parameter"));
        let res = self
            .reader()
            .call(
                move |c: &mut rusqlite::Connection| -> Result<Option<String>, rusqlite::Error> {
                    let mut stmt = c.prepare_cached(&select_param)?;
                    stmt.query_row(params_from_iter([&name]), |row| row.get::<_, String>(0))
                        .optional()
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(res)
    }

    /// Upsert a `name`/`value` pair into the `parameters` table.
    async fn set_parameter(&self, name: &'static str, value: &str) -> DbResult<()> {
        let upsert_param = replace_dollars_with_qn(get_sqlite_query!("upsert-parameter"));
        let value_s = value.to_owned();
        self.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(&upsert_param, params_from_iter([&name, &value_s.as_str()]))?;
                    tx.commit()?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    pub(crate) async fn health_check(&self) -> DbResult<()> {
        self.writer
            .call(|c| c.query_row("SELECT 1", [], |_row| Ok(())))
            .await
            .map_err(DbError::from)
    }
}

impl SqlDatabase for SqlitePool {
    fn get_loader(&self) -> &Loader {
        &PGSQL_QUERIES
    }
}

fn replace_dollars_with_qn(sql: &str) -> String {
    // Convert occurrences of $N to ?N for rusqlite, but leave JSON paths like '$.foo' unchanged.
    let mut out = String::with_capacity(sql.len());
    let bytes = sql.as_bytes();
    let mut i = 0;
    let mut in_single_quote = false;
    while i < bytes.len() {
        let ch = bytes.get(i).map(|b| char::from(*b)).unwrap_or_default();
        if ch == '\'' {
            in_single_quote = !in_single_quote;
            out.push(ch);
            i += 1;
            continue;
        }
        if !in_single_quote && ch == '$' {
            // If next char is a digit, treat as placeholder and replace '$' with '?'
            if i + 1 < bytes.len()
                && bytes
                    .get(i + 1)
                    .is_some_and(|b| char::from(*b).is_ascii_digit())
            {
                out.push('?');
                i += 1;
                continue;
            }
        }
        out.push(ch);
        i += 1;
    }
    out
}

fn sqlite_row_to_owm(row: &Row<'_>) -> Result<ObjectWithMetadata, DbError> {
    let id: String = row.get(0)?;
    let object_json: String = row.get(1)?;
    let attributes_json: String = row.get(2)?;
    let owner: String = row.get(3)?;
    let state_str: String = row.get(4)?;
    let domain: String = row.get::<_, String>(5).unwrap_or_default();
    let object: Object = serde_json::from_str(&object_json)?;
    let object = migrate_block_cipher_mode_if_needed(object);
    let attributes: Attributes = serde_json::from_str(&attributes_json)?;
    let state =
        State::try_from(state_str.as_str()).map_err(|e| DbError::DatabaseError(e.to_string()))?;
    Ok(ObjectWithMetadata::new(
        id, object, owner, state, attributes, domain,
    ))
}

#[async_trait(?Send)]
impl ObjectsStore for SqlitePool {
    async fn create(
        &self,
        uid: Option<String>,
        owner: &UserId,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
        domain: &str,
    ) -> InterfaceResult<String> {
        let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());
        // If an explicit UID already exists, return a clear error matching CLI expectations
        let exists = self
            .writer
            .call({
                let uid_check = uid.clone();
                move |c: &mut rusqlite::Connection| -> Result<bool, rusqlite::Error> {
                    let mut stmt = c.prepare_cached("SELECT 1 FROM objects WHERE id=?1 LIMIT 1")?;
                    let present = stmt.exists(params_from_iter([&uid_check]))?;
                    Ok(present)
                }
            })
            .await
            .map_err(DbError::from)?;
        if exists {
            return Err(InterfaceError::Db(
                "one or more objects already exist".to_owned(),
            ));
        }
        let object_json = serde_json::to_string(object)
            .map_err(|e| InterfaceError::Db(format!("failed serializing object: {e}")))?;
        let attributes_json = serde_json::to_string(attributes)
            .map_err(|e| InterfaceError::Db(format!("failed serializing attributes: {e}")))?;
        let state_s = attributes.state.unwrap_or(State::PreActive).to_string();
        let owner_s: String = owner.as_str().to_owned();
        let wrapping_key_id = object.wrapping_key_uid();
        let domain_s = domain.to_owned();

        let insert_object = replace_dollars_with_qn(get_sqlite_query!("insert-objects"));
        let insert_tag = replace_dollars_with_qn(get_sqlite_query!("insert-tags"));

        let uid_clone = uid.clone();
        let tags_owned: HashSet<String> = tags.clone();
        self.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(
                        &insert_object,
                        rusqlite::params![
                            uid_clone,
                            object_json,
                            attributes_json,
                            state_s,
                            owner_s,
                            wrapping_key_id,
                            &domain_s,
                        ],
                    )?;
                    for tag in &tags_owned {
                        tx.execute(&insert_tag, params_from_iter([&uid_clone, tag.as_str()]))?;
                    }
                    tx.commit()?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(uid)
    }

    async fn retrieve(&self, uid: &str) -> InterfaceResult<Option<ObjectWithMetadata>> {
        let select_object: &str = get_sqlite_query!("select-object");
        let uid_s = uid.to_owned();
        let res = self.reader()
            .call(move |c: &mut rusqlite::Connection| -> Result<Option<ObjectWithMetadata>, rusqlite::Error> {
                let mut stmt = c.prepare_cached(select_object)?;
                let row = stmt
                    .query_row(params_from_iter([&uid_s]), |row| {
                            sqlite_row_to_owm(row).map_err(|_err| rusqlite::Error::InvalidQuery)
                    })
                    .optional()?;
                Ok(row)
            })
            .await
            .map_err(DbError::from)?;
        Ok(res)
    }

    async fn retrieve_tags(&self, uid: &str) -> InterfaceResult<HashSet<String>> {
        let sql: &str = get_sqlite_query!("select-tags");
        let uid_s = uid.to_owned();
        let tags = self
            .reader()
            .call(
                move |c: &mut rusqlite::Connection| -> Result<HashSet<String>, rusqlite::Error> {
                    let mut stmt = c.prepare_cached(sql)?;
                    let mut rows = stmt.query(params_from_iter([&uid_s]))?;
                    let mut tags = HashSet::new();
                    while let Some(r) = rows.next()? {
                        let tag: String = r.get(0)?;
                        tags.insert(tag);
                    }
                    Ok(tags)
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(tags)
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
    ) -> InterfaceResult<()> {
        let object_json = serde_json::to_string(object)
            .map_err(|e| InterfaceError::Db(format!("failed serializing object: {e}")))?;
        let attributes_json = serde_json::to_string(attributes)
            .map_err(|e| InterfaceError::Db(format!("failed serializing attributes: {e}")))?;
        let wrapping_key_id = object.wrapping_key_uid();

        let sql_update = replace_dollars_with_qn(get_sqlite_query!("update-object-with-object"));
        let sql_delete_tags = replace_dollars_with_qn(get_sqlite_query!("delete-tags"));
        let sql_insert_tag = replace_dollars_with_qn(get_sqlite_query!("insert-tags"));

        let uid_s = uid.to_owned();
        let tags_owned: Option<HashSet<String>> = tags.cloned();
        self.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(
                        &sql_update,
                        rusqlite::params![object_json, attributes_json, wrapping_key_id, uid_s],
                    )?;
                    if let Some(tags) = tags_owned.as_ref() {
                        tx.execute(&sql_delete_tags, params_from_iter([&uid_s]))?;
                        for tag in tags {
                            tx.execute(&sql_insert_tag, params_from_iter([&uid_s, tag.as_str()]))?;
                        }
                    }
                    tx.commit()?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn update_state(&self, uid: &str, state: State) -> InterfaceResult<()> {
        let sql = replace_dollars_with_qn(get_sqlite_query!("update-object-with-state"));
        let state_s = state.to_string();
        let uid_s = uid.to_owned();
        self.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(&sql, params_from_iter([state_s, uid_s]))?;
                    tx.commit()?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn delete(&self, uid: &str) -> InterfaceResult<()> {
        let del_obj = replace_dollars_with_qn(get_sqlite_query!("delete-object"));
        let del_tags = replace_dollars_with_qn(get_sqlite_query!("delete-tags"));
        let del_access =
            replace_dollars_with_qn(get_sqlite_query!("delete-read-access-for-object"));
        let uid_s = uid.to_owned();
        self.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(&del_obj, params_from_iter([&uid_s]))?;
                    tx.execute(&del_tags, params_from_iter([&uid_s]))?;
                    tx.execute(&del_access, params_from_iter([&uid_s]))?;
                    tx.commit()?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn atomic(
        &self,
        user: &UserId,
        operations: &[AtomicOperation],
    ) -> InterfaceResult<Vec<String>> {
        let user_s: String = user.as_str().to_owned();
        let ops_owned: Vec<OwnedOp> = operations.iter().map(OwnedOp::from).collect();
        let v = self
            .writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<Vec<String>, rusqlite::Error> {
                    let tx = c.transaction()?;
                    let uids = apply_owned_ops(&tx, &user_s, &ops_owned)
                        .map_err(|_err| rusqlite::Error::InvalidQuery)?;
                    tx.commit()?;
                    Ok(uids)
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(v)
    }

    async fn is_object_owned_by(&self, uid: &str, owner: &UserId) -> InterfaceResult<bool> {
        let sql = get_sqlite_query!("has-row-objects").to_string();
        let uid_s = uid.to_owned();
        let owner_s: String = owner.as_str().to_owned();
        let owned = self
            .reader()
            .call(
                move |c: &mut rusqlite::Connection| -> Result<bool, rusqlite::Error> {
                    let mut stmt = c.prepare_cached(&sql)?;
                    let exists = stmt.exists(params_from_iter([&uid_s, &owner_s]))?;
                    Ok(exists)
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(owned)
    }

    async fn list_uids_for_tags(&self, tags: &HashSet<String>) -> InterfaceResult<HashSet<String>> {
        let placeholders = (1..=tags.len())
            .map(|i| format!("${i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let raw_sql = get_sqlite_query!("select-uids-from-tags")
            .replace("@TAGS", &placeholders)
            .replace("@LEN", &format!("${}", tags.len() + 1));
        let sql = replace_dollars_with_qn(&raw_sql);
        let tag_list: Vec<String> = tags.iter().cloned().collect();
        let len_val: i64 = i64::try_from(tags.len()).unwrap_or(0);
        let set = self
            .reader()
            .call(
                move |c: &mut rusqlite::Connection| -> Result<HashSet<String>, rusqlite::Error> {
                    let mut stmt = c.prepare_cached(&sql)?;
                    // Build dynamic params: tags then len
                    let mut param_refs: Vec<&dyn rusqlite::ToSql> =
                        Vec::with_capacity(tag_list.len() + 1);
                    for t in &tag_list {
                        param_refs.push(t);
                    }
                    param_refs.push(&len_val);
                    let mut rows = stmt.query(rusqlite::params_from_iter(param_refs.iter()))?;
                    let mut ids = HashSet::new();
                    while let Some(r) = rows.next()? {
                        let id: String = r.get(0)?;
                        ids.insert(id);
                    }
                    Ok(ids)
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(set)
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        user: &UserId,
        user_must_be_owner: bool,
        vendor_id: &str,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        let locate = query_from_attributes::<SqlitePlaceholder>(
            researched_attributes,
            state,
            user,
            user_must_be_owner,
            vendor_id,
        );
        let sql_conversion = replace_dollars_with_qn(&locate.sql);
        let locate_params = locate.params;
        let rows = self.reader()
            .call(move |c: &mut rusqlite::Connection| -> Result<Vec<(String, State, Attributes)>, rusqlite::Error> {
                let mut stmt = c.prepare_cached(&sql_conversion)?;
                let values: Vec<rusqlite::types::Value> = locate_params
                    .into_iter()
                    .map(|p| match p {
                        crate::stores::sql::locate_query::LocateParam::Text(s) => {
                            rusqlite::types::Value::Text(s)
                        }
                        crate::stores::sql::locate_query::LocateParam::I64(i) => {
                            rusqlite::types::Value::Integer(i)
                        }
                    })
                    .collect();
                let mut q = stmt.query(rusqlite::params_from_iter(values.iter()))?;
                let mut out = Vec::new();
                while let Some(r) = q.next()? {
                    let id: String = r.get(0)?;
                    let state_str: String = r.get(1)?;
                    let state = State::try_from(state_str.as_str())
                        .map_err(|_err| rusqlite::Error::InvalidQuery)?;
                    let raw: String = r.get(2)?;
                    let attrs = if raw.is_empty() {
                        Attributes::default()
                    } else {
                        serde_json::from_str::<Attributes>(&raw)
                            .map_err(|_err| rusqlite::Error::InvalidQuery)?
                    };
                    out.push((id, state, attrs));
                }
                Ok(out)
            })
            .await
            .map_err(DbError::from)?;
        Ok(rows)
    }

    async fn find_wrapped_by(
        &self,
        wrapping_key_uid: &str,
        user: &UserId,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        let sql = replace_dollars_with_qn(get_sqlite_query!("find-wrapped-by"));
        let uid_s = wrapping_key_uid.to_owned();
        let user_s: String = user.as_str().to_owned();
        let rows = self
            .reader()
            .call(
                move |c: &mut rusqlite::Connection| -> Result<
                    Vec<(String, State, Attributes)>,
                    rusqlite::Error,
                > {
                    let mut stmt = c.prepare(&sql)?;
                    let mut q =
                        stmt.query(params_from_iter([uid_s.as_str(), user_s.as_str()]))?;
                    let mut out = Vec::new();
                    while let Some(r) = q.next()? {
                        let id: String = r.get(0)?;
                        let state_str: String = r.get(1)?;
                        let state = State::try_from(state_str.as_str())
                            .map_err(|_e| rusqlite::Error::InvalidQuery)?;
                        let raw: String = r.get(2)?;
                        let attrs = if raw.is_empty() {
                            Attributes::default()
                        } else {
                            serde_json::from_str::<Attributes>(&raw)
                                .map_err(|_e| rusqlite::Error::InvalidQuery)?
                        };
                        out.push((id, state, attrs));
                    }
                    Ok(out)
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(rows)
    }

    async fn find_due_for_rotation(
        &self,
        now: time::OffsetDateTime,
    ) -> InterfaceResult<Vec<(String, String)>> {
        let sql = find_due_for_rotation_query::<SqlitePlaceholder>();
        let rows = self
            .reader()
            .call(
                move |c: &mut rusqlite::Connection| -> Result<
                    Vec<(String, String, String)>,
                    rusqlite::Error,
                > {
                    let mut stmt = c.prepare(&sql)?;
                    let mut q = stmt.query([])?;
                    let mut out = Vec::new();
                    while let Some(r) = q.next()? {
                        let id: String = r.get(0)?;
                        let owner: String = r.get(1)?;
                        let attrs_json: String = r.get(2)?;
                        out.push((id, owner, attrs_json));
                    }
                    Ok(out)
                },
            )
            .await
            .map_err(DbError::from)?;

        let mut due = Vec::new();
        for (uid, owner, attrs_json) in rows {
            let attrs: Attributes = serde_json::from_str(&attrs_json).unwrap_or_default();
            if crate::stores::sql::locate_query::is_due_for_rotation(&attrs, now) {
                due.push((uid, owner));
            }
        }
        Ok(due)
    }

    async fn find_by_rotate_name(
        &self,
        name: &str,
        generation: Option<i32>,
        owner: &UserId,
    ) -> InterfaceResult<Vec<(String, Attributes)>> {
        let locate = find_by_rotate_name_query::<SqlitePlaceholder>(name, generation, owner);
        let sql = replace_dollars_with_qn(&locate.sql);
        let locate_params = locate.params;
        let rows = self
            .reader()
            .call(
                move |c: &mut rusqlite::Connection| -> Result<
                    Vec<(String, String)>,
                    rusqlite::Error,
                > {
                    let mut stmt = c.prepare(&sql)?;
                    let values: Vec<rusqlite::types::Value> = locate_params
                        .into_iter()
                        .map(|p| match p {
                            crate::stores::sql::locate_query::LocateParam::Text(s) => {
                                rusqlite::types::Value::Text(s)
                            }
                            crate::stores::sql::locate_query::LocateParam::I64(i) => {
                                rusqlite::types::Value::Integer(i)
                            }
                        })
                        .collect();
                    let mut q = stmt.query(rusqlite::params_from_iter(values.iter()))?;
                    let mut out = Vec::new();
                    while let Some(r) = q.next()? {
                        let id: String = r.get(0)?;
                        let attrs_json: String = r.get(1)?;
                        out.push((id, attrs_json));
                    }
                    Ok(out)
                },
            )
            .await
            .map_err(DbError::from)?;

        let mut results = Vec::new();
        for (uid, attrs_json) in rows {
            let attrs: Attributes = serde_json::from_str(&attrs_json).unwrap_or_default();
            results.push((uid, attrs));
        }
        Ok(results)
    }

    async fn find_all(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        vendor_id: &str,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        let locate =
            query_all_from_attributes::<SqlitePlaceholder>(researched_attributes, state, vendor_id);
        let sql_conversion = replace_dollars_with_qn(&locate.sql);
        let locate_params = locate.params;
        let rows = self.reader()
            .call(move |c: &mut rusqlite::Connection| -> Result<Vec<(String, State, Attributes)>, rusqlite::Error> {
                let mut stmt = c.prepare(&sql_conversion)?;
                let values: Vec<rusqlite::types::Value> = locate_params
                    .into_iter()
                    .map(|p| match p {
                        crate::stores::sql::locate_query::LocateParam::Text(s) => {
                            rusqlite::types::Value::Text(s)
                        }
                        crate::stores::sql::locate_query::LocateParam::I64(i) => {
                            rusqlite::types::Value::Integer(i)
                        }
                    })
                    .collect();
                let mut q = stmt.query(rusqlite::params_from_iter(values.iter()))?;
                let mut out = Vec::new();
                while let Some(r) = q.next()? {
                    let id: String = r.get(0)?;
                    let state_str: String = r.get(1)?;
                    let state = State::try_from(state_str.as_str())
                        .map_err(|_err| rusqlite::Error::InvalidQuery)?;
                    let raw: String = r.get(2)?;
                    let attrs = if raw.is_empty() {
                        Attributes::default()
                    } else {
                        serde_json::from_str::<Attributes>(&raw)
                            .map_err(|_err| rusqlite::Error::InvalidQuery)?
                    };
                    out.push((id, state, attrs));
                }
                Ok(out)
            })
            .await
            .map_err(DbError::from)?;
        Ok(rows)
    }

    async fn count_all_non_destroyed(&self) -> InterfaceResult<u64> {
        let sql = get_sqlite_query!("count-all-non-destroyed");
        let count = self
            .reader()
            .call(
                |c: &mut rusqlite::Connection| -> Result<u64, rusqlite::Error> {
                    c.query_row(sql, [], |row| row.get(0))
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(count)
    }

    async fn count_non_destroyed_keys(&self) -> InterfaceResult<u64> {
        // Object JSON is stored as {"SymmetricKey": {...}} — the variant
        // name is the top-level key.  Use json_type() to check presence.
        let sql = get_sqlite_query!("count-non-destroyed-keys");
        let count = self
            .reader()
            .call(
                |c: &mut rusqlite::Connection| -> Result<u64, rusqlite::Error> {
                    c.query_row(sql, [], |row| row.get(0))
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(count)
    }
}

#[async_trait(?Send)]
impl Migrate for SqlitePool {
    async fn get_db_state(&self) -> DbResult<Option<DbState>> {
        let select_param = replace_dollars_with_qn(
            PGSQL_QUERIES
                .get("select-parameter")
                .ok_or_else(|| db_error!("select-parameter SQL query can't be found"))?,
        );
        let res: Option<String> = self
            .reader()
            .call(
                move |c: &mut rusqlite::Connection| -> Result<Option<String>, rusqlite::Error> {
                    let mut stmt = c.prepare_cached(&select_param)?;
                    let row = stmt
                        .query_row(params_from_iter([&"db_state"]), |row| {
                            row.get::<_, String>(0)
                        })
                        .optional()?;
                    Ok(row)
                },
            )
            .await
            .map_err(DbError::from)?;
        match res {
            Some(s) => Ok(Some(serde_json::from_str(&s)?)),
            None => Ok(None),
        }
    }

    async fn set_db_state(&self, state: DbState) -> DbResult<()> {
        let upsert_param = replace_dollars_with_qn(
            PGSQL_QUERIES
                .get("upsert-parameter")
                .ok_or_else(|| db_error!("upsert-parameter SQL query can't be found"))?,
        );
        let state_json = serde_json::to_string(&state)?;
        self.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(
                        &upsert_param,
                        params_from_iter([&"db_state", &state_json.as_str()]),
                    )?;
                    tx.commit()?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn get_current_db_version(&self) -> DbResult<Option<String>> {
        let select_param = replace_dollars_with_qn(
            PGSQL_QUERIES
                .get("select-parameter")
                .ok_or_else(|| db_error!("select-parameter SQL query can't be found"))?,
        );
        let res: Option<String> = self
            .reader()
            .call(
                move |c: &mut rusqlite::Connection| -> Result<Option<String>, rusqlite::Error> {
                    let mut stmt = c.prepare_cached(&select_param)?;
                    let row = stmt
                        .query_row(params_from_iter([&"db_version"]), |row| {
                            row.get::<_, String>(0)
                        })
                        .optional()?;
                    Ok(row)
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(res)
    }

    async fn set_current_db_version(&self, version: &str) -> DbResult<()> {
        let upsert_param = replace_dollars_with_qn(
            PGSQL_QUERIES
                .get("upsert-parameter")
                .ok_or_else(|| db_error!("upsert-parameter SQL query can't be found"))?,
        );
        let version_s = version.to_owned();
        self.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(
                        &upsert_param,
                        params_from_iter([&"db_version", &version_s.as_str()]),
                    )?;
                    tx.commit()?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl PermissionsStore for SqlitePool {
    async fn list_user_operations_granted(
        &self,
        user: &UserId,
    ) -> InterfaceResult<HashMap<String, (String, State, HashSet<KmipOperation>)>> {
        let sql = get_sqlite_query!("select-objects-access-obtained").to_string();
        let user_s: String = user.as_str().to_owned();
        let list = self
            .reader()
            .call(
                move |c: &mut rusqlite::Connection| -> Result<
                    HashMap<String, (String, State, HashSet<KmipOperation>)>,
                    rusqlite::Error,
                > {
                    let mut stmt = c.prepare_cached(&sql)?;
                    let mut rows = stmt.query(params_from_iter([&user_s]))?;
                    let mut ids: HashMap<String, (String, State, HashSet<KmipOperation>)> =
                        HashMap::new();
                    while let Some(r) = rows.next()? {
                        let id: String = r.get(0)?;
                        let owner: String = r.get(1)?;
                        let state_str: String = r.get(2)?;
                        let state = State::try_from(state_str.as_str())
                            .map_err(|_err| rusqlite::Error::InvalidQuery)?;
                        let perms_raw: String = r.get(3)?;
                        let perms: HashSet<KmipOperation> = serde_json::from_str(&perms_raw)
                            .map_err(|_err| rusqlite::Error::InvalidQuery)?;
                        ids.insert(id, (owner, state, perms));
                    }
                    Ok(ids)
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(list)
    }

    async fn list_object_operations_granted(
        &self,
        uid: &str,
    ) -> InterfaceResult<HashMap<String, HashSet<KmipOperation>>> {
        let sql = get_sqlite_query!("select-rows-read_access-with-object-id").to_string();
        let uid_s = uid.to_owned();
        let map = self.reader()
            .call(move |c: &mut rusqlite::Connection| -> Result<HashMap<String, HashSet<KmipOperation>>, rusqlite::Error> {
                let mut stmt = c.prepare_cached(&sql)?;
                let mut rows = stmt.query(params_from_iter([&uid_s]))?;
                let mut ids: HashMap<String, HashSet<KmipOperation>> = HashMap::new();
                while let Some(r) = rows.next()? {
                    let user: String = r.get(0)?;
                    let perms_val: Value = r.get(1)?;
                    let perms: HashSet<KmipOperation> = serde_json::from_value(perms_val)
                        .map_err(|_err| rusqlite::Error::InvalidQuery)?;
                    ids.insert(user, perms);
                }
                Ok(ids)
            })
            .await
            .map_err(DbError::from)?;
        Ok(map)
    }

    async fn grant_operations(
        &self,
        uid: &str,
        user: &UserId,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()> {
        let sql_select = get_sqlite_query!("select-user-accesses-for-object").to_string();
        let sql_upsert = replace_dollars_with_qn(get_sqlite_query!("upsert-row-read_access"));
        let uid_s = uid.to_owned();
        let user_s: String = user.as_str().to_owned();
        self.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let mut stmt = c.prepare_cached(&sql_select)?;
                    let mut perms: HashSet<KmipOperation> = stmt
                        .query_row(params_from_iter([&uid_s, &user_s]), |row| {
                            let raw: String = row.get(0)?;
                            let p: HashSet<KmipOperation> = serde_json::from_str(&raw)
                                .map_err(|_err| rusqlite::Error::InvalidQuery)?;
                            Ok(p)
                        })
                        .optional()?
                        .unwrap_or_default();
                    if operations.is_subset(&perms) {
                        return Ok(());
                    }
                    perms.extend(operations.iter().copied());
                    let json_str = serde_json::to_string(&perms)
                        .map_err(|_err| rusqlite::Error::InvalidQuery)?;
                    c.execute(&sql_upsert, params_from_iter([&uid_s, &user_s, &json_str]))?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn remove_operations(
        &self,
        uid: &str,
        user: &UserId,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()> {
        let sql_select = get_sqlite_query!("select-user-accesses-for-object").to_string();
        let sql_delete = replace_dollars_with_qn(get_sqlite_query!("delete-rows-read_access"));
        let sql_update =
            replace_dollars_with_qn(get_sqlite_query!("update-rows-read_access-with-permission"));
        let uid_s = uid.to_owned();
        let user_s: String = user.as_str().to_owned();
        let operations = operations.clone();
        self.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let mut stmt = c.prepare_cached(&sql_select)?;
                    let perms: HashSet<KmipOperation> = stmt
                        .query_row(params_from_iter([&uid_s, &user_s]), |row| {
                            let raw: String = row.get(0)?;
                            let p: HashSet<KmipOperation> = serde_json::from_str(&raw)
                                .map_err(|_err| rusqlite::Error::InvalidQuery)?;
                            Ok(p)
                        })
                        .optional()?
                        .unwrap_or_default();
                    let perms: HashSet<KmipOperation> =
                        perms.difference(&operations).copied().collect();
                    if perms.is_empty() {
                        c.execute(&sql_delete, params_from_iter([&uid_s, &user_s]))?;
                        return Ok(());
                    }
                    let json_str = serde_json::to_string(&perms)
                        .map_err(|_err| rusqlite::Error::InvalidQuery)?;
                    c.execute(&sql_update, params_from_iter([&uid_s, &user_s, &json_str]))?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &UserId,
        no_inherited_access: bool,
    ) -> InterfaceResult<HashSet<KmipOperation>> {
        let mut user_perms = self.perms(uid, user).await?;
        if !no_inherited_access && user != "*" {
            user_perms.extend(self.perms(uid, "*").await?);
        }
        Ok(user_perms)
    }

    async fn activate_crypto_officer_ceremony(
        &self,
        sealed_record: &str,
        activated_by: &str,
    ) -> InterfaceResult<()> {
        let sql = replace_dollars_with_qn(get_sqlite_query!("insert-crypto-officer-activation"));
        let sealed = sealed_record.to_owned();
        let activated_by_s = activated_by.to_owned();
        self.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(&sql, params_from_iter([&sealed, &activated_by_s]))?;
                    tx.commit()?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn get_crypto_officer_activation(&self) -> InterfaceResult<Option<String>> {
        let sql =
            replace_dollars_with_qn(get_sqlite_query!("select-active-crypto-officer-activation"));
        let result: Option<String> = self
            .reader()
            .call(
                move |c: &mut rusqlite::Connection| -> Result<Option<String>, rusqlite::Error> {
                    c.query_row(&sql, [], |row| row.get(0)).optional()
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(result)
    }

    async fn revoke_crypto_officer_activation(&self, revoked_by: &str) -> InterfaceResult<()> {
        let sql = replace_dollars_with_qn(get_sqlite_query!("revoke-crypto-officer-activation"));
        let revoked_by_s = revoked_by.to_owned();
        self.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(&sql, params_from_iter([&revoked_by_s]))?;
                    tx.commit()?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn upsert_crl(
        &self,
        issuer_id: &str,
        crl_der: &[u8],
        crl_number: u64,
        generated_at: &str,
        next_update: &str,
    ) -> InterfaceResult<()> {
        let sql = replace_dollars_with_qn(get_sqlite_query!("upsert-crl"));
        let issuer_id_s = issuer_id.to_owned();
        let crl_der_v = crl_der.to_vec();

        let crl_number_i = i64::try_from(crl_number).unwrap_or(i64::MAX);
        let generated_at_s = generated_at.to_owned();
        let next_update_s = next_update.to_owned();
        self.writer
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(
                        &sql,
                        rusqlite::params![
                            issuer_id_s,
                            crl_der_v,
                            crl_number_i,
                            generated_at_s,
                            next_update_s
                        ],
                    )?;
                    tx.commit()?;
                    Ok(())
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn get_crl(&self, issuer_id: &str) -> InterfaceResult<Option<(Vec<u8>, String)>> {
        let sql = replace_dollars_with_qn(get_sqlite_query!("select-crl"));
        let issuer_id_s = issuer_id.to_owned();
        let result: Option<(Vec<u8>, String)> = self
            .reader()
            .call(
                move |c: &mut rusqlite::Connection| -> Result<
                    Option<(Vec<u8>, String)>,
                    rusqlite::Error,
                > {
                    c.query_row(&sql, rusqlite::params![issuer_id_s], |row| {
                        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
                    })
                    .optional()
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(result)
    }

    async fn list_crl_issuers(&self) -> InterfaceResult<Vec<(String, String)>> {
        let sql = replace_dollars_with_qn(get_sqlite_query!("list-crl-issuers"));
        let result: Vec<(String, String)> = self
            .reader()
            .call(
                move |c: &mut rusqlite::Connection| -> Result<Vec<(String, String)>, rusqlite::Error> {
                    let mut stmt = c.prepare_cached(&sql)?;
                    let mut q = stmt.query([])?;
                    let mut out = Vec::new();
                    while let Some(r) = q.next()? {
                        out.push((r.get::<_, String>(0)?, r.get::<_, String>(1)?));
                    }
                    Ok(out)
                },
            )
            .await
            .map_err(DbError::from)?;
        Ok(result)
    }
}

impl SqlitePool {
    async fn perms(&self, uid: &str, userid: &str) -> DbResult<HashSet<KmipOperation>> {
        let sql = get_sqlite_query!("select-user-accesses-for-object").to_string();
        let uid_s = uid.to_owned();
        let user_s = userid.to_owned();
        self.reader()
            .call(move |c: &mut rusqlite::Connection| -> Result<HashSet<KmipOperation>, rusqlite::Error> {
                let mut stmt = c.prepare_cached(&sql)?;
                let res = stmt
                    .query_row(params_from_iter([&uid_s, &user_s]), |row| {
                        let raw: String = row.get(0)?;
                        let p: HashSet<KmipOperation> = serde_json::from_str(&raw)
                            .map_err(|_err| rusqlite::Error::InvalidQuery)?;
                        Ok(p)
                    })
                    .optional()?;
                Ok(res.unwrap_or_default())
            })
            .await
            .map_err(DbError::from)
    }
}

fn create_sqlite(
    tx: &rusqlite::Transaction<'_>,
    uid: Option<String>,
    owner: &str,
    object: &Object,
    attributes: &Attributes,
    tags: &HashSet<String>,
) -> DbResult<String> {
    // If an explicit UID is provided and already exists, return a clear error
    if let Some(ref explicit_uid) = uid {
        let mut stmt = tx.prepare_cached("SELECT 1 FROM objects WHERE id=?1 LIMIT 1")?;
        let exists = stmt.exists(params_from_iter([explicit_uid]))?;
        if exists {
            return Err(DbError::DatabaseError(
                "one or more objects already exist".to_owned(),
            ));
        }
    }
    let object_json = serde_json::to_string(object).map_err(|e| {
        DbError::DatabaseError(format!("failed serializing the object to JSON: {e}"))
    })?;
    let attributes_json = serde_json::to_string(attributes).map_err(|e| {
        DbError::DatabaseError(format!("failed serializing the attributes to JSON: {e}"))
    })?;
    let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());
    let wrapping_key_id = object.wrapping_key_uid();

    let sql = replace_dollars_with_qn(get_sqlite_query!("insert-objects"));
    let state_s = attributes.state.unwrap_or(State::PreActive).to_string();
    let owner_s: String = owner.to_owned();
    let domain_s = String::new();
    tx.execute(
        &sql,
        rusqlite::params![
            uid,
            object_json,
            attributes_json,
            state_s,
            owner_s,
            wrapping_key_id,
            domain_s
        ],
    )?;

    let sql = replace_dollars_with_qn(get_sqlite_query!("insert-tags"));
    for tag in tags {
        tx.execute(&sql, params_from_iter([&uid, tag.as_str()]))?;
    }
    Ok(uid)
}

fn update_object_sqlite(
    tx: &rusqlite::Transaction<'_>,
    uid: &str,
    object: &Object,
    attributes: &Attributes,
    tags: Option<&HashSet<String>>,
) -> DbResult<()> {
    let object_json = serde_json::to_string(object).map_err(|e| {
        DbError::DatabaseError(format!("failed serializing the object to JSON: {e}"))
    })?;
    let attributes_json = serde_json::to_string(attributes).map_err(|e| {
        DbError::DatabaseError(format!("failed serializing the attributes to JSON: {e}"))
    })?;
    let wrapping_key_id = object.wrapping_key_uid();
    let sql = replace_dollars_with_qn(get_sqlite_query!("update-object-with-object"));
    let uid_s = uid.to_owned();
    tx.execute(
        &sql,
        rusqlite::params![object_json, attributes_json, wrapping_key_id, uid_s],
    )?;
    if let Some(tags) = tags {
        let del = replace_dollars_with_qn(get_sqlite_query!("delete-tags"));
        tx.execute(&del, params_from_iter([&uid_s]))?;
        let ins = replace_dollars_with_qn(get_sqlite_query!("insert-tags"));
        for tag in tags {
            tx.execute(&ins, params_from_iter([&uid_s, tag.as_str()]))?;
        }
    }
    Ok(())
}

fn upsert_sqlite(
    tx: &rusqlite::Transaction<'_>,
    uid: &str,
    owner: &str,
    object: &Object,
    attributes: &Attributes,
    tags: Option<&HashSet<String>>,
    state: State,
) -> DbResult<()> {
    let object_json = serde_json::to_string(object).map_err(|e| {
        DbError::DatabaseError(format!("failed serializing the object to JSON: {e}"))
    })?;
    let attributes_json = serde_json::to_string(attributes).map_err(|e| {
        DbError::DatabaseError(format!("failed serializing the attributes to JSON: {e}"))
    })?;
    let wrapping_key_id = object.wrapping_key_uid();
    let sql = replace_dollars_with_qn(get_sqlite_query!("upsert-object"));
    let state_s = state.to_string();
    let uid_s = uid.to_owned();
    let owner_s: String = owner.to_owned();
    tx.execute(
        &sql,
        rusqlite::params![
            uid_s,
            object_json,
            attributes_json,
            state_s,
            owner_s,
            wrapping_key_id
        ],
    )?;
    if let Some(tags) = tags {
        let del = replace_dollars_with_qn(get_sqlite_query!("delete-tags"));
        tx.execute(&del, params_from_iter([&uid_s]))?;
        let ins = replace_dollars_with_qn(get_sqlite_query!("insert-tags"));
        for tag in tags {
            tx.execute(&ins, params_from_iter([&uid_s, tag.as_str()]))?;
        }
    }
    Ok(())
}

// atomic_sqlite replaced by apply_owned_ops using an owned op representation

#[derive(Clone)]
enum OwnedOp {
    Create((String, Object, Attributes, HashSet<String>)),
    Upsert((String, Object, Attributes, Option<HashSet<String>>, State)),
    UpdateObject((String, Object, Attributes, Option<HashSet<String>>)),
    UpdateState((String, State)),
    Delete(String),
}

impl From<&AtomicOperation> for OwnedOp {
    fn from(op: &AtomicOperation) -> Self {
        match op {
            AtomicOperation::Create((uid, _owner, obj, attrs, tags)) => {
                Self::Create((uid.clone(), obj.clone(), attrs.clone(), tags.clone()))
            }
            AtomicOperation::Upsert((uid, obj, attrs, tags, state)) => Self::Upsert((
                uid.clone(),
                obj.clone(),
                attrs.clone(),
                tags.clone(),
                *state,
            )),
            AtomicOperation::UpdateObject((uid, obj, attrs, tags)) => {
                Self::UpdateObject((uid.clone(), obj.clone(), attrs.clone(), tags.clone()))
            }
            AtomicOperation::UpdateState((uid, state)) => Self::UpdateState((uid.clone(), *state)),
            AtomicOperation::Delete(uid) => Self::Delete(uid.clone()),
        }
    }
}

fn apply_owned_ops(
    tx: &rusqlite::Transaction<'_>,
    owner: &str,
    ops: &[OwnedOp],
) -> DbResult<Vec<String>> {
    let mut uids = Vec::with_capacity(ops.len());
    for op in ops {
        match op {
            OwnedOp::Create((uid, obj, attrs, tags)) => {
                create_sqlite(tx, Some(uid.clone()), owner, obj, attrs, tags)?;
                uids.push(uid.clone());
            }
            OwnedOp::Upsert((uid, obj, attrs, tags, state)) => {
                upsert_sqlite(tx, uid, owner, obj, attrs, tags.as_ref(), *state)?;
                uids.push(uid.clone());
            }
            OwnedOp::UpdateObject((uid, obj, attrs, tags)) => {
                update_object_sqlite(tx, uid, obj, attrs, tags.as_ref())?;
                uids.push(uid.clone());
            }
            OwnedOp::UpdateState((uid, state)) => {
                let sql = replace_dollars_with_qn(get_sqlite_query!("update-object-with-state"));
                let state_s = state.to_string();
                tx.execute(&sql, params_from_iter([&state_s, uid]))?;
                uids.push(uid.clone());
            }
            OwnedOp::Delete(uid) => {
                let del_obj = replace_dollars_with_qn(get_sqlite_query!("delete-object"));
                tx.execute(&del_obj, params_from_iter([uid]))?;
                let del_tags = replace_dollars_with_qn(get_sqlite_query!("delete-tags"));
                tx.execute(&del_tags, params_from_iter([uid]))?;
                let del_access =
                    replace_dollars_with_qn(get_sqlite_query!("delete-read-access-for-object"));
                tx.execute(&del_access, params_from_iter([uid]))?;
                uids.push(uid.clone());
            }
        }
    }
    Ok(uids)
}
