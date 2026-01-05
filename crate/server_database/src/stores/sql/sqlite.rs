// SQLite backend implementation using tokio-rusqlite
use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use async_trait::async_trait;
use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{KmipOperation, kmip_attributes::Attributes, kmip_objects::Object},
};
use cosmian_kms_interfaces::{
    AtomicOperation, InterfaceError, InterfaceResult, ObjectWithMetadata, ObjectsStore,
    PermissionsStore,
};
use rawsql::Loader;
use rusqlite::{OptionalExtension, Row, params_from_iter};
use serde_json::Value;
use tokio_rusqlite::Connection;
use uuid::Uuid;

use super::locate_query::{SqlitePlaceholder, query_from_attributes};
use crate::db_error;
use crate::{
    error::{DbError, DbResult},
    migrate_block_cipher_mode_if_needed,
    stores::{SQLITE_QUERIES, sql::database::SqlDatabase},
};

macro_rules! get_sqlite_query {
    ($name:literal) => {
        SQLITE_QUERIES
            .get($name)
            .ok_or_else(|| db_error!("{} SQL query can't be found", $name))?
    };
}

#[derive(Clone)]
pub(crate) struct SqlitePool {
    conn: Connection,
}

impl SqlitePool {
    pub(crate) async fn instantiate(
        path: &Path,
        clear_database: bool,
        _max_connections: Option<u32>,
    ) -> DbResult<Self> {
        let conn = Connection::open(path).await?;
        let pool = Self { conn };
        // Bootstrap schema and optionally clear database on startup, using trait queries
        let create_parameters = pool.get_query("create-table-parameters")?.to_owned();
        let create_objects = pool.get_query("create-table-objects")?.to_owned();
        let create_read_access = pool.get_query("create-table-read_access")?.to_owned();
        let create_tags = pool.get_query("create-table-tags")?.to_owned();
        let clean_objects = pool.get_query("clean-table-objects")?.to_owned();
        let clean_read_access = pool.get_query("clean-table-read_access")?.to_owned();
        let clean_tags = pool.get_query("clean-table-tags")?.to_owned();
        pool.conn
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(&create_parameters, [])?;
                    tx.execute(&create_objects, [])?;
                    tx.execute(&create_read_access, [])?;
                    tx.execute(&create_tags, [])?;
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

        Ok(pool)
    }
}

impl SqlDatabase for SqlitePool {
    fn get_loader(&self) -> &Loader {
        &SQLITE_QUERIES
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
    let object: Object = serde_json::from_str(&object_json)?;
    let object = migrate_block_cipher_mode_if_needed(object);
    let attributes: Attributes = serde_json::from_str(&attributes_json)?;
    let state =
        State::try_from(state_str.as_str()).map_err(|e| DbError::DatabaseError(e.to_string()))?;
    Ok(ObjectWithMetadata::new(
        id, object, owner, state, attributes,
    ))
}

#[async_trait(?Send)]
impl ObjectsStore for SqlitePool {
    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
    ) -> InterfaceResult<String> {
        let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());
        // If an explicit UID already exists, return a clear error matching CLI expectations
        let exists = self
            .conn
            .call({
                let uid_check = uid.clone();
                move |c: &mut rusqlite::Connection| -> Result<bool, rusqlite::Error> {
                    let mut stmt = c.prepare("SELECT 1 FROM objects WHERE id=?1 LIMIT 1")?;
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
        let owner_s = owner.to_owned();

        let insert_object = replace_dollars_with_qn(get_sqlite_query!("insert-objects"));
        let insert_tag = replace_dollars_with_qn(get_sqlite_query!("insert-tags"));

        let uid_clone = uid.clone();
        let tags_owned: HashSet<String> = tags.clone();
        self.conn
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    // Insert object
                    tx.execute(
                        &insert_object,
                        params_from_iter([
                            &uid_clone,
                            &object_json,
                            &attributes_json,
                            &state_s,
                            &owner_s,
                        ]),
                    )?;
                    // Insert tags
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
        let select_object = get_sqlite_query!("select-object").to_string();
        let uid_s = uid.to_owned();
        let res = self
            .conn
            .call(move |c: &mut rusqlite::Connection| -> Result<Option<ObjectWithMetadata>, rusqlite::Error> {
                let mut stmt = c.prepare(&select_object)?;
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
        let sql = get_sqlite_query!("select-tags").to_string();
        let uid_s = uid.to_owned();
        let tags = self
            .conn
            .call(
                move |c: &mut rusqlite::Connection| -> Result<HashSet<String>, rusqlite::Error> {
                    let mut stmt = c.prepare(&sql)?;
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

        let sql_update = replace_dollars_with_qn(get_sqlite_query!("update-object-with-object"));
        let sql_delete_tags = replace_dollars_with_qn(get_sqlite_query!("delete-tags"));
        let sql_insert_tag = replace_dollars_with_qn(get_sqlite_query!("insert-tags"));

        let uid_s = uid.to_owned();
        let tags_owned: Option<HashSet<String>> = tags.cloned();
        self.conn
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(
                        &sql_update,
                        params_from_iter([&object_json, &attributes_json, &uid_s]),
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
        self.conn
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
        let uid_s = uid.to_owned();
        self.conn
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let tx = c.transaction()?;
                    tx.execute(&del_obj, params_from_iter([&uid_s]))?;
                    tx.execute(&del_tags, params_from_iter([&uid_s]))?;
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
        user: &str,
        operations: &[AtomicOperation],
    ) -> InterfaceResult<Vec<String>> {
        let user_s = user.to_owned();
        let ops_owned: Vec<OwnedOp> = operations.iter().map(OwnedOp::from).collect();
        let v = self
            .conn
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

    async fn is_object_owned_by(&self, uid: &str, owner: &str) -> InterfaceResult<bool> {
        let sql = get_sqlite_query!("has-row-objects").to_string();
        let uid_s = uid.to_owned();
        let owner_s = owner.to_owned();
        let owned = self
            .conn
            .call(
                move |c: &mut rusqlite::Connection| -> Result<bool, rusqlite::Error> {
                    let mut stmt = c.prepare(&sql)?;
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
            .conn
            .call(
                move |c: &mut rusqlite::Connection| -> Result<HashSet<String>, rusqlite::Error> {
                    let mut stmt = c.prepare(&sql)?;
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
        user: &str,
        user_must_be_owner: bool,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        let sql = query_from_attributes::<SqlitePlaceholder>(
            researched_attributes,
            state,
            user,
            user_must_be_owner,
        );
        let sql_conversion = replace_dollars_with_qn(&sql);
        let user1 = user.to_owned();
        let user2 = user.to_owned();
        let user3 = user.to_owned();
        let rows = self
            .conn
            .call(move |c: &mut rusqlite::Connection| -> Result<Vec<(String, State, Attributes)>, rusqlite::Error> {
                let mut stmt = c.prepare(&sql_conversion)?;
                let params: Vec<&str> = if user_must_be_owner {
                    vec![user1.as_str()]
                } else {
                    vec![user1.as_str(), user2.as_str(), user3.as_str()]
                };
                let mut q = stmt.query(params_from_iter(params.iter()))?;
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
}

#[async_trait(?Send)]
impl PermissionsStore for SqlitePool {
    async fn list_user_operations_granted(
        &self,
        user: &str,
    ) -> InterfaceResult<HashMap<String, (String, State, HashSet<KmipOperation>)>> {
        let sql = get_sqlite_query!("select-objects-access-obtained").to_string();
        let user_s = user.to_owned();
        let list = self
            .conn
            .call(
                move |c: &mut rusqlite::Connection| -> Result<
                    HashMap<String, (String, State, HashSet<KmipOperation>)>,
                    rusqlite::Error,
                > {
                    let mut stmt = c.prepare(&sql)?;
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
        let map = self
            .conn
            .call(move |c: &mut rusqlite::Connection| -> Result<HashMap<String, HashSet<KmipOperation>>, rusqlite::Error> {
                let mut stmt = c.prepare(&sql)?;
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
        user: &str,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()> {
        let sql_select = get_sqlite_query!("select-user-accesses-for-object").to_string();
        let sql_upsert = replace_dollars_with_qn(get_sqlite_query!("upsert-row-read_access"));
        let uid_s = uid.to_owned();
        let user_s = user.to_owned();
        self.conn
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let mut stmt = c.prepare(&sql_select)?;
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
        user: &str,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()> {
        let sql_select = get_sqlite_query!("select-user-accesses-for-object").to_string();
        let sql_delete = replace_dollars_with_qn(get_sqlite_query!("delete-rows-read_access"));
        let sql_update =
            replace_dollars_with_qn(get_sqlite_query!("update-rows-read_access-with-permission"));
        let uid_s = uid.to_owned();
        let user_s = user.to_owned();
        let operations = operations.clone();
        self.conn
            .call(
                move |c: &mut rusqlite::Connection| -> Result<(), rusqlite::Error> {
                    let mut stmt = c.prepare(&sql_select)?;
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
        user: &str,
        no_inherited_access: bool,
    ) -> InterfaceResult<HashSet<KmipOperation>> {
        let mut user_perms = self.perms(uid, user).await?;
        if !no_inherited_access && user != "*" {
            user_perms.extend(self.perms(uid, "*").await?);
        }
        Ok(user_perms)
    }
}

impl SqlitePool {
    async fn perms(&self, uid: &str, userid: &str) -> DbResult<HashSet<KmipOperation>> {
        let sql = get_sqlite_query!("select-user-accesses-for-object").to_string();
        let uid_s = uid.to_owned();
        let user_s = userid.to_owned();
        self.conn
            .call(move |c: &mut rusqlite::Connection| -> Result<HashSet<KmipOperation>, rusqlite::Error> {
                let mut stmt = c.prepare(&sql)?;
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
        let mut stmt = tx.prepare("SELECT 1 FROM objects WHERE id=?1 LIMIT 1")?;
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

    let sql = replace_dollars_with_qn(get_sqlite_query!("insert-objects"));
    let state_s = attributes.state.unwrap_or(State::PreActive).to_string();
    let owner_s = owner.to_owned();
    tx.execute(
        &sql,
        params_from_iter([&uid, &object_json, &attributes_json, &state_s, &owner_s]),
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
    let sql = replace_dollars_with_qn(get_sqlite_query!("update-object-with-object"));
    let uid_s = uid.to_owned();
    tx.execute(
        &sql,
        params_from_iter([&object_json, &attributes_json, &uid_s]),
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
    let sql = replace_dollars_with_qn(get_sqlite_query!("upsert-object"));
    let state_s = state.to_string();
    let uid_s = uid.to_owned();
    let owner_s = owner.to_owned();
    tx.execute(
        &sql,
        params_from_iter([&uid_s, &object_json, &attributes_json, &state_s, &owner_s]),
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
            AtomicOperation::Create((uid, obj, attrs, tags)) => {
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
                uids.push(uid.clone());
            }
        }
    }
    Ok(uids)
}
