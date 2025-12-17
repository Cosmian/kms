use crate::db_error;
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
use rawsql::Loader;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tokio_postgres::{
    NoTls,
    types::{Json, ToSql},
};
use uuid::Uuid;

use crate::{
    error::{DbError, DbResult},
    migrate_block_cipher_mode_if_needed,
    stores::{PGSQL_QUERIES, sql::database::SqlDatabase},
};

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
        let mut cfg = PgConfig::new();
        cfg.url = Some(connection_url.to_owned());
        cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });
        if let Some(max) = max_connections {
            cfg.pool = Some(deadpool_postgres::PoolConfig {
                max_size: usize::try_from(max).unwrap_or(usize::MAX),
                ..Default::default()
            });
        }
        let pool = cfg
            .create_pool(None, NoTls)
            .map_err(|e| DbError::DatabaseError(e.to_string()))?;
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
            client
                .batch_execute(sql)
                .await
                .map_err(|e| DbError::DatabaseError(e.to_string()))?;
        }
        // Ensure attributes column is jsonb (and convert if needed)
        client
            .batch_execute(
                "ALTER TABLE objects ALTER COLUMN attributes TYPE jsonb USING attributes::jsonb;",
            )
            .await
            .map_err(|e| DbError::DatabaseError(e.to_string()))?;

        // Optionally clear any existing data (useful for tests)
        if clear_database {
            for name in [
                // Remove dependent rows first to avoid potential constraints if present
                "clean-table-read_access",
                "clean-table-tags",
                "clean-table-objects",
            ] {
                let sql = tmp_loader.get_query(name)?;
                client
                    .batch_execute(sql)
                    .await
                    .map_err(|e| DbError::DatabaseError(e.to_string()))?;
            }
        }
        Ok(Self { pool })
    }
}

impl SqlDatabase for PgPool {
    fn get_loader(&self) -> &Loader {
        &PGSQL_QUERIES
    }
}

#[async_trait(?Send)]
impl ObjectsStore for PgPool {
    fn filename(&self, _group_id: u128) -> Option<std::path::PathBuf> {
        None
    }

    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
    ) -> InterfaceResult<String> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());
        let object_json =
            serde_json::to_string(object).map_err(|e| InterfaceError::Db(e.to_string()))?;
        let attributes_json =
            serde_json::to_value(attributes).map_err(|e| InterfaceError::Db(e.to_string()))?;
        let state = attributes.state.unwrap_or(State::PreActive).to_string();
        let stmt = tx
            .prepare(get_pgsql_query!("insert-objects"))
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let attrs_param = Json(&attributes_json);
        {
            let params: &[&(dyn ToSql + Sync)] =
                &[&uid, &object_json, &attrs_param, &state, &owner];
            tx.execute(&stmt, params)
                .await
                .map_err(|e| InterfaceError::Db(crate::error::DbError::from(e).to_string()))?;
        }
        if !tags.is_empty() {
            let transaction_stmt = tx
                .prepare(get_pgsql_query!("insert-tags"))
                .await
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
            for tag in tags {
                let params: &[&(dyn ToSql + Sync)] = &[&uid, tag];
                tx.execute(&transaction_stmt, params)
                    .await
                    .map_err(|e| InterfaceError::Db(crate::error::DbError::from(e).to_string()))?;
            }
        }
        tx.commit()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        Ok(uid)
    }

    async fn retrieve(&self, uid: &str) -> InterfaceResult<Option<ObjectWithMetadata>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let stmt = client
            .prepare(get_pgsql_query!("select-object"))
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let params: &[&(dyn ToSql + Sync)] = &[&uid];
        let rows = client
            .query(&stmt, params)
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        if let Some(row) = rows.first() {
            let id: String = row.get(0);
            let object_json: String = row.get(1);
            let object: Object = serde_json::from_str(&object_json)
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
            let object = migrate_block_cipher_mode_if_needed(object);
            let attributes_val: Value = row.get(2);
            let attributes: Attributes = serde_json::from_value(attributes_val)
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
            let owner: String = row.get(3);
            let state_str: String = row.get(4);
            let state = State::try_from(state_str.as_str())
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
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
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let stmt = client
            .prepare(get_pgsql_query!("select-tags"))
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let params: &[&(dyn ToSql + Sync)] = &[&uid];
        let rows = client
            .query(&stmt, params)
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
    ) -> InterfaceResult<()> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let object_json =
            serde_json::to_string(object).map_err(|e| InterfaceError::Db(e.to_string()))?;
        let attributes_json =
            serde_json::to_value(attributes).map_err(|e| InterfaceError::Db(e.to_string()))?;
        let stmt = tx
            .prepare(get_pgsql_query!("update-object-with-object"))
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let attrs_param = Json(&attributes_json);
        {
            let params: &[&(dyn ToSql + Sync)] = &[&object_json, &attrs_param, &uid];
            tx.execute(&stmt, params)
                .await
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
        }
        if let Some(tags) = tags {
            let delete_stmt = tx
                .prepare(get_pgsql_query!("delete-tags"))
                .await
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
            {
                let params: &[&(dyn ToSql + Sync)] = &[&uid];
                tx.execute(&delete_stmt, params)
                    .await
                    .map_err(|e| InterfaceError::Db(e.to_string()))?;
            }
            let insert_stmt = tx
                .prepare(get_pgsql_query!("insert-tags"))
                .await
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
            for tag in tags {
                let params: &[&(dyn ToSql + Sync)] = &[&uid, tag];
                tx.execute(&insert_stmt, params)
                    .await
                    .map_err(|e| InterfaceError::Db(e.to_string()))?;
            }
        }
        tx.commit()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        Ok(())
    }

    async fn update_state(&self, uid: &str, state: State) -> InterfaceResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let stmt = client
            .prepare(get_pgsql_query!("update-object-with-state"))
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let s = state.to_string();
        {
            let params: &[&(dyn ToSql + Sync)] = &[&s, &uid];
            client
                .execute(&stmt, params)
                .await
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
        }
        Ok(())
    }

    async fn delete(&self, uid: &str) -> InterfaceResult<()> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let d1 = tx
            .prepare(get_pgsql_query!("delete-object"))
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        {
            let params: &[&(dyn ToSql + Sync)] = &[&uid];
            tx.execute(&d1, params)
                .await
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
        }
        let d2 = tx
            .prepare(get_pgsql_query!("delete-tags"))
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        {
            let params: &[&(dyn ToSql + Sync)] = &[&uid];
            tx.execute(&d2, params)
                .await
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
        }
        tx.commit()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        Ok(())
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
    ) -> InterfaceResult<Vec<String>> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let mut uids = Vec::with_capacity(operations.len());
        for op in operations {
            match op {
                AtomicOperation::Create((uid, object, attributes, tags)) => {
                    let new_uid = self
                        .create(Some(uid.clone()), user, object, attributes, tags)
                        .await?;
                    uids.push(new_uid);
                }
                AtomicOperation::UpdateObject((uid, object, attributes, tags)) => {
                    self.update_object(uid, object, attributes, tags.as_ref())
                        .await?;
                    uids.push(uid.clone());
                }
                AtomicOperation::UpdateState((uid, state)) => {
                    self.update_state(uid, *state).await?;
                    uids.push(uid.clone());
                }
                AtomicOperation::Upsert((uid, object, attributes, tags, state)) => {
                    // emulate upsert via object upsert query
                    let object_json = serde_json::to_string(object)
                        .map_err(|e| InterfaceError::Db(e.to_string()))?;
                    let attributes_json = serde_json::to_value(attributes)
                        .map_err(|e| InterfaceError::Db(e.to_string()))?;
                    let stmt = tx
                        .prepare(get_pgsql_query!("upsert-object"))
                        .await
                        .map_err(|e| InterfaceError::Db(e.to_string()))?;
                    let st = state.to_string();
                    let attrs_param = Json(&attributes_json);
                    {
                        let params: &[&(dyn ToSql + Sync)] =
                            &[&uid, &object_json, &attrs_param, &st, &user];
                        tx.execute(&stmt, params)
                            .await
                            .map_err(|e| InterfaceError::Db(e.to_string()))?;
                    }
                    if let Some(tags) = tags {
                        let delete_stmt = tx
                            .prepare(get_pgsql_query!("delete-tags"))
                            .await
                            .map_err(|e| InterfaceError::Db(e.to_string()))?;
                        {
                            let params: &[&(dyn ToSql + Sync)] = &[&uid];
                            tx.execute(&delete_stmt, params)
                                .await
                                .map_err(|e| InterfaceError::Db(e.to_string()))?;
                        }
                        let insert_stmt = tx
                            .prepare(get_pgsql_query!("insert-tags"))
                            .await
                            .map_err(|e| InterfaceError::Db(e.to_string()))?;
                        for tag in tags {
                            let params: &[&(dyn ToSql + Sync)] = &[&uid, tag];
                            tx.execute(&insert_stmt, params)
                                .await
                                .map_err(|e| InterfaceError::Db(e.to_string()))?;
                        }
                    }
                    uids.push(uid.clone());
                }
                AtomicOperation::Delete(uid) => {
                    self.delete(uid).await?;
                    uids.push(uid.clone());
                }
            }
        }
        tx.commit()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        Ok(uids)
    }

    async fn is_object_owned_by(&self, uid: &str, owner: &str) -> InterfaceResult<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let stmt = client
            .prepare(get_pgsql_query!("has-row-objects"))
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let params: &[&(dyn ToSql + Sync)] = &[&uid, &owner];
        let row = client
            .query_opt(&stmt, params)
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        Ok(row.is_some())
    }

    async fn list_uids_for_tags(&self, tags: &HashSet<String>) -> InterfaceResult<HashSet<String>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
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
            .map_err(|e| InterfaceError::Db(format!("tags query exec failed: {e}")))?;
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
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let query = crate::stores::sql::locate_query::query_from_attributes::<
            crate::stores::sql::locate_query::PgSqlPlaceholder,
        >(researched_attributes, state, user, user_must_be_owner);
        cosmian_logger::debug!("PG find query: {query}");
        let stmt = client
            .prepare(&query)
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let params: Vec<&(dyn ToSql + Sync)> = if user_must_be_owner {
            vec![&user]
        } else {
            vec![&user, &user, &user]
        };
        let rows = client
            .query(&stmt, &params)
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            let uid: String = row.get(0);
            let state_str: String = row.get(1);
            let state = State::try_from(state_str.as_str())
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
            let attrs_val: Value = row.get(2);
            let attrs: Attributes =
                serde_json::from_value(attrs_val).map_err(|e| InterfaceError::Db(e.to_string()))?;
            out.push((uid, state, attrs));
        }
        Ok(out)
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
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let stmt = client
            .prepare(get_pgsql_query!("select-objects-access-obtained"))
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let params: &[&(dyn ToSql + Sync)] = &[&user];
        let rows = client
            .query(&stmt, params)
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
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
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let stmt = client
            .prepare(get_pgsql_query!("select-rows-read_access-with-object-id"))
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let params: &[&(dyn ToSql + Sync)] = &[&uid];
        let rows = client
            .query(&stmt, params)
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
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
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        // Merge with existing permissions
        let existing = self.list_user_operations_on_object(uid, user, true).await?;
        let mut combined = existing;
        combined.extend(operations);
        let json =
            serde_json::to_value(&combined).map_err(|e| InterfaceError::Db(e.to_string()))?;
        let stmt = client
            .prepare(get_pgsql_query!("upsert-row-read_access"))
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        {
            let params: &[&(dyn ToSql + Sync)] = &[&uid, &user, &json];
            client
                .execute(&stmt, params)
                .await
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
        }
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
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let current = self.list_user_operations_on_object(uid, user, true).await?;
        let remaining: HashSet<KmipOperation> = current.difference(&operations).copied().collect();
        if remaining.is_empty() {
            let d = client
                .prepare(get_pgsql_query!("delete-rows-read_access"))
                .await
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
            {
                let params: &[&(dyn ToSql + Sync)] = &[&uid, &user];
                client
                    .execute(&d, params)
                    .await
                    .map_err(|e| InterfaceError::Db(e.to_string()))?;
            }
            return Ok(());
        }
        let json =
            serde_json::to_value(&remaining).map_err(|e| InterfaceError::Db(e.to_string()))?;
        let u = client
            .prepare(get_pgsql_query!("update-rows-read_access-with-permission"))
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        {
            let params: &[&(dyn ToSql + Sync)] = &[&uid, &user, &json];
            client
                .execute(&u, params)
                .await
                .map_err(|e| InterfaceError::Db(e.to_string()))?;
        }
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
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let stmt = client
            .prepare(get_pgsql_query!("select-user-accesses-for-object"))
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?;
        let mut perms: HashSet<KmipOperation> = match client
            .query_opt(&stmt, &[&uid, &user])
            .await
            .map_err(|e| InterfaceError::Db(e.to_string()))?
        {
            Some(row) => {
                let v: Value = row.get(0);
                serde_json::from_value(v).map_err(|e| InterfaceError::Db(e.to_string()))?
            }
            None => HashSet::new(),
        };
        if !no_inherited_access && user != "*" {
            if let Some(row) = client
                .query_opt(&stmt, &[&uid, &"*"])
                .await
                .map_err(|e| InterfaceError::Db(e.to_string()))?
            {
                let v: Value = row.get(0);
                let all: HashSet<KmipOperation> =
                    serde_json::from_value(v).map_err(|e| InterfaceError::Db(e.to_string()))?;
                perms.extend(all);
            }
        }
        Ok(perms)
    }
}
