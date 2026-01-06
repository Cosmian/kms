use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use async_trait::async_trait;
use cosmian_kmip::{
    kmip_0::kmip_types::{ErrorReason, State},
    kmip_2_1::{KmipOperation, kmip_attributes::Attributes, kmip_objects::Object},
};
use cosmian_kms_interfaces::{
    AtomicOperation, InterfaceError, InterfaceResult, ObjectWithMetadata, ObjectsStore,
    PermissionsStore, SessionParams,
};
use cosmian_logger::{debug, trace};
use rawsql::Loader;
use serde_json::Value;
use sqlx::{
    ConnectOptions, Executor, Pool, Postgres, Row, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions, PgRow},
};
use uuid::Uuid;

use crate::{
    db_bail, db_error,
    error::{DbError, DbResult, DbResultHelper},
    migrate_block_cipher_mode_if_needed,
    stores::{
        PGSQL_QUERIES,
        migrate::HasDatabase,
        sql::{
            database::SqlDatabase,
            locate_query::{PgSqlPlaceholder, query_from_attributes},
            main_store::SqlMainStore,
        },
    },
};

#[macro_export]
macro_rules! get_pgsql_query {
    ($name:literal) => {
        PGSQL_QUERIES
            .get($name)
            .ok_or_else(|| db_error!("{} SQL query can't be found", $name))?
    };
    ($name:expr) => {
        PGSQL_QUERIES
            .get($name)
            .ok_or_else(|| db_error!("{} SQL query can't be found", $name))?
    };
}

/// Convert a row from the database into an `ObjectWithMetadata`
/// This function is used to convert the result of a `SELECT` query
/// into an `ObjectWithMetadata`
fn pg_row_to_owm(row: &PgRow) -> Result<ObjectWithMetadata, DbError> {
    let id = row.get::<String, _>(0);
    let object: Object = serde_json::from_str(&row.get::<String, _>(1))
        .context("failed deserializing the object")?;
    let object = migrate_block_cipher_mode_if_needed(object);
    let attributes: Attributes = serde_json::from_value(row.get::<Value, _>(2))
        .context("failed deserializing the Attributes")?;
    let owner = row.get::<String, _>(3);
    let state = State::try_from(row.get::<String, _>(4).as_str()).map_err(|e| {
        DbError::ConversionError(format!("failed converting the state: {e}").into())
    })?;
    Ok(ObjectWithMetadata::new(
        id, object, owner, state, attributes,
    ))
}

#[derive(Clone)]
pub(crate) struct PgPool {
    pool: Pool<Postgres>,
}

impl HasDatabase for PgPool {
    type Database = Postgres;
}

impl PgPool {
    /// Instantiate a new `Postgres` database
    /// and create the appropriate table(s) if need be
    pub(crate) async fn instantiate(
        connection_url: &str,
        clear_database: bool,
        max_connections: Option<u32>,
    ) -> DbResult<Self> {
        let options = PgConnectOptions::from_str(connection_url)?
            // disable logging of each query
            .disable_statement_logging();

        // Default rationale: small, CPU-aware pool. Postgres handles concurrency well,
        // but oversized pools increase contention and idle resource usage. Using
        // min(10, 2 × CPU cores) provides enough parallelism for typical APIs while
        // staying below common server max_connections and avoiding oversubscription.
        let default_conns: u32 = u32::try_from(num_cpus::get())
            .map(|c| c.saturating_mul(2).min(10))
            .unwrap_or(10);
        let max_conns: u32 = max_connections.unwrap_or(default_conns);
        let pool = PgPoolOptions::new()
            .max_connections(max_conns)
            .connect_with(options)
            .await?;

        // Instantiate the pool
        let pgsql_pool = Self { pool };

        // Blanket implementation of SqlMainStore for SqlDatabase
        pgsql_pool.start(clear_database).await?;

        Ok(pgsql_pool)
    }
}

impl SqlDatabase<Postgres> for PgPool {
    fn get_pool(&self) -> &Pool<Postgres> {
        &self.pool
    }

    fn get_loader(&self) -> &Loader {
        &PGSQL_QUERIES
    }
}

#[async_trait(?Send)]
impl ObjectsStore for PgPool {
    fn filename(&self, _group_id: u128) -> Option<PathBuf> {
        None
    }

    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<String> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("Failed to start a transaction: {e}")))?;
        let uid = match create_(uid, owner, object, attributes, tags, &mut tx).await {
            Ok(uid) => uid,
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                return Err(InterfaceError::Db(format!(
                    "creation of object failed: {e}"
                )));
            }
        };
        tx.commit()
            .await
            .map_err(|e| InterfaceError::Db(format!("Failed to commit the transaction: {e}")))?;
        Ok(uid)
    }

    async fn retrieve(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Option<ObjectWithMetadata>> {
        Ok(retrieve_(uid, &self.pool).await?)
    }

    async fn retrieve_tags(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>> {
        Ok(retrieve_tags_(uid, &self.pool).await?)
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("Failed to start a transaction: {e}")))?;
        match update_object_(uid, object, attributes, tags, &mut tx).await {
            Ok(()) => {
                tx.commit().await.map_err(|e| {
                    InterfaceError::Db(format!("Failed to commit the transaction: {e}"))
                })?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                Err(InterfaceError::Db(format!("update of object failed: {e}")))
            }
        }
    }

    async fn update_state(
        &self,
        uid: &str,
        state: State,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("Failed to start a transaction: {e}")))?;
        match update_state_(uid, state, &mut tx).await {
            Ok(()) => {
                tx.commit().await.map_err(|e| {
                    InterfaceError::Db(format!("Failed to commit the transaction: {e}"))
                })?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                Err(InterfaceError::Db(format!(
                    "update of the state of object {uid} failed: {e}"
                )))
            }
        }
    }

    async fn delete(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("Failed to start a transaction: {e}")))?;
        match delete_(uid, &mut tx).await {
            Ok(()) => {
                tx.commit().await.map_err(|e| {
                    InterfaceError::Db(format!("Failed to commit the transaction: {e}"))
                })?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                Err(InterfaceError::Db(format!("delete of object failed: {e}")))
            }
        }
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<String>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("Failed to start a transaction: {e}")))?;
        match atomic_(user, operations, &mut tx).await {
            Ok(v) => {
                tx.commit().await.map_err(|e| {
                    InterfaceError::Db(format!("Failed to commit the transaction: {e}"))
                })?;
                Ok(v)
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                Err(InterfaceError::Db(format!("atomic operation failed: {e}")))
            }
        }
    }

    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<bool> {
        Ok(is_object_owned_by_(uid, owner, &self.pool).await?)
    }

    async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>> {
        Ok(list_uids_from_tags_(tags, &self.pool).await?)
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        user: &str,
        user_must_be_owner: bool,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        Ok(find_(
            researched_attributes,
            state,
            user,
            user_must_be_owner,
            &self.pool,
        )
        .await?)
    }
}

#[async_trait(?Send)]
impl PermissionsStore for PgPool {
    async fn list_user_operations_granted(
        &self,
        user: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashMap<String, (String, State, HashSet<KmipOperation>)>> {
        Ok(list_user_granted_access_rights_(user, &self.pool).await?)
    }

    async fn list_object_operations_granted(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashMap<String, HashSet<KmipOperation>>> {
        Ok(list_accesses_(uid, &self.pool).await?)
    }

    async fn grant_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        Ok(insert_access_(uid, user, operations, &self.pool).await?)
    }

    async fn remove_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        Ok(remove_access_(uid, user, operations, &self.pool).await?)
    }

    async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<KmipOperation>> {
        Ok(list_user_access_rights_on_object_(uid, user, no_inherited_access, &self.pool).await?)
    }
}

pub(super) async fn create_(
    uid: Option<String>,
    owner: &str,
    object: &Object,
    attributes: &Attributes,
    tags: &HashSet<String>,
    executor: &mut Transaction<'_, Postgres>,
) -> DbResult<String> {
    let object_json =
        serde_json::to_string_pretty(object).context("failed serializing the object to JSON")?;
    debug!("uid: {:?}, object_json: {object_json:#?}", uid);

    let attributes_json =
        serde_json::to_value(attributes).context("failed serializing the attributes to JSON")?;

    // If the uid is not provided, generate a new one
    let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());

    // Try to insert the object
    match sqlx::query(get_pgsql_query!("insert-objects"))
        .bind(uid.clone())
        .bind(object_json)
        .bind(attributes_json)
        .bind(attributes.state.unwrap_or(State::PreActive).to_string())
        .bind(owner)
        .execute(&mut **executor)
        .await
    {
        Ok(_) => {}
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            return Err(DbError::Kmip21Error(
                ErrorReason::Object_Already_Exists,
                format!("Object with UID '{uid}' already exists"),
            ));
        }
        Err(e) => return Err(e.into()),
    }

    // Insert the tags
    for tag in tags {
        sqlx::query(get_pgsql_query!("insert-tags"))
            .bind(uid.clone())
            .bind(tag)
            .execute(&mut **executor)
            .await?;
    }

    trace!("Created in DB: {uid} / {owner}");
    Ok(uid)
}

pub(super) async fn retrieve_<'e, E>(uid: &str, executor: E) -> DbResult<Option<ObjectWithMetadata>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let row = sqlx::query(get_pgsql_query!("select-object"))
        .bind(uid)
        .fetch_optional(executor)
        .await?;
    if let Some(row) = row {
        return Ok(Some(pg_row_to_owm(&row)?));
    }
    Ok(None)
}

async fn retrieve_tags_<'e, E>(uid: &str, executor: E) -> DbResult<HashSet<String>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let rows: Vec<PgRow> = sqlx::query(get_pgsql_query!("select-tags"))
        .bind(uid)
        .fetch_all(executor)
        .await?;

    let tags = rows.iter().map(|r| r.get(0)).collect::<HashSet<String>>();

    Ok(tags)
}

pub(super) async fn update_object_(
    uid: &str,
    object: &Object,
    attributes: &Attributes,
    tags: Option<&HashSet<String>>,
    executor: &mut Transaction<'_, Postgres>,
) -> DbResult<()> {
    let object_json =
        serde_json::to_string_pretty(object).context("failed serializing the object to JSON")?;

    let attributes_json =
        serde_json::to_value(attributes).context("failed serializing the attributes to JSON")?;

    sqlx::query(get_pgsql_query!("update-object-with-object"))
        .bind(object_json)
        .bind(attributes_json)
        .bind(uid)
        .execute(&mut **executor)
        .await?;

    // Insert the new tags if any
    if let Some(tags) = tags {
        // delete the existing tags
        sqlx::query(get_pgsql_query!("delete-tags"))
            .bind(uid)
            .execute(&mut **executor)
            .await?;

        for tag in tags {
            sqlx::query(get_pgsql_query!("insert-tags"))
                .bind(uid)
                .bind(tag)
                .execute(&mut **executor)
                .await?;
        }
    }

    trace!("Updated in DB: {uid}");
    Ok(())
}

pub(super) async fn update_state_(
    uid: &str,
    state: State,
    executor: &mut Transaction<'_, Postgres>,
) -> DbResult<()> {
    sqlx::query(get_pgsql_query!("update-object-with-state"))
        .bind(state.to_string())
        .bind(uid)
        .execute(&mut **executor)
        .await?;
    trace!("Updated in DB: {uid}");
    Ok(())
}

pub(super) async fn delete_(uid: &str, executor: &mut Transaction<'_, Postgres>) -> DbResult<()> {
    // delete the object
    sqlx::query(get_pgsql_query!("delete-object"))
        .bind(uid)
        .execute(&mut **executor)
        .await?;

    // delete the tags
    sqlx::query(get_pgsql_query!("delete-tags"))
        .bind(uid)
        .execute(&mut **executor)
        .await?;

    trace!("Deleted in DB: {uid}");
    Ok(())
}

pub(super) async fn upsert_(
    uid: &str,
    owner: &str,
    object: &Object,
    attributes: &Attributes,
    tags: Option<&HashSet<String>>,
    state: State,
    executor: &mut Transaction<'_, Postgres>,
) -> DbResult<()> {
    let object_json =
        serde_json::to_string_pretty(object).context("failed serializing the object to JSON")?;

    let attributes_json =
        serde_json::to_value(attributes).context("failed serializing the attributes to JSON")?;

    sqlx::query(get_pgsql_query!("upsert-object"))
        .bind(uid)
        .bind(object_json)
        .bind(attributes_json)
        .bind(state.to_string())
        .bind(owner)
        .execute(&mut **executor)
        .await?;

    // Insert the new tags if present
    if let Some(tags) = tags {
        // delete the existing tags
        sqlx::query(get_pgsql_query!("delete-tags"))
            .bind(uid)
            .execute(&mut **executor)
            .await?;
        // insert the new ones
        for tag in tags {
            sqlx::query(get_pgsql_query!("insert-tags"))
                .bind(uid)
                .bind(tag)
                .execute(&mut **executor)
                .await?;
        }
    }

    trace!("Upserted in DB: {uid}");
    Ok(())
}

pub(super) async fn list_uids_from_tags_<'e, E>(
    tags: &HashSet<String>,
    executor: E,
) -> DbResult<HashSet<String>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let tags_params = tags
        .iter()
        .enumerate()
        .map(|(i, _)| format!("${}", i + 1))
        .collect::<Vec<_>>()
        .join(", ");

    let raw_sql = get_pgsql_query!("select-uids-from-tags")
        .replace("@TAGS", &tags_params)
        .replace("@LEN", &format!("${}", tags.len() + 1));

    let mut query = sqlx::query::<Postgres>(&raw_sql);
    for tag in tags {
        query = query.bind(tag);
    }
    // Bind the tags len and the user
    query = query.bind(i16::try_from(tags.len())?);

    let rows = query.fetch_all(executor).await?;
    let uids = rows.iter().map(|r| r.get(0)).collect::<HashSet<String>>();
    Ok(uids)
}

pub(super) async fn list_accesses_<'e, E>(
    uid: &str,
    executor: E,
) -> DbResult<HashMap<String, HashSet<KmipOperation>>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    debug!("Uid = {}", uid);

    let list = sqlx::query(get_pgsql_query!("select-rows-read_access-with-object-id"))
        .bind(uid)
        .fetch_all(executor)
        .await?;
    let mut ids: HashMap<String, HashSet<KmipOperation>> = HashMap::with_capacity(list.len());
    for row in list {
        ids.insert(
            // userid
            row.get::<String, _>(0),
            // permissions
            serde_json::from_value(row.get::<Value, _>(1))?,
        );
    }
    debug!("Listed {} rows", ids.len());
    Ok(ids)
}

pub(super) async fn list_user_granted_access_rights_<'e, E>(
    user: &str,
    executor: E,
) -> DbResult<HashMap<String, (String, State, HashSet<KmipOperation>)>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    debug!("Owner = {}", user);
    let list = sqlx::query(get_pgsql_query!("select-objects-access-obtained"))
        .bind(user)
        .fetch_all(executor)
        .await?;
    let mut ids: HashMap<String, (String, State, HashSet<KmipOperation>)> =
        HashMap::with_capacity(list.len());
    for row in list {
        ids.insert(
            row.get::<String, _>(0),
            (
                row.get::<String, _>(1),
                State::try_from(row.get::<String, _>(2).as_str()).map_err(|e| {
                    DbError::ConversionError(format!("failed converting the state: {e}").into())
                })?,
                serde_json::from_value(
                    row.try_get::<Value, _>(3)
                        .context("failed deserializing the operations")?,
                )?,
            ),
        );
    }
    debug!("Listed {} rows", ids.len());
    Ok(ids)
}

pub(super) async fn list_user_access_rights_on_object_<'e, E>(
    uid: &str,
    userid: &str,
    no_inherited_access: bool,
    executor: E,
) -> DbResult<HashSet<KmipOperation>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let mut user_perms = perms(uid, userid, executor).await?;
    if no_inherited_access || userid == "*" {
        return Ok(user_perms);
    }
    user_perms.extend(perms(uid, "*", executor).await?);
    Ok(user_perms)
}

async fn perms<'e, E>(uid: &str, userid: &str, executor: E) -> DbResult<HashSet<KmipOperation>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let row: Option<PgRow> = sqlx::query(get_pgsql_query!("select-user-accesses-for-object"))
        .bind(uid)
        .bind(userid)
        .fetch_optional(executor)
        .await?;

    row.map_or(Ok(HashSet::new()), |row| {
        let perms_value = row
            .try_get::<Value, _>(0)
            .context("failed deserializing the permissions")?;
        serde_json::from_value(perms_value).context("failed deserializing the permissions")
    })
}

pub(super) async fn insert_access_<'e, E>(
    uid: &str,
    userid: &str,
    operation_types: HashSet<KmipOperation>,
    executor: E,
) -> DbResult<()>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    // Retrieve existing permissions if any
    let mut perms = list_user_access_rights_on_object_(uid, userid, false, executor).await?;
    if operation_types.is_subset(&perms) {
        // permissions are already setup
        return Ok(());
    }
    perms.extend(operation_types.iter());

    // Serialize permissions
    let json =
        serde_json::to_value(&perms).context("failed serializing the permissions to JSON")?;

    // Upsert the DB
    sqlx::query(get_pgsql_query!("upsert-row-read_access"))
        .bind(uid)
        .bind(userid)
        .bind(json)
        .execute(executor)
        .await?;
    trace!("Insert read access right in DB: {uid} / {userid}");
    Ok(())
}

pub(super) async fn remove_access_<'e, E>(
    uid: &str,
    userid: &str,
    operation_types: HashSet<KmipOperation>,
    executor: E,
) -> DbResult<()>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    // Retrieve existing permissions if any
    let perms = list_user_access_rights_on_object_(uid, userid, true, executor)
        .await?
        .difference(&operation_types)
        .copied()
        .collect::<HashSet<_>>();

    // No remaining permissions, delete the row
    if perms.is_empty() {
        sqlx::query(get_pgsql_query!("delete-rows-read_access"))
            .bind(uid)
            .bind(userid)
            .execute(executor)
            .await?;
        return Ok(());
    }

    // Serialize permissions
    let json =
        serde_json::to_value(&perms).context("failed serializing the permissions to JSON")?;

    // Update the DB
    sqlx::query(get_pgsql_query!("update-rows-read_access-with-permission"))
        .bind(uid)
        .bind(userid)
        .bind(json)
        .execute(executor)
        .await?;
    trace!("Deleted in DB: {uid} / {userid}");
    Ok(())
}

pub(super) async fn is_object_owned_by_<'e, E>(
    uid: &str,
    owner: &str,
    executor: E,
) -> DbResult<bool>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let row: Option<PgRow> = sqlx::query(get_pgsql_query!("has-row-objects"))
        .bind(uid)
        .bind(owner)
        .fetch_optional(executor)
        .await?;
    Ok(row.is_some())
}

pub(super) async fn find_<'e, E>(
    researched_attributes: Option<&Attributes>,
    state: Option<State>,
    user: &str,
    user_must_be_owner: bool,
    executor: E,
) -> DbResult<Vec<(String, State, Attributes)>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let query = query_from_attributes::<PgSqlPlaceholder>(
        researched_attributes,
        state,
        user,
        user_must_be_owner,
    );
    trace!("{query:?}");

    let mut query = sqlx::query(&query);
    // Bind user-provided values to placeholders
    query = if user_must_be_owner {
        query.bind(user)
    } else {
        query.bind(user).bind(user).bind(user)
    };
    let rows = query.fetch_all(executor).await?;

    to_qualified_uids(&rows)
}

/// Convert a list of rows into a list of qualified uids
fn to_qualified_uids(rows: &[PgRow]) -> DbResult<Vec<(String, State, Attributes)>> {
    let mut uids = Vec::with_capacity(rows.len());
    for row in rows {
        let attrs: Attributes = match row.try_get::<Value, _>(2) {
            Err(_) => return Err(DbError::DatabaseError("no attributes found".to_owned())),
            Ok(v) => serde_json::from_value(v)
                .context("failed deserializing the attributes")
                .map_err(|e| DbError::DatabaseError(e.to_string()))?,
        };

        uids.push((
            row.get::<String, _>(0),
            State::try_from(row.get::<String, _>(1).as_str()).map_err(|e| {
                DbError::ConversionError(format!("failed converting the state: {e}").into())
            })?,
            attrs,
        ));
    }
    Ok(uids)
}

pub(super) async fn atomic_(
    owner: &str,
    operations: &[AtomicOperation],
    tx: &mut Transaction<'_, Postgres>,
) -> DbResult<Vec<String>> {
    let mut uids = Vec::with_capacity(operations.len());
    for operation in operations {
        match operation {
            AtomicOperation::Create((uid, object, attributes, tags)) => {
                if let Err(e) =
                    create_(Some(uid.clone()), owner, object, attributes, tags, tx).await
                {
                    db_bail!("creation of object {uid} failed: {e}");
                }
                uids.push(uid.clone());
            }
            AtomicOperation::UpdateObject((uid, object, attributes, tags)) => {
                if let Err(e) = update_object_(uid, object, attributes, tags.as_ref(), tx).await {
                    db_bail!("update of object {uid} failed: {e}");
                }
                uids.push(uid.clone());
            }
            AtomicOperation::UpdateState((uid, state)) => {
                if let Err(e) = update_state_(uid, *state, tx).await {
                    db_bail!("update of the state of object {uid} failed: {e}");
                }
                uids.push(uid.clone());
            }
            AtomicOperation::Upsert((uid, object, attributes, tags, state)) => {
                if let Err(e) =
                    upsert_(uid, owner, object, attributes, tags.as_ref(), *state, tx).await
                {
                    db_bail!("upsert of object {uid} failed: {e}");
                }
                uids.push(uid.clone());
            }
            AtomicOperation::Delete(uid) => {
                if let Err(e) = delete_(uid, tx).await {
                    db_bail!("deletion of object {uid} failed: {e}");
                }
                uids.push(uid.clone());
            }
        }
    }
    Ok(uids)
}
