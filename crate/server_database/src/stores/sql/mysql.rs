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
    ConnectOptions, Executor, MySql, Pool, Row, Transaction,
    mysql::{MySqlConnectOptions, MySqlPoolOptions, MySqlRow},
};
use uuid::Uuid;

// Default MySQL lock wait timeout (seconds) applied to every new session.
// MySQL default is ~50s; 10s is more appropriate for tests and reduces long stalls.
const DEFAULT_LOCK_WAIT_TIMEOUT_SECS: u32 = 10;

use crate::{
    db_bail, db_error,
    error::{DbError, DbResult, DbResultHelper},
    stores::{
        MYSQL_QUERIES,
        migrate::HasDatabase,
        sql::{
            database::SqlDatabase,
            locate_query::{MySqlPlaceholder, query_from_attributes},
            main_store::SqlMainStore,
        },
    },
};

#[macro_export]
macro_rules! get_mysql_query {
    ($name:literal) => {
        MYSQL_QUERIES
            .get($name)
            .ok_or_else(|| db_error!("{} SQL query can't be found", $name))?
    };
    ($name:expr) => {
        MYSQL_QUERIES
            .get($name)
            .ok_or_else(|| db_error!("{} SQL query can't be found", $name))?
    };
}

/// Convert a `MySQL` row into an `ObjectWithMetadata`
/// This function is used to convert the result of a SQL query into an `ObjectWithMetadata`.
/// This is used in the `retrieve_` function.
/// # Arguments
/// * `row` - The `MySQL` row to convert
/// # Returns
/// * An `ObjectWithMetadata` object
/// # Errors
/// * If the deserialization of the object or the attributes fails
/// * If the state is not a valid `StateEnumeration`
/// * If the conversion fails
fn my_sql_row_to_owm(row: &MySqlRow) -> Result<ObjectWithMetadata, DbError> {
    let id = row.get::<String, _>(0);
    let object: Object = serde_json::from_str(&row.get::<String, _>(1))
        .context("failed deserializing the object")?;
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

/// The `MySQL` connector is also compatible to connect a `MariaDB`
/// see: <https://mariadb.com/kb/en/mariadb-vs-mysql-compatibility>/
#[derive(Clone)]
pub(crate) struct MySqlPool {
    pool: Pool<MySql>,
}

impl HasDatabase for MySqlPool {
    type Database = MySql;
}

impl MySqlPool {
    pub(crate) async fn instantiate(
        connection_url: &str,
        clear_database: bool,
        max_connections: Option<u32>,
    ) -> DbResult<Self> {
        let options = MySqlConnectOptions::from_str(connection_url)?
            // disable logging of each query
            .disable_statement_logging();

        // Default: reduce deadlocks by using READ COMMITTED isolation level per session
        // This is applied for every new connection.
        // Also set a reasonable lock wait timeout (seconds) to fail faster under contention
        // Default rationale: conservative pool tuned to CPU. MySQL/MariaDB can suffer
        // from too many concurrent connections (threads, buffer pool pressure). Using
        // min(10, 2 × CPU cores) balances parallelism with stability for typical services.
        let default_conns: u32 = u32::try_from(num_cpus::get())
            .map(|c| c.saturating_mul(2).min(10))
            .unwrap_or(10);
        let max_conns: u32 = max_connections.unwrap_or(default_conns);
        let pool = MySqlPoolOptions::new()
            .max_connections(max_conns)
            .after_connect(move |conn, _meta| {
                Box::pin(async move {
                    // Always set READ COMMITTED for this session
                    sqlx::query("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")
                        .execute(&mut *conn)
                        .await?;
                    // Best effort: may require privileges depending on server config
                    match sqlx::query(&format!(
                        "SET SESSION innodb_lock_wait_timeout = {DEFAULT_LOCK_WAIT_TIMEOUT_SECS}"
                    ))
                    .execute(&mut *conn)
                    .await
                    {
                        Ok(_) => (),
                        Err(e) => {
                            debug!(
                                "Could not set innodb_lock_wait_timeout to {}s: {e}",
                                DEFAULT_LOCK_WAIT_TIMEOUT_SECS
                            );
                        }
                    }
                    Ok(())
                })
            })
            .connect_with(options)
            .await?;

        // Create the tables if they don't exist
        let mysql_pool = Self { pool };

        // Blanket implementation of SqlMainStore for SqlDatabase
        mysql_pool.start(clear_database).await?;
        Ok(mysql_pool)
    }
}

impl SqlDatabase<MySql> for MySqlPool {
    fn get_pool(&self) -> &Pool<MySql> {
        &self.pool
    }

    fn get_loader(&self) -> &Loader {
        &MYSQL_QUERIES
    }

    fn binder(&self, _param_number: usize) -> String {
        "?".to_owned()
    }
}

#[async_trait(?Send)]
impl ObjectsStore for MySqlPool {
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
        Ok(list_uids_for_tags_(tags, &self.pool).await?)
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
impl PermissionsStore for MySqlPool {
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
    executor: &mut Transaction<'_, MySql>,
) -> DbResult<String> {
    let object_json =
        serde_json::to_string_pretty(object).context("failed serializing the object to JSON")?;

    let attributes_json =
        serde_json::to_value(attributes).context("failed serializing the attributes to JSON")?;

    // If the uid is not provided, generate a new one
    let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());

    // Try to insert the object
    match sqlx::query(get_mysql_query!("insert-objects"))
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
        sqlx::query(get_mysql_query!("insert-tags"))
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
    E: Executor<'e, Database = MySql> + Copy,
{
    let row = sqlx::query(get_mysql_query!("select-object"))
        .bind(uid)
        .fetch_optional(executor)
        .await?;

    if let Some(row) = row {
        return Ok(Some(my_sql_row_to_owm(&row)?));
    }
    Ok(None)
}

async fn retrieve_tags_<'e, E>(uid: &str, executor: E) -> DbResult<HashSet<String>>
where
    E: Executor<'e, Database = MySql> + Copy,
{
    let rows: Vec<MySqlRow> = sqlx::query(get_mysql_query!("select-tags"))
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
    executor: &mut Transaction<'_, MySql>,
) -> DbResult<()> {
    let object_json =
        serde_json::to_string_pretty(object).context("failed serializing the object to JSON")?;

    let attributes_json =
        serde_json::to_value(attributes).context("failed serializing the attributes to JSON")?;

    sqlx::query(get_mysql_query!("update-object-with-object"))
        .bind(object_json)
        .bind(attributes_json)
        .bind(uid)
        .execute(&mut **executor)
        .await?;

    // Insert the new tags if any
    if let Some(tags) = tags {
        // delete the existing tags
        sqlx::query(get_mysql_query!("delete-tags"))
            .bind(uid)
            .execute(&mut **executor)
            .await?;

        for tag in tags {
            sqlx::query(get_mysql_query!("insert-tags"))
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
    executor: &mut Transaction<'_, MySql>,
) -> DbResult<()> {
    sqlx::query(get_mysql_query!("update-object-with-state"))
        .bind(state.to_string())
        .bind(uid)
        .execute(&mut **executor)
        .await?;
    trace!("Updated in DB: {uid}");
    Ok(())
}

pub(super) async fn delete_(uid: &str, executor: &mut Transaction<'_, MySql>) -> DbResult<()> {
    // delete the object
    sqlx::query(get_mysql_query!("delete-object"))
        .bind(uid)
        .execute(&mut **executor)
        .await?;

    // delete the tags
    sqlx::query(get_mysql_query!("delete-tags"))
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
    executor: &mut Transaction<'_, MySql>,
) -> DbResult<()> {
    let object_json =
        serde_json::to_string_pretty(object).context("failed serializing the object to JSON")?;

    let attributes_json =
        serde_json::to_value(attributes).context("failed serializing the attributes to JSON")?;

    sqlx::query(get_mysql_query!("upsert-object"))
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
        sqlx::query(get_mysql_query!("delete-tags"))
            .bind(uid)
            .execute(&mut **executor)
            .await?;
        // insert the new ones
        for tag in tags {
            sqlx::query(get_mysql_query!("insert-tags"))
                .bind(uid)
                .bind(tag)
                .execute(&mut **executor)
                .await?;
        }
    }

    trace!("Upserted in DB: {uid}");
    Ok(())
}

pub(super) async fn list_uids_for_tags_<'e, E>(
    tags: &HashSet<String>,
    executor: E,
) -> DbResult<HashSet<String>>
where
    E: Executor<'e, Database = MySql> + Copy,
{
    let tags_params = tags.iter().map(|_| "?").collect::<Vec<_>>().join(", ");

    // Build the raw SQL query
    let raw_sql = get_mysql_query!("select-uids-from-tags").replace("@TAGS", &tags_params);

    // Bind the tags params
    let mut query = sqlx::query::<MySql>(&raw_sql);
    for tag in tags {
        query = query.bind(tag);
    }

    // Bind the tags len
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
    E: Executor<'e, Database = MySql> + Copy,
{
    debug!("Uid = {}", uid);

    let list = sqlx::query(get_mysql_query!("select-rows-read_access-with-object-id"))
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
    E: Executor<'e, Database = MySql> + Copy,
{
    debug!("Owner = {}", user);
    let list = sqlx::query(get_mysql_query!("select-objects-access-obtained"))
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
    E: Executor<'e, Database = MySql> + Copy,
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
    E: Executor<'e, Database = MySql> + Copy,
{
    let row: Option<MySqlRow> = sqlx::query(get_mysql_query!("select-user-accesses-for-object"))
        .bind(uid)
        .bind(userid)
        .fetch_optional(executor)
        .await?;

    row.map_or(Ok(HashSet::new()), |row| {
        let perms_raw = row.get::<Value, _>(0);
        serde_json::from_value(perms_raw).context("failed deserializing the permissions")
    })
}

pub(super) async fn insert_access_<'e, E>(
    uid: &str,
    userid: &str,
    operation_types: HashSet<KmipOperation>,
    executor: E,
) -> DbResult<()>
where
    E: Executor<'e, Database = MySql> + Copy,
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
    sqlx::query(get_mysql_query!("upsert-row-read_access"))
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
    E: Executor<'e, Database = MySql> + Copy,
{
    // Retrieve existing permissions if any
    let perms = list_user_access_rights_on_object_(uid, userid, true, executor)
        .await?
        .difference(&operation_types)
        .copied()
        .collect::<HashSet<_>>();

    // No remaining permissions, delete the row
    if perms.is_empty() {
        sqlx::query(get_mysql_query!("delete-rows-read_access"))
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
    sqlx::query(get_mysql_query!("update-rows-read_access-with-permission"))
        .bind(json)
        .bind(uid)
        .bind(userid)
        .execute(executor)
        .await?;
    Ok(())
}

pub(super) async fn is_object_owned_by_<'e, E>(
    uid: &str,
    owner: &str,
    executor: E,
) -> DbResult<bool>
where
    E: Executor<'e, Database = MySql> + Copy,
{
    let row: Option<MySqlRow> = sqlx::query(get_mysql_query!("has-row-objects"))
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
    E: Executor<'e, Database = MySql> + Copy,
{
    let query = query_from_attributes::<MySqlPlaceholder>(
        researched_attributes,
        state,
        user,
        user_must_be_owner,
    );
    trace!("find_: {query:?}");

    let mut query = sqlx::query(&query);
    // Bind user-provided values to the ? placeholders
    query = if user_must_be_owner {
        query.bind(user)
    } else {
        query.bind(user).bind(user).bind(user)
    };

    let rows = query.fetch_all(executor).await?;

    to_qualified_uids(&rows)
}

/// Convert a list of rows into a list of qualified uids
fn to_qualified_uids(rows: &[MySqlRow]) -> DbResult<Vec<(String, State, Attributes)>> {
    let mut uids = Vec::with_capacity(rows.len());
    for row in rows {
        let raw = row.get::<Value, _>(2);
        let attrs: Attributes =
            serde_json::from_value(raw).context("failed deserializing attributes")?;

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
    tx: &mut Transaction<'_, MySql>,
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

// impl_sql_migrate!(MySqlPool, get_mysql_query);
