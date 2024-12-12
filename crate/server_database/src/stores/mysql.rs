use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    str::FromStr,
};

use async_trait::async_trait;
use clap::crate_version;
use cosmian_kmip::kmip_2_1::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration},
    KmipOperation,
};
use serde_json::Value;
use sqlx::{
    mysql::{MySqlConnectOptions, MySqlPoolOptions, MySqlRow},
    ConnectOptions, Executor, MySql, Pool, Row, Transaction,
};
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{
    db_bail, db_error,
    error::{DbError, DbResult, DbResultHelper},
    migrate::do_migration,
    stores::{
        locate_query::{query_from_attributes, MySqlPlaceholder},
        store_traits::{ObjectsStore, PermissionsStore},
        DBObject, ExtraStoreParams, MYSQL_QUERIES,
    },
    AtomicOperation, ObjectWithMetadata, KMS_VERSION_BEFORE_MIGRATION_SUPPORT,
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

impl TryFrom<&MySqlRow> for ObjectWithMetadata {
    type Error = DbError;

    fn try_from(row: &MySqlRow) -> Result<Self, Self::Error> {
        let id = row.get::<String, _>(0);
        let db_object: DBObject = serde_json::from_value(row.get::<Value, _>(1))
            .context("failed deserializing the object")?;
        let object = Object::post_fix(db_object.object_type, db_object.object);
        let attributes: Attributes = serde_json::from_value(row.get::<Value, _>(2))
            .context("failed deserializing the Attributes")?;
        let owner = row.get::<String, _>(3);
        let state = StateEnumeration::try_from(row.get::<String, _>(4))?;
        Ok(Self::new(id, object, owner, state, attributes))
    }
}

/// The `MySQL` connector is also compatible to connect a `MariaDB`
/// see: <https://mariadb.com/kb/en/mariadb-vs-mysql-compatibility>/
#[derive(Clone)]
pub(crate) struct MySqlPool {
    pool: Pool<MySql>,
}

impl MySqlPool {
    pub(crate) async fn instantiate(connection_url: &str, clear_database: bool) -> DbResult<Self> {
        let options = MySqlConnectOptions::from_str(connection_url)?
            // disable logging of each query
            .disable_statement_logging();

        let pool = MySqlPoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        sqlx::query(get_mysql_query!("create-table-context"))
            .execute(&pool)
            .await?;

        sqlx::query(get_mysql_query!("create-table-objects"))
            .execute(&pool)
            .await?;

        sqlx::query(get_mysql_query!("create-table-read_access"))
            .execute(&pool)
            .await?;

        sqlx::query(get_mysql_query!("create-table-tags"))
            .execute(&pool)
            .await?;

        if clear_database {
            clear_database_(&pool).await?;
        }

        let mysql_pool = Self { pool };
        mysql_pool.migrate(None).await?;
        Ok(mysql_pool)
    }
}

#[async_trait(?Send)]
impl ObjectsStore for MySqlPool {
    fn filename(&self, _group_id: u128) -> Option<PathBuf> {
        None
    }

    async fn migrate(&self, _params: Option<&ExtraStoreParams>) -> DbResult<()> {
        trace!("Migrate database");
        // Get the context rows
        match sqlx::query(get_mysql_query!("select-context"))
            .fetch_optional(&self.pool)
            .await?
        {
            None => {
                trace!("No context row found, migrating from scratch");
                return migrate_(
                    &self.pool,
                    KMS_VERSION_BEFORE_MIGRATION_SUPPORT,
                    "insert-context",
                )
                .await;
            }
            Some(context_row) => {
                let last_kms_version_run = context_row.get::<String, _>(0);
                let state = context_row.get::<String, _>(1);
                trace!(
                    "Context row found, migrating from version {last_kms_version_run} (state: \
                     {state})"
                );
                let current_kms_version = crate_version!();
                debug!(
                    "[state={state}] Last KMS version run: {last_kms_version_run}, Current KMS \
                     version: {current_kms_version}"
                );

                if do_migration(&last_kms_version_run, current_kms_version, &state)? {
                    return migrate_(&self.pool, current_kms_version, "update-context").await;
                }
            }
        }

        Ok(())
    }

    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<String> {
        if is_migration_in_progress_(&self.pool).await? {
            db_bail!("Migration in progress. Please retry later");
        }

        let mut tx = self.pool.begin().await?;
        let uid = match create_(uid, owner, object, attributes, tags, &mut tx).await {
            Ok(uid) => uid,
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                db_bail!("creation of object failed: {e}");
            }
        };
        tx.commit().await?;
        Ok(uid)
    }

    async fn retrieve(
        &self,
        uid: &str,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<Option<ObjectWithMetadata>> {
        retrieve_(uid, &self.pool).await
    }

    async fn retrieve_tags(
        &self,
        uid: &str,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<String>> {
        retrieve_tags_(uid, &self.pool).await
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        let mut tx = self.pool.begin().await?;
        match update_object_(uid, object, attributes, tags, &mut tx).await {
            Ok(()) => {
                tx.commit().await?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                db_bail!("update of object failed: {}", e);
            }
        }
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        if is_migration_in_progress_(&self.pool).await? {
            db_bail!("Migration in progress. Please retry later");
        }
        let mut tx = self.pool.begin().await?;
        match update_state_(uid, state, &mut tx).await {
            Ok(()) => {
                tx.commit().await?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                db_bail!("update of the state of object {uid} failed: {e}");
            }
        }
    }

    async fn delete(&self, uid: &str, _params: Option<&ExtraStoreParams>) -> DbResult<()> {
        if is_migration_in_progress_(&self.pool).await? {
            db_bail!("Migration in progress. Please retry later");
        }

        let mut tx = self.pool.begin().await?;
        match delete_(uid, &mut tx).await {
            Ok(()) => {
                tx.commit().await?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                db_bail!("delete of object failed: {}", e);
            }
        }
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<Vec<String>> {
        if is_migration_in_progress_(&self.pool).await? {
            db_bail!("Migration in progress. Please retry later");
        }

        let mut tx = self.pool.begin().await?;
        match atomic_(user, operations, &mut tx).await {
            Ok(v) => {
                tx.commit().await?;
                Ok(v)
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                Err(e)
            }
        }
    }

    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<bool> {
        is_object_owned_by_(uid, owner, &self.pool).await
    }

    async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<String>> {
        list_uids_for_tags_(tags, &self.pool).await
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<Vec<(String, StateEnumeration, Attributes)>> {
        find_(
            researched_attributes,
            state,
            user,
            user_must_be_owner,
            &self.pool,
        )
        .await
    }
}

#[async_trait(?Send)]
impl PermissionsStore for MySqlPool {
    async fn list_user_operations_granted(
        &self,
        user: &str,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashMap<String, (String, StateEnumeration, HashSet<KmipOperation>)>> {
        list_user_granted_access_rights_(user, &self.pool).await
    }

    async fn list_object_operations_granted(
        &self,
        uid: &str,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashMap<String, HashSet<KmipOperation>>> {
        list_accesses_(uid, &self.pool).await
    }

    async fn grant_operations(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<KmipOperation>,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        if is_migration_in_progress_(&self.pool).await? {
            db_bail!("Migration in progress. Please retry later");
        }

        insert_access_(uid, user, operation_types, &self.pool).await
    }

    async fn remove_operations(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<KmipOperation>,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<()> {
        if is_migration_in_progress_(&self.pool).await? {
            db_bail!("Migration in progress. Please retry later");
        }

        remove_access_(uid, user, operation_types, &self.pool).await
    }

    async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
        _params: Option<&ExtraStoreParams>,
    ) -> DbResult<HashSet<KmipOperation>> {
        list_user_access_rights_on_object_(uid, user, no_inherited_access, &self.pool).await
    }
}

pub(crate) async fn create_(
    uid: Option<String>,
    owner: &str,
    object: &Object,
    attributes: &Attributes,
    tags: &HashSet<String>,
    executor: &mut Transaction<'_, MySql>,
) -> DbResult<String> {
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")?;

    let attributes_json =
        serde_json::to_value(attributes).context("failed serializing the attributes to JSON")?;

    // If the uid is not provided, generate a new one
    let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());

    sqlx::query(get_mysql_query!("insert-objects"))
        .bind(uid.clone())
        .bind(object_json)
        .bind(attributes_json)
        .bind(StateEnumeration::Active.to_string())
        .bind(owner)
        .execute(&mut **executor)
        .await?;

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

pub(crate) async fn retrieve_<'e, E>(uid: &str, executor: E) -> DbResult<Option<ObjectWithMetadata>>
where
    E: Executor<'e, Database = MySql> + Copy,
{
    let row = sqlx::query(get_mysql_query!("select-object"))
        .bind(uid)
        .fetch_optional(executor)
        .await?;

    if let Some(row) = row {
        return Ok(Some(ObjectWithMetadata::try_from(&row)?));
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

pub(crate) async fn update_object_(
    uid: &str,
    object: &Object,
    attributes: &Attributes,
    tags: Option<&HashSet<String>>,
    executor: &mut Transaction<'_, MySql>,
) -> DbResult<()> {
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")?;

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

pub(crate) async fn update_state_(
    uid: &str,
    state: StateEnumeration,
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

pub(crate) async fn delete_(uid: &str, executor: &mut Transaction<'_, MySql>) -> DbResult<()> {
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

pub(crate) async fn upsert_(
    uid: &str,
    owner: &str,
    object: &Object,
    attributes: &Attributes,
    tags: Option<&HashSet<String>>,
    state: StateEnumeration,
    executor: &mut Transaction<'_, MySql>,
) -> DbResult<()> {
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")?;

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

pub(crate) async fn list_uids_for_tags_<'e, E>(
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

pub(crate) async fn list_accesses_<'e, E>(
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

pub(crate) async fn list_user_granted_access_rights_<'e, E>(
    user: &str,
    executor: E,
) -> DbResult<HashMap<String, (String, StateEnumeration, HashSet<KmipOperation>)>>
where
    E: Executor<'e, Database = MySql> + Copy,
{
    debug!("Owner = {}", user);
    let list = sqlx::query(get_mysql_query!("select-objects-access-obtained"))
        .bind(user)
        .fetch_all(executor)
        .await?;
    let mut ids: HashMap<String, (String, StateEnumeration, HashSet<KmipOperation>)> =
        HashMap::with_capacity(list.len());
    for row in list {
        ids.insert(
            row.get::<String, _>(0),
            (
                row.get::<String, _>(1),
                StateEnumeration::try_from(row.get::<String, _>(2))?,
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

pub(crate) async fn list_user_access_rights_on_object_<'e, E>(
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
        return Ok(user_perms)
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
        let perms_raw = row.get::<Vec<u8>, _>(0);
        serde_json::from_slice(&perms_raw).context("failed deserializing the permissions")
    })
}

pub(crate) async fn insert_access_<'e, E>(
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
        return Ok(())
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

pub(crate) async fn remove_access_<'e, E>(
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
        return Ok(())
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

pub(crate) async fn is_object_owned_by_<'e, E>(
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

pub(crate) async fn find_<'e, E>(
    researched_attributes: Option<&Attributes>,
    state: Option<StateEnumeration>,
    user: &str,
    user_must_be_owner: bool,
    executor: E,
) -> DbResult<Vec<(String, StateEnumeration, Attributes)>>
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
    let query = sqlx::query(&query);
    let rows = query.fetch_all(executor).await?;

    to_qualified_uids(&rows)
}

/// Convert a list of rows into a list of qualified uids
fn to_qualified_uids(rows: &[MySqlRow]) -> DbResult<Vec<(String, StateEnumeration, Attributes)>> {
    let mut uids = Vec::with_capacity(rows.len());
    for row in rows {
        let raw = row.get::<Vec<u8>, _>(2);
        let attrs = if raw.is_empty() {
            Attributes::default()
        } else {
            let attrs: Attributes =
                serde_json::from_slice(&raw).context("failed deserializing attributes")?;
            attrs
        };

        uids.push((
            row.get::<String, _>(0),
            StateEnumeration::try_from(row.get::<String, _>(1))?,
            attrs,
        ));
    }
    Ok(uids)
}

async fn clear_database_<'e, E>(executor: E) -> DbResult<()>
where
    E: Executor<'e, Database = MySql> + Copy,
{
    // Erase `context` table
    sqlx::query(get_mysql_query!("clean-table-context"))
        .execute(executor)
        .await?;
    // Erase `objects` table
    sqlx::query(get_mysql_query!("clean-table-objects"))
        .execute(executor)
        .await?;
    // Erase `read_access` table
    sqlx::query(get_mysql_query!("clean-table-read_access"))
        .execute(executor)
        .await?;
    // Erase `tags` table
    sqlx::query(get_mysql_query!("clean-table-tags"))
        .execute(executor)
        .await?;
    Ok(())
}

pub(crate) async fn atomic_(
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

pub(crate) async fn is_migration_in_progress_<'e, E>(executor: E) -> DbResult<bool>
where
    E: Executor<'e, Database = MySql> + Copy,
{
    (sqlx::query(get_mysql_query!("select-context"))
        .fetch_optional(executor)
        .await?)
        .map_or(Ok(false), |context_row| {
            let state = context_row.get::<String, _>(1);
            Ok(state == "upgrading")
        })
}

pub(crate) async fn migrate_(
    executor: &Pool<MySql>,
    last_version_run: &str,
    query_name: &str,
) -> DbResult<()> {
    trace!("Set status to upgrading and last version run: {last_version_run}");
    let upsert_context = get_mysql_query!(query_name);
    trace!("{query_name}: {upsert_context}");
    match query_name {
        "insert-context" => {
            sqlx::query(upsert_context)
                .bind(last_version_run)
                .bind("upgrading")
                .execute(executor)
                .await
        }
        "update-context" => {
            sqlx::query(upsert_context)
                .bind(last_version_run)
                .bind("upgrading")
                .bind("upgrading")
                .execute(executor)
                .await
        }
        _ => db_bail!("Unknown query name: {query_name}"),
    }?;

    trace!("Migrate data from version {last_version_run}");

    // Process migration for each KMS version
    let current_kms_version = crate_version!();
    if last_version_run == KMS_VERSION_BEFORE_MIGRATION_SUPPORT {
        migrate_from_4_12_0_to_4_13_0(executor).await?;
    } else {
        trace!("No migration needed between {last_version_run} and {current_kms_version}");
    }

    // Set the current running version
    trace!("Set status to ready and last version run: {current_kms_version}");
    sqlx::query(get_mysql_query!("update-context"))
        .bind(current_kms_version)
        .bind("ready")
        .bind("upgrading")
        .execute(executor)
        .await?;

    Ok(())
}

/// Before the version 4.13.0, the KMIP attributes were stored in the objects table (via the objects themselves).
/// The new column attributes allows to store the KMIP attributes in a dedicated column even for KMIP objects that do not have KMIP attributes (such as Certificates).
pub(crate) async fn migrate_from_4_12_0_to_4_13_0(executor: &Pool<MySql>) -> DbResult<()> {
    trace!("Migrating from 4.12.0 to 4.13.0");

    // Add the column attributes to the objects table
    if (sqlx::query(get_mysql_query!("has-column-attributes"))
        .execute(executor)
        .await)
        .is_ok()
    {
        trace!("Column attributes already exists, nothing to do");
        return Ok(());
    }

    trace!("Column attributes does not exist, adding it");
    sqlx::query(get_mysql_query!("add-column-attributes"))
        .execute(executor)
        .await?;

    // Select all objects and extract the KMIP attributes to be stored in the new column
    let rows = sqlx::query("SELECT * FROM objects")
        .fetch_all(executor)
        .await?;

    let mut operations = Vec::with_capacity(rows.len());
    for row in rows {
        let uid = row.get::<String, _>(0);
        let db_object: DBObject = serde_json::from_slice(&row.get::<Vec<u8>, _>(1))
            .context("migrate: failed deserializing the object")?;
        let object = Object::post_fix(db_object.object_type, db_object.object);
        trace!(
            "migrate_from_4_12_0_to_4_13_0: object (type: {})={:?}",
            object.object_type(),
            uid
        );
        let attributes = match object.clone().attributes() {
            Ok(attrs) => attrs.clone(),
            Err(_error) => {
                // For example, Certificate object has no KMIP-attribute
                Attributes::default()
            }
        };
        let tags = retrieve_tags_(&uid, executor).await?;
        operations.push(AtomicOperation::UpdateObject((
            uid,
            object,
            attributes,
            Some(tags),
        )));
    }

    let mut tx = executor.begin().await?;
    match atomic_(
        "this user is not used to update objects",
        &operations,
        &mut tx,
    )
    .await
    {
        Ok(_v) => {
            tx.commit().await?;
            Ok(())
        }
        Err(e) => {
            tx.rollback().await.context("transaction failed")?;
            Err(e)
        }
    }
}
