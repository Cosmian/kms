use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    str::FromStr,
};

use async_trait::async_trait;
use clap::crate_version;
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::ErrorReason,
    kmip_types::{Attributes, StateEnumeration},
};
use cosmian_kms_client::access::{IsWrapped, ObjectOperationType};
use serde_json::Value;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgRow},
    ConnectOptions, Executor, Pool, Postgres, Row, Transaction,
};
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{
    core::extra_database_params::ExtraDatabaseParams,
    database::{
        database_trait::AtomicOperation, migrate::do_migration,
        object_with_metadata::ObjectWithMetadata, query_from_attributes, state_from_string,
        DBObject, Database, PgSqlPlaceholder, KMS_VERSION_BEFORE_MIGRATION_SUPPORT, PGSQL_QUERIES,
    },
    error::KmsError,
    kms_bail, kms_error,
    result::{KResult, KResultHelper},
};

#[macro_export]
macro_rules! get_pgsql_query {
    ($name:literal) => {
        PGSQL_QUERIES
            .get($name)
            .ok_or_else(|| kms_error!("{} SQL query can't be found", $name))?
    };
    ($name:expr) => {
        PGSQL_QUERIES
            .get($name)
            .ok_or_else(|| kms_error!("{} SQL query can't be found", $name))?
    };
}

pub(crate) struct PgPool {
    pool: Pool<Postgres>,
}

impl PgPool {
    /// Instantiate a new `Postgres` database
    /// and create the appropriate table(s) if need be
    pub(crate) async fn instantiate(connection_url: &str, clear_database: bool) -> KResult<Self> {
        let options = PgConnectOptions::from_str(connection_url)?
            // disable logging of each query
            .disable_statement_logging();

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        sqlx::query(get_pgsql_query!("create-table-objects"))
            .execute(&pool)
            .await?;

        sqlx::query(get_pgsql_query!("create-table-context"))
            .execute(&pool)
            .await?;

        sqlx::query(get_pgsql_query!("create-table-read_access"))
            .execute(&pool)
            .await?;

        sqlx::query(get_pgsql_query!("create-table-tags"))
            .execute(&pool)
            .await?;

        if clear_database {
            clear_database_(&pool).await?;
        }

        let pgsql_pool = Self { pool };
        pgsql_pool.migrate(None).await?;
        Ok(pgsql_pool)
    }
}

#[async_trait(?Send)]
impl Database for PgPool {
    fn filename(&self, _group_id: u128) -> Option<PathBuf> {
        None
    }

    async fn migrate(&self, _params: Option<&ExtraDatabaseParams>) -> KResult<()> {
        trace!("Migrate database");
        // Get the context rows
        match sqlx::query(get_pgsql_query!("select-context"))
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
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<String> {
        if is_migration_in_progress_(&self.pool).await? {
            kms_bail!("Migration in progress. Please retry later");
        }

        let mut tx = self.pool.begin().await?;
        let uid = match create_(uid, owner, object, attributes, tags, &mut tx).await {
            Ok(uid) => uid,
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                kms_bail!("creation of object failed: {e}");
            }
        };
        tx.commit().await?;
        Ok(uid)
    }

    async fn retrieve(
        &self,
        uid_or_tags: &str,
        user: &str,
        query_access_grant: ObjectOperationType,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, ObjectWithMetadata>> {
        retrieve_(uid_or_tags, user, query_access_grant, &self.pool).await
    }

    async fn retrieve_tags(
        &self,
        uid: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>> {
        retrieve_tags_(uid, &self.pool).await
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let mut tx = self.pool.begin().await?;
        match update_object_(uid, object, attributes, tags, &mut tx).await {
            Ok(()) => {
                tx.commit().await?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                kms_bail!("update of object failed: {}", e);
            }
        }
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if is_migration_in_progress_(&self.pool).await? {
            kms_bail!("Migration in progress. Please retry later");
        }
        let mut tx = self.pool.begin().await?;
        match update_state_(uid, state, &mut tx).await {
            Ok(()) => {
                tx.commit().await?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                kms_bail!("update of the state of object {uid} failed: {e}");
            }
        }
    }

    async fn upsert(
        &self,
        uid: &str,
        user: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        state: StateEnumeration,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if is_migration_in_progress_(&self.pool).await? {
            kms_bail!("Migration in progress. Please retry later");
        }

        let mut tx = self.pool.begin().await?;
        match upsert_(uid, user, object, attributes, tags, state, &mut tx).await {
            Ok(()) => {
                tx.commit().await?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                kms_bail!("upsert of object failed: {}", e);
            }
        }
    }

    async fn delete(
        &self,
        uid: &str,
        user: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if is_migration_in_progress_(&self.pool).await? {
            kms_bail!("Migration in progress. Please retry later");
        }

        let mut tx = self.pool.begin().await?;
        match delete_(uid, user, &mut tx).await {
            Ok(()) => {
                tx.commit().await?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                kms_bail!("delete of object failed: {}", e);
            }
        }
    }

    async fn list_user_granted_access_rights(
        &self,
        user: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, (String, StateEnumeration, HashSet<ObjectOperationType>)>> {
        list_user_granted_access_rights_(user, &self.pool).await
    }

    async fn list_object_accesses_granted(
        &self,
        uid: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashMap<String, HashSet<ObjectOperationType>>> {
        list_accesses_(uid, &self.pool).await
    }

    async fn grant_access(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<ObjectOperationType>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if is_migration_in_progress_(&self.pool).await? {
            kms_bail!("Migration in progress. Please retry later");
        }

        insert_access_(uid, user, operation_types, &self.pool).await
    }

    async fn remove_access(
        &self,
        uid: &str,
        user: &str,
        operation_types: HashSet<ObjectOperationType>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if is_migration_in_progress_(&self.pool).await? {
            kms_bail!("Migration in progress. Please retry later");
        }

        remove_access_(uid, user, operation_types, &self.pool).await
    }

    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<bool> {
        is_object_owned_by_(uid, owner, &self.pool).await
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(String, StateEnumeration, Attributes, IsWrapped)>> {
        find_(
            researched_attributes,
            state,
            user,
            user_must_be_owner,
            &self.pool,
        )
        .await
    }

    async fn list_user_access_rights_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<ObjectOperationType>> {
        list_user_access_rights_on_object_(uid, user, no_inherited_access, &self.pool).await
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        if is_migration_in_progress_(&self.pool).await? {
            kms_bail!("Migration in progress. Please retry later");
        }

        let mut tx = self.pool.begin().await?;
        match atomic_(user, operations, &mut tx).await {
            Ok(()) => {
                tx.commit().await?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                Err(e)
            }
        }
    }
}

pub(crate) async fn create_(
    uid: Option<String>,
    owner: &str,
    object: &Object,
    attributes: &Attributes,
    tags: &HashSet<String>,
    executor: &mut Transaction<'_, Postgres>,
) -> KResult<String> {
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    let attributes_json = serde_json::to_value(attributes)
        .context("failed serializing the attributes to JSON")
        .reason(ErrorReason::Internal_Server_Error)?;

    // If the uid is not provided, generate a new one
    let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());

    sqlx::query(get_pgsql_query!("insert-objects"))
        .bind(uid.clone())
        .bind(object_json)
        .bind(attributes_json)
        .bind(StateEnumeration::Active.to_string())
        .bind(owner)
        .execute(&mut **executor)
        .await?;

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

pub(crate) async fn retrieve_<'e, E>(
    uid_or_tags: &str,
    user: &str,
    operation_type: ObjectOperationType,
    executor: E,
) -> KResult<HashMap<String, ObjectWithMetadata>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let rows: Vec<PgRow> = if uid_or_tags.starts_with('[') {
        // deserialize the array to an HashSet
        let tags: HashSet<String> = serde_json::from_str(uid_or_tags)
            .with_context(|| format!("Invalid tags: {uid_or_tags}"))?;

        // find the key(s) that matches the tags
        // the user must be the owner or have decrypt permissions
        // Build the raw tags params
        let tags_params = tags
            .iter()
            .enumerate()
            .map(|(i, _)| format!("${}", i + 1))
            .collect::<Vec<_>>()
            .join(", ");

        // Build the raw SQL query
        let raw_sql = get_pgsql_query!("select-from-tags")
            .replace("@TAGS", &tags_params)
            .replace("@LEN", &format!("${}", tags.len() + 1))
            .replace("@USER", &format!("${}", tags.len() + 2));

        // Bind the tags params
        let mut query = sqlx::query::<Postgres>(&raw_sql);
        for tag in &tags {
            query = query.bind(tag);
        }
        // Bind the tags len and the user
        query = query.bind(i16::try_from(tags.len())?).bind(user);

        // Execute the query
        query.fetch_all(executor).await?
    } else {
        sqlx::query(get_pgsql_query!("select-object"))
            .bind(uid_or_tags)
            .bind(user)
            .fetch_optional(executor)
            .await?
            .map_or(vec![], |row| vec![row])
    };

    // process the rows and find the tags
    let mut res: HashMap<String, ObjectWithMetadata> = HashMap::new();
    for row in rows {
        let object_with_metadata = ObjectWithMetadata::try_from(&row)?;

        // check if the user, who is not an owner, has the right permissions
        if (user != object_with_metadata.owner)
            && !object_with_metadata.permissions.contains(&operation_type)
        {
            continue
        }

        // check if the object is already in the result
        // this can happen as permissions may have been granted
        // to both this user and the wildcard user
        match res.get_mut(&object_with_metadata.id) {
            Some(existing_object) => {
                // update the permissions
                existing_object
                    .permissions
                    .extend_from_slice(&object_with_metadata.permissions);
            }
            None => {
                // insert the object
                res.insert(object_with_metadata.id.clone(), object_with_metadata);
            }
        };
    }
    Ok(res)
}

async fn retrieve_tags_<'e, E>(uid: &str, executor: E) -> KResult<HashSet<String>>
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

pub(crate) async fn update_object_(
    uid: &str,
    object: &Object,
    attributes: &Attributes,
    tags: Option<&HashSet<String>>,
    executor: &mut Transaction<'_, Postgres>,
) -> KResult<()> {
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    let attributes_json = serde_json::to_value(attributes)
        .context("failed serializing the attributes to JSON")
        .reason(ErrorReason::Internal_Server_Error)?;

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

pub(crate) async fn update_state_(
    uid: &str,
    state: StateEnumeration,
    executor: &mut Transaction<'_, Postgres>,
) -> KResult<()> {
    sqlx::query(get_pgsql_query!("update-object-with-state"))
        .bind(state.to_string())
        .bind(uid)
        .execute(&mut **executor)
        .await?;
    trace!("Updated in DB: {uid}");
    Ok(())
}

pub(crate) async fn delete_(
    uid: &str,
    owner: &str,
    executor: &mut Transaction<'_, Postgres>,
) -> KResult<()> {
    // delete the object
    sqlx::query(get_pgsql_query!("delete-object"))
        .bind(uid)
        .bind(owner)
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

pub(crate) async fn upsert_(
    uid: &str,
    owner: &str,
    object: &Object,
    attributes: &Attributes,
    tags: Option<&HashSet<String>>,
    state: StateEnumeration,
    executor: &mut Transaction<'_, Postgres>,
) -> KResult<()> {
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    let attributes_json = serde_json::to_value(attributes)
        .context("failed serializing the attributes to JSON")
        .reason(ErrorReason::Internal_Server_Error)?;

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

pub(crate) async fn list_accesses_<'e, E>(
    uid: &str,
    executor: E,
) -> KResult<HashMap<String, HashSet<ObjectOperationType>>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    debug!("Uid = {}", uid);

    let list = sqlx::query(get_pgsql_query!("select-rows-read_access-with-object-id"))
        .bind(uid)
        .fetch_all(executor)
        .await?;
    let mut ids: HashMap<String, HashSet<ObjectOperationType>> = HashMap::with_capacity(list.len());
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
) -> KResult<HashMap<String, (String, StateEnumeration, HashSet<ObjectOperationType>)>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    debug!("Owner = {}", user);
    let list = sqlx::query(get_pgsql_query!("select-objects-access-obtained"))
        .bind(user)
        .fetch_all(executor)
        .await?;
    let mut ids: HashMap<String, (String, StateEnumeration, HashSet<ObjectOperationType>)> =
        HashMap::with_capacity(list.len());
    for row in list {
        ids.insert(
            row.get::<String, _>(0),
            (
                row.get::<String, _>(1),
                state_from_string(&row.get::<String, _>(2))?,
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
) -> KResult<HashSet<ObjectOperationType>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let mut user_perms = perms(uid, userid, executor).await?;
    if no_inherited_access || userid == "*" {
        return Ok(user_perms)
    }
    user_perms.extend(perms(uid, "*", executor).await?);
    Ok(user_perms)
}

async fn perms<'e, E>(uid: &str, userid: &str, executor: E) -> KResult<HashSet<ObjectOperationType>>
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
        serde_json::from_value(perms_value)
            .context("failed deserializing the permissions")
            .reason(ErrorReason::Internal_Server_Error)
    })
}

pub(crate) async fn insert_access_<'e, E>(
    uid: &str,
    userid: &str,
    operation_types: HashSet<ObjectOperationType>,
    executor: E,
) -> KResult<()>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    // Retrieve existing permissions if any
    let mut perms = list_user_access_rights_on_object_(uid, userid, false, executor).await?;
    if operation_types.is_subset(&perms) {
        // permissions are already setup
        return Ok(())
    }
    perms.extend(operation_types.iter());

    // Serialize permissions
    let json = serde_json::to_value(&perms)
        .context("failed serializing the permissions to JSON")
        .reason(ErrorReason::Internal_Server_Error)?;

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

pub(crate) async fn remove_access_<'e, E>(
    uid: &str,
    userid: &str,
    operation_types: HashSet<ObjectOperationType>,
    executor: E,
) -> KResult<()>
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
        return Ok(())
    }

    // Serialize permissions
    let json = serde_json::to_value(&perms)
        .context("failed serializing the permissions to JSON")
        .reason(ErrorReason::Internal_Server_Error)?;

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

pub(crate) async fn is_object_owned_by_<'e, E>(uid: &str, owner: &str, executor: E) -> KResult<bool>
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

pub(crate) async fn find_<'e, E>(
    researched_attributes: Option<&Attributes>,
    state: Option<StateEnumeration>,
    user: &str,
    user_must_be_owner: bool,
    executor: E,
) -> KResult<Vec<(String, StateEnumeration, Attributes, IsWrapped)>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let query = query_from_attributes::<PgSqlPlaceholder>(
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
fn to_qualified_uids(
    rows: &[PgRow],
) -> KResult<Vec<(String, StateEnumeration, Attributes, IsWrapped)>> {
    let mut uids = Vec::with_capacity(rows.len());
    for row in rows {
        let attrs: Attributes = match row.try_get::<Value, _>(2) {
            Err(_) => return Err(KmsError::DatabaseError("no attributes found".to_owned())),
            Ok(v) => serde_json::from_value(v)
                .context("failed deserializing the attributes")
                .map_err(|e| KmsError::DatabaseError(e.to_string()))?,
        };

        uids.push((
            row.get::<String, _>(0),
            state_from_string(&row.get::<String, _>(1))?,
            attrs,
            row.get::<IsWrapped, _>(3),
        ));
    }
    Ok(uids)
}

async fn clear_database_<'e, E>(executor: E) -> KResult<()>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    // Erase `context` table
    sqlx::query(get_pgsql_query!("clean-table-context"))
        .execute(executor)
        .await?;
    // Erase `objects` table
    sqlx::query(get_pgsql_query!("clean-table-objects"))
        .execute(executor)
        .await?;
    // Erase `read_access` table
    sqlx::query(get_pgsql_query!("clean-table-read_access"))
        .execute(executor)
        .await?;
    // Erase `tags` table
    sqlx::query(get_pgsql_query!("clean-table-tags"))
        .execute(executor)
        .await?;
    Ok(())
}

pub(crate) async fn atomic_(
    owner: &str,
    operations: &[AtomicOperation],
    tx: &mut Transaction<'_, Postgres>,
) -> KResult<()> {
    for operation in operations {
        match operation {
            AtomicOperation::Create((uid, object, attributes, tags)) => {
                if let Err(e) =
                    create_(Some(uid.clone()), owner, object, attributes, tags, tx).await
                {
                    kms_bail!("creation of object {uid} failed: {e}");
                }
            }
            AtomicOperation::UpdateObject((uid, object, attributes, tags)) => {
                if let Err(e) = update_object_(uid, object, attributes, tags.as_ref(), tx).await {
                    kms_bail!("update of object {uid} failed: {e}");
                }
            }
            AtomicOperation::UpdateState((uid, state)) => {
                if let Err(e) = update_state_(uid, *state, tx).await {
                    kms_bail!("update of the state of object {uid} failed: {e}");
                }
            }
            AtomicOperation::Upsert((uid, object, attributes, tags, state)) => {
                if let Err(e) =
                    upsert_(uid, owner, object, attributes, tags.as_ref(), *state, tx).await
                {
                    kms_bail!("upsert of object {uid} failed: {e}");
                }
            }
            AtomicOperation::Delete(uid) => {
                if let Err(e) = delete_(uid, owner, tx).await {
                    kms_bail!("deletion of object {uid} failed: {e}");
                }
            }
        }
    }
    Ok(())
}

pub(crate) async fn is_migration_in_progress_<'e, E>(executor: E) -> KResult<bool>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    (sqlx::query(get_pgsql_query!("select-context"))
        .fetch_optional(executor)
        .await?)
        .map_or(Ok(false), |context_row| {
            let state = context_row.get::<String, _>(1);
            Ok(state == "upgrading")
        })
}

pub(crate) async fn migrate_(
    executor: &Pool<Postgres>,
    last_version_run: &str,
    query_name: &str,
) -> KResult<()> {
    trace!("Set status to upgrading and last version run: {last_version_run}");
    let upsert_context = get_pgsql_query!(query_name);
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
        _ => kms_bail!("Unknown query name: {query_name}"),
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
    sqlx::query(get_pgsql_query!("update-context"))
        .bind(current_kms_version)
        .bind("ready")
        .bind("upgrading")
        .execute(executor)
        .await?;

    Ok(())
}

/// Before the version 4.13.0, the KMIP attributes were stored in the objects table (via the objects themselves).
/// The new column attributes allows to store the KMIP attributes in a dedicated column even for KMIP objects that do not have KMIP attributes (such as Certificates).
pub(crate) async fn migrate_from_4_12_0_to_4_13_0(executor: &Pool<Postgres>) -> KResult<()> {
    trace!("Migrating from 4.12.0 to 4.13.0");

    // Add the column attributes to the objects table
    if (sqlx::query(get_pgsql_query!("has-column-attributes"))
        .execute(executor)
        .await)
        .is_ok()
    {
        trace!("Column attributes already exists, nothing to do");
        return Ok(());
    }

    trace!("Column attributes does not exist, adding it");
    sqlx::query(get_pgsql_query!("add-column-attributes"))
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
            .context("migrate: failed deserializing the object")
            .reason(ErrorReason::Internal_Server_Error)?;
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
        Ok(()) => {
            tx.commit().await?;
            Ok(())
        }
        Err(e) => {
            tx.rollback().await.context("transaction failed")?;
            Err(e)
        }
    }
}
