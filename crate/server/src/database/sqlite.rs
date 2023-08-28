use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    kmip_objects,
    kmip_operations::ErrorReason,
    kmip_types::{Attributes, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, IsWrapped, ObjectOperationType};
use serde_json::Value;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow},
    ConnectOptions, Executor, Pool, Row, Sqlite, Transaction,
};
use tracing::{debug, trace};
use uuid::Uuid;

use super::object_with_metadata::ObjectWithMetadata;
use crate::{
    database::{
        query_from_attributes, state_from_string, DBObject, Database, SqlitePlaceholder,
        SQLITE_QUERIES,
    },
    error::KmsError,
    kms_bail, kms_error,
    result::{KResult, KResultHelper},
};

pub struct SqlitePool {
    pool: Pool<Sqlite>,
}

impl SqlitePool {
    /// Instantiate a new `SQLite` database
    /// and create the appropriate table(s) if need be
    pub async fn instantiate(path: &Path, clear_database: bool) -> KResult<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            // Sets a timeout value to wait when the database is locked, before returning a busy timeout error.
            .busy_timeout(Duration::from_secs(120))
            .create_if_missing(true)
            // disable logging of each query
            .disable_statement_logging();

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;

        sqlx::query(
            SQLITE_QUERIES
                .get("create-table-objects")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            SQLITE_QUERIES
                .get("create-table-read_access")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            SQLITE_QUERIES
                .get("create-table-tags")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .execute(&pool)
        .await?;

        if clear_database {
            clear_database_(&pool).await?;
        }

        Ok(Self { pool })
    }
}

#[async_trait]
impl Database for SqlitePool {
    fn filename(&self, _group_id: u128) -> Option<PathBuf> {
        None
    }

    async fn create(
        &self,
        uid: Option<String>,
        user: &str,
        object: &kmip_objects::Object,
        tags: &HashSet<String>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<UniqueIdentifier> {
        let mut tx = self.pool.begin().await?;
        let uid = match create_(uid, user, object, tags, &mut tx).await {
            Ok(uid) => uid,
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                kms_bail!("creation of object failed: {e}");
            }
        };
        tx.commit().await?;
        Ok(uid)
    }

    async fn create_objects(
        &self,
        user: &str,
        objects: &[(Option<String>, kmip_objects::Object, &HashSet<String>)],
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<UniqueIdentifier>> {
        let mut res = vec![];
        let mut tx = self.pool.begin().await?;
        for (uid, object, tags) in objects {
            match create_(uid.clone(), user, object, tags, &mut tx).await {
                Ok(uid) => res.push(uid),
                Err(e) => {
                    tx.rollback().await.context("transaction failed")?;
                    kms_bail!("creation of objects failed: {}", e);
                }
            };
        }
        tx.commit().await?;
        Ok(res)
    }

    async fn retrieve(
        &self,
        uid_or_tags: &str,
        user: &str,
        operation_type: ObjectOperationType,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<ObjectWithMetadata>> {
        retrieve_(uid_or_tags, user, operation_type, &self.pool).await
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
        object: &kmip_objects::Object,
        tags: Option<&HashSet<String>>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let mut tx = self.pool.begin().await?;
        match update_object_(uid, object, tags, &mut tx).await {
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
        update_state_(uid, state, &self.pool).await
    }

    async fn upsert(
        &self,
        uid: &str,
        user: &str,
        object: &kmip_objects::Object,
        tags: &HashSet<String>,
        state: StateEnumeration,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let mut tx = self.pool.begin().await?;
        match upsert_(uid, user, object, tags, state, &mut tx).await {
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

    async fn list_access_rights_obtained(
        &self,
        user: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<
        Vec<(
            UniqueIdentifier,
            String,
            StateEnumeration,
            Vec<ObjectOperationType>,
            IsWrapped,
        )>,
    > {
        list_shared_objects_(user, &self.pool).await
    }

    async fn list_accesses(
        &self,
        uid: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(String, Vec<ObjectOperationType>)>> {
        list_accesses_(uid, &self.pool).await
    }

    async fn grant_access(
        &self,
        uid: &str,
        userid: &str,
        operation_type: ObjectOperationType,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        insert_access_(uid, userid, operation_type, &self.pool).await
    }

    async fn remove_access(
        &self,
        uid: &str,
        userid: &str,
        operation_type: ObjectOperationType,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        delete_access_(uid, userid, operation_type, &self.pool).await
    }

    async fn is_object_owned_by(
        &self,
        uid: &str,
        userid: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<bool> {
        is_object_owned_by_(uid, userid, &self.pool).await
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes, IsWrapped)>> {
        find_(
            researched_attributes,
            state,
            user,
            user_must_be_owner,
            &self.pool,
        )
        .await
    }

    #[cfg(test)]
    async fn perms(
        &self,
        uid: &str,
        userid: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<ObjectOperationType>> {
        fetch_permissions_(uid, userid, &self.pool).await
    }
}

pub(crate) async fn create_(
    uid: Option<String>,
    owner: &str,
    object: &kmip_objects::Object,
    tags: &HashSet<String>,
    executor: &mut Transaction<'_, Sqlite>,
) -> KResult<UniqueIdentifier> {
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    // If the uid is not provided, generate a new one
    let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());

    sqlx::query(
        SQLITE_QUERIES
            .get("insert-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid.clone())
    .bind(object_json)
    .bind(StateEnumeration::Active.to_string())
    .bind(owner)
    .execute(&mut **executor)
    .await?;

    // Insert the tags
    for tag in tags {
        sqlx::query(
            SQLITE_QUERIES
                .get("insert-tags")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
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
) -> KResult<Vec<ObjectWithMetadata>>
where
    E: Executor<'e, Database = Sqlite> + Copy,
{
    let rows: Vec<SqliteRow> = if !uid_or_tags.starts_with('[') {
        sqlx::query(
            SQLITE_QUERIES
                .get("select-object")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .bind(uid_or_tags)
        .bind(user)
        .fetch_optional(executor)
        .await?
        .map_or(vec![], |row| vec![row])
    } else {
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
        let raw_sql = SQLITE_QUERIES
            .get("select-from-tags")
            .context("SQL query can't be found")?
            .replace("@TAGS", &tags_params)
            .replace("@LEN", &format!("${}", tags.len() + 1))
            .replace("@USER", &format!("${}", tags.len() + 2));

        // Bind the tags params
        let mut query = sqlx::query::<Sqlite>(&raw_sql);
        for tag in &tags {
            query = query.bind(tag);
        }
        // Bind the tags len and the user
        query = query.bind(tags.len() as i16).bind(user);

        // Execute the query
        query.fetch_all(executor).await?
    };

    // process the rows and find the tags
    let mut res = vec![];
    for row in rows {
        let object_with_metadata = ObjectWithMetadata::try_from(&row)?;

        // check if the user, who is not an owner, has the right permissions
        if (user != object_with_metadata.owner)
            && !object_with_metadata.permissions.contains(&operation_type)
        {
            continue
        }

        res.push(object_with_metadata);
    }

    Ok(res)
}

pub(crate) async fn retrieve_tags_<'e, E>(uid: &str, executor: E) -> KResult<HashSet<String>>
where
    E: Executor<'e, Database = Sqlite> + Copy,
{
    let rows: Vec<SqliteRow> = sqlx::query(
        SQLITE_QUERIES
            .get("select-tags")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .fetch_all(executor)
    .await?;

    let tags = rows.iter().map(|r| r.get(0)).collect::<HashSet<String>>();

    Ok(tags)
}

pub(crate) async fn update_object_(
    uid: &str,
    object: &kmip_objects::Object,
    tags: Option<&HashSet<String>>,
    executor: &mut Transaction<'_, Sqlite>,
) -> KResult<()> {
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    sqlx::query(
        SQLITE_QUERIES
            .get("update-object-with-object")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(object_json)
    .bind(uid)
    .execute(&mut **executor)
    .await?;

    // delete the existing tags
    sqlx::query(
        SQLITE_QUERIES
            .get("delete-tags")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .execute(&mut **executor)
    .await?;

    // Insert the new tags if any
    if let Some(tags) = tags {
        for tag in tags {
            sqlx::query(
                SQLITE_QUERIES
                    .get("insert-tags")
                    .ok_or_else(|| kms_error!("SQL query can't be found"))?,
            )
            .bind(uid)
            .bind(tag)
            .execute(&mut **executor)
            .await?;
        }
    }

    trace!("Updated in DB: {uid}");
    Ok(())
}

pub(crate) async fn update_state_<'e, E>(
    uid: &str,
    state: StateEnumeration,
    executor: E,
) -> KResult<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        SQLITE_QUERIES
            .get("update-object-with-state")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(state.to_string())
    .bind(uid)
    .execute(executor)
    .await?;
    trace!("Updated in DB: {uid}");
    Ok(())
}

pub(crate) async fn delete_(
    uid: &str,
    owner: &str,
    executor: &mut Transaction<'_, Sqlite>,
) -> KResult<()> {
    // delete the object
    sqlx::query(
        SQLITE_QUERIES
            .get("delete-object")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(owner)
    .execute(&mut **executor)
    .await?;

    // delete the tags
    sqlx::query(
        SQLITE_QUERIES
            .get("delete-tags")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .execute(&mut **executor)
    .await?;

    trace!("Deleted in DB: {uid}");
    Ok(())
}

pub(crate) async fn upsert_(
    uid: &str,
    owner: &str,
    object: &kmip_objects::Object,
    tags: &HashSet<String>,
    state: StateEnumeration,
    executor: &mut Transaction<'_, Sqlite>,
) -> KResult<()> {
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    sqlx::query(
        SQLITE_QUERIES
            .get("upsert-object")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(object_json)
    .bind(state.to_string())
    .bind(owner)
    .execute(&mut **executor)
    .await?;

    // delete the existing tags
    sqlx::query(
        SQLITE_QUERIES
            .get("delete-tags")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .execute(&mut **executor)
    .await?;

    // Insert the new tags
    for tag in tags {
        sqlx::query(
            SQLITE_QUERIES
                .get("insert-tags")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .bind(uid)
        .bind(tag)
        .execute(&mut **executor)
        .await?;
    }

    trace!("Upserted in DB: {uid}");
    Ok(())
}

pub(crate) async fn list_accesses_<'e, E>(
    uid: &str,
    executor: E,
) -> KResult<Vec<(String, Vec<ObjectOperationType>)>>
where
    E: Executor<'e, Database = Sqlite>,
{
    debug!("Uid = {}", uid);

    let list = sqlx::query(
        SQLITE_QUERIES
            .get("select-rows-read_access-with-object-id")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .fetch_all(executor)
    .await?;
    let mut ids: Vec<(String, Vec<ObjectOperationType>)> = Vec::with_capacity(list.len());
    for row in list {
        ids.push((
            row.get::<String, _>(0),
            serde_json::from_value(row.get::<Value, _>(1))?,
        ));
    }
    debug!("Listed {} rows", ids.len());
    Ok(ids)
}

pub(crate) async fn list_shared_objects_<'e, E>(
    user: &str,
    executor: E,
) -> KResult<
    Vec<(
        UniqueIdentifier,
        String,
        StateEnumeration,
        Vec<ObjectOperationType>,
        IsWrapped,
    )>,
>
where
    E: Executor<'e, Database = Sqlite>,
{
    debug!("Owner = {}", user);
    let list = sqlx::query(
        SQLITE_QUERIES
            .get("select-objects-access-obtained")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(user)
    .fetch_all(executor)
    .await?;
    let mut ids: Vec<(
        UniqueIdentifier,
        String,
        StateEnumeration,
        Vec<ObjectOperationType>,
        IsWrapped,
    )> = Vec::with_capacity(list.len());
    for row in list {
        ids.push((
            row.get::<String, _>(0),
            row.get::<String, _>(1),
            state_from_string(&row.get::<String, _>(2))?,
            serde_json::from_slice(&row.get::<Vec<u8>, _>(3))?,
            false, // TODO: unharcode this value by updating the query. See issue: http://gitlab.cosmian.com/core/kms/-/issues/15
        ));
    }
    debug!("Listed {} rows", ids.len());
    Ok(ids)
}

pub(crate) async fn fetch_permissions_<'e, E>(
    uid: &str,
    userid: &str,
    executor: E,
) -> KResult<Vec<ObjectOperationType>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let row: Option<SqliteRow> = sqlx::query(
        SQLITE_QUERIES
            .get("select-row-read_access")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(userid)
    .fetch_optional(executor)
    .await?;

    row.map_or(Ok(vec![]), |row| {
        let perms_raw = row.get::<Vec<u8>, _>(0);
        let perms: Vec<ObjectOperationType> = serde_json::from_slice(&perms_raw)
            .context("failed deserializing the permissions")
            .reason(ErrorReason::Internal_Server_Error)?;
        Ok(perms)
    })
}

pub(crate) async fn insert_access_<'e, E>(
    uid: &str,
    userid: &str,
    operation_type: ObjectOperationType,
    executor: E,
) -> KResult<()>
where
    E: Executor<'e, Database = Sqlite> + Copy,
{
    // Retrieve existing permissions if any
    let mut perms = fetch_permissions_(uid, userid, executor).await?;
    if perms.contains(&operation_type) {
        // permission is already setup
        return Ok(())
    }
    perms.push(operation_type);

    // Serialize permissions
    let json = serde_json::to_value(&perms)
        .context("failed serializing the permissions to JSON")
        .reason(ErrorReason::Internal_Server_Error)?;

    // Upsert the DB
    sqlx::query(
        SQLITE_QUERIES
            .get("upsert-row-read_access")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(userid)
    .bind(json)
    .execute(executor)
    .await?;
    trace!("Insert read access right in DB: {uid} / {userid}");
    Ok(())
}

pub(crate) async fn delete_access_<'e, E>(
    uid: &str,
    userid: &str,
    operation_type: ObjectOperationType,
    executor: E,
) -> KResult<()>
where
    E: Executor<'e, Database = Sqlite> + Copy,
{
    // Retrieve existing permissions if any
    let mut perms = fetch_permissions_(uid, userid, executor).await?;
    perms.retain(|p| *p != operation_type);

    // No remaining permissions, delete the row
    if perms.is_empty() {
        sqlx::query(
            SQLITE_QUERIES
                .get("delete-rows-read_access")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
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
    sqlx::query(
        SQLITE_QUERIES
            .get("update-rows-read_access-with-permission")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
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
    E: Executor<'e, Database = Sqlite> + Copy,
{
    let row: Option<SqliteRow> = sqlx::query(
        SQLITE_QUERIES
            .get("has-row-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
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
) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes, IsWrapped)>>
where
    E: Executor<'e, Database = Sqlite> + Copy,
{
    let query = query_from_attributes::<SqlitePlaceholder>(
        researched_attributes,
        state,
        user,
        user_must_be_owner,
    )?;
    let query = sqlx::query(&query);
    let rows = query.fetch_all(executor).await?;

    to_qualified_uids(&rows)
}

/// Convert a list of rows into a list of qualified uids
fn to_qualified_uids(
    rows: &[SqliteRow],
) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes, IsWrapped)>> {
    let mut uids = Vec::with_capacity(rows.len());
    for row in rows {
        let raw = row.get::<Vec<u8>, _>(2);
        let attrs: Attributes = serde_json::from_slice(&raw)
            .context("failed deserializing attributes")
            .map_err(|e| KmsError::DatabaseError(e.to_string()))?;

        uids.push((
            row.get::<String, _>(0),
            state_from_string(&row.get::<String, _>(1))?,
            attrs,
            row.get::<IsWrapped, _>(3),
        ));
    }
    Ok(uids)
}

pub(crate) async fn clear_database_<'e, E>(executor: E) -> KResult<()>
where
    E: Executor<'e, Database = Sqlite> + Copy,
{
    // Erase `objects` table
    sqlx::query(
        SQLITE_QUERIES
            .get("clean-table-objects")
            .expect("SQL query can't be found"),
    )
    .execute(executor)
    .await?;
    // Erase `read_access` table
    sqlx::query(
        SQLITE_QUERIES
            .get("clean-table-read_access")
            .expect("SQL query can't be found"),
    )
    .execute(executor)
    .await?;
    // Erase `tags` table
    sqlx::query(
        SQLITE_QUERIES
            .get("clean-table-tags")
            .expect("SQL query can't be found"),
    )
    .execute(executor)
    .await?;
    Ok(())
}
