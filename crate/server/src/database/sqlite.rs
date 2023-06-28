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
    pub async fn instantiate(path: &Path) -> KResult<Self> {
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

        Ok(Self { pool })
    }

    #[cfg(test)]
    pub async fn perms(&self, uid: &str, userid: &str) -> KResult<Vec<ObjectOperationType>> {
        fetch_permissions_(uid, userid, &self.pool).await
    }
}

#[async_trait]
impl Database for SqlitePool {
    fn filename(&self, _group_id: u128) -> PathBuf {
        PathBuf::from("")
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
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<String>> {
        retrieve_tags_(uid, &self.pool).await
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &kmip_objects::Object,
        tags: &HashSet<String>,
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
        owner: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes, IsWrapped)>> {
        find_(researched_attributes, state, owner, &self.pool).await
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
        if (user != &object_with_metadata.owner)
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
    tags: &HashSet<String>,
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
    owner: &str,
    executor: E,
) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes, IsWrapped)>>
where
    E: Executor<'e, Database = Sqlite> + Copy,
{
    let query = query_from_attributes::<SqlitePlaceholder>(researched_attributes, state, owner)?;
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

/*
#[cfg(test)]
mod tests {
    use cloudproof::reexport::crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng,
    };
    use cosmian_kmip::kmip::{
        kmip_objects::ObjectType,
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, Link,
            LinkType, LinkedObjectIdentifier, StateEnumeration,
        },
    };
    use cosmian_kms_utils::{
        access::ObjectOperationTypes, crypto::symmetric::create_symmetric_key,
    };
    use tempfile::tempdir;
    use uuid::Uuid;

    use super::SqlitePool;
    use crate::{database::Database, kms_bail, log_utils::log_init, result::KResult};

    #[actix_rt::test]
    pub async fn test_owner() -> KResult<()> {
        log_init("info");
        let mut rng = CsRng::from_entropy();
        let owner = "eyJhbGciOiJSUzI1Ni";
        let userid = "foo@example.org";
        let userid2 = "bar@example.org";
        let invalid_owner = "invalid_owner";
        let dir = tempdir()?;
        let file_path = dir.path().join("test_sqlite.db");
        if file_path.exists() {
            std::fs::remove_file(&file_path).unwrap();
        }

        let db = SqlitePool::instantiate(&file_path).await?;
        let mut symmetric_key_bytes = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key_bytes);
        let symmetric_key = create_symmetric_key(&symmetric_key_bytes, CryptographicAlgorithm::AES);
        let uid = Uuid::new_v4().to_string();

        db.upsert(&uid, owner, &symmetric_key, StateEnumeration::Active, None)
            .await?;

        assert!(db.is_object_owned_by(&uid, owner, None).await?);

        // Retrieve object with valid owner with `Get` operation type - OK

        match db
            .retrieve(&uid, owner, ObjectOperationTypes::Get, None)
            .await?
        {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Retrieve object with invalid owner with `Get` operation type - ko

        if db
            .retrieve(&uid, invalid_owner, ObjectOperationTypes::Get, None)
            .await?
            .is_some()
        {
            kms_bail!("It should not be possible to get this object")
        }

        // Add authorized `userid` to `read_access` table

        db.grant_access(&uid, userid, ObjectOperationTypes::Get, None)
            .await?;

        // Retrieve object with authorized `userid` with `Create` operation type - ko

        if db
            .retrieve(&uid, userid, ObjectOperationTypes::Create, None)
            .await
            .is_ok()
        {
            kms_bail!("It should not be possible to get this object with `Create` request")
        }

        // Retrieve object with authorized `userid` with `Get` operation type - OK

        match db
            .retrieve(&uid, userid, ObjectOperationTypes::Get, None)
            .await?
        {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Add authorized `userid2` to `read_access` table

        db.grant_access(&uid, userid2, ObjectOperationTypes::Get, None)
            .await?;

        // Try to add same access again - OK

        db.grant_access(&uid, userid2, ObjectOperationTypes::Get, None)
            .await?;

        let objects = db.find(None, None, owner, None).await?;
        assert_eq!(objects.len(), 1);
        let (o_uid, o_state, _, _) = &objects[0];
        assert_eq!(o_uid, &uid);
        assert_eq!(o_state, &StateEnumeration::Active);

        let objects = db.find(None, None, userid2, None).await?;
        assert!(objects.is_empty());

        let objects = db.list_access_rights_obtained(userid2, None).await?;
        assert_eq!(
            objects,
            vec![(
                uid.clone(),
                String::from(owner),
                StateEnumeration::Active,
                vec![ObjectOperationTypes::Get],
                false
            )]
        );

        // Retrieve object with authorized `userid2` with `Create` operation type - ko

        if db
            .retrieve(&uid, userid2, ObjectOperationTypes::Create, None)
            .await
            .is_ok()
        {
            kms_bail!("It should not be possible to get this object with `Create` request")
        }

        // Retrieve object with authorized `userid` with `Get` operation type - OK

        match db
            .retrieve(&uid, userid2, ObjectOperationTypes::Get, None)
            .await?
        {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Be sure we can still retrieve object with authorized `userid` with `Get` operation type - OK

        match db
            .retrieve(&uid, userid, ObjectOperationTypes::Get, None)
            .await?
        {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Remove `userid2` authorization

        db.remove_access(&uid, userid2, ObjectOperationTypes::Get, None)
            .await?;

        // Retrieve object with `userid2` with `Get` operation type - ko

        if db
            .retrieve(&uid, userid2, ObjectOperationTypes::Get, None)
            .await?
            .is_some()
        {
            kms_bail!("It should not be possible to get this object with `Get` request")
        }

        Ok(())
    }

    #[actix_rt::test]
    pub async fn test_permissions() -> KResult<()> {
        log_init("info");
        let userid = "foo@example.org";
        let userid2 = "bar@example.org";
        let dir = tempdir()?;
        let file_path = dir.path().join("test_sqlite.db");
        if file_path.exists() {
            std::fs::remove_file(&file_path).unwrap();
        }

        let db = SqlitePool::instantiate(&file_path).await?;
        let uid = Uuid::new_v4().to_string();

        // simple insert
        db.grant_access(&uid, userid, ObjectOperationTypes::Get, None)
            .await?;

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        // double insert, expect no duplicate
        db.grant_access(&uid, userid, ObjectOperationTypes::Get, None)
            .await?;

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        // insert other operation type
        db.grant_access(&uid, userid, ObjectOperationTypes::Encrypt, None)
            .await?;

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(
            perms,
            vec![ObjectOperationTypes::Get, ObjectOperationTypes::Encrypt]
        );

        // insert other `userid2`, check it is ok and it didn't change anything for `userid`
        db.grant_access(&uid, userid2, ObjectOperationTypes::Get, None)
            .await?;

        let perms = db.perms(&uid, userid2).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(
            perms,
            vec![ObjectOperationTypes::Get, ObjectOperationTypes::Encrypt]
        );

        let accesses = db.list_accesses(&uid, None).await?;
        assert_eq!(
            accesses,
            vec![
                (
                    String::from("bar@example.org"),
                    vec![ObjectOperationTypes::Get]
                ),
                (
                    String::from("foo@example.org"),
                    vec![ObjectOperationTypes::Get, ObjectOperationTypes::Encrypt]
                )
            ]
        );

        // remove `Get` access for `userid`
        db.remove_access(&uid, userid, ObjectOperationTypes::Get, None)
            .await?;

        let perms = db.perms(&uid, userid2).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Encrypt]);

        Ok(())
    }

    #[actix_rt::test]
    #[cfg_attr(feature = "sqlcipher", ignore)]
    pub async fn test_json_access() -> KResult<()> {
        log_init("info");
        let mut rng = CsRng::from_entropy();
        let owner = "eyJhbGciOiJSUzI1Ni";
        let dir = tempdir()?;
        let file_path = dir.path().join("test_sqlite.db");
        if file_path.exists() {
            std::fs::remove_file(&file_path).unwrap();
        }

        let db = SqlitePool::instantiate(&file_path).await?;

        //

        let mut symmetric_key_bytes = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key_bytes);
        let symmetric_key = create_symmetric_key(&symmetric_key_bytes, CryptographicAlgorithm::AES);

        let uid = Uuid::new_v4().to_string();

        db.upsert(&uid, owner, &symmetric_key, StateEnumeration::Active, None)
            .await?;

        assert!(db.is_object_owned_by(&uid, owner, None).await?);

        // Retrieve object with valid owner with `Get` operation type - OK

        match db
            .retrieve(&uid, owner, ObjectOperationTypes::Get, None)
            .await?
        {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Find with crypto algo attribute

        let researched_attributes = Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                None,
            )
            .await?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, uid);

        // Find with crypto length attribute

        let researched_attributes = Some(Attributes {
            cryptographic_length: Some(symmetric_key.attributes()?.cryptographic_length.unwrap()),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                None,
            )
            .await?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, uid);

        // Find with crypto attributes

        let researched_attributes = Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(symmetric_key.attributes()?.cryptographic_length.unwrap()),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                None,
            )
            .await?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, uid);

        // Find with key format type attribute

        let researched_attributes = Some(Attributes {
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                None,
            )
            .await?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, uid);

        // Find with all attributes

        let researched_attributes = Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(symmetric_key.attributes()?.cryptographic_length.unwrap()),
            cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
            key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                None,
            )
            .await?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, uid);

        // Find bad crypto algo

        let researched_attributes = Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                None,
            )
            .await?;
        assert!(found.is_empty());

        // Find bad key format type

        let researched_attributes = Some(Attributes {
            key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                None,
            )
            .await?;
        assert!(found.is_empty());

        Ok(())
    }

    #[actix_rt::test]
    #[cfg_attr(feature = "sqlcipher", ignore)]
    pub async fn test_find_attrs() -> KResult<()> {
        let mut rng = CsRng::from_entropy();
        let owner = "eyJhbGciOiJSUzI1Ni";
        let dir = tempdir()?;
        let file_path = dir.path().join("test_sqlite.db");
        if file_path.exists() {
            std::fs::remove_file(&file_path).unwrap();
        }

        let db = SqlitePool::instantiate(&file_path).await?;

        //

        let mut symmetric_key_bytes = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key_bytes);
        let mut symmetric_key =
            create_symmetric_key(&symmetric_key_bytes, CryptographicAlgorithm::AES);

        let uid = Uuid::new_v4().to_string();

        // Define the link vector
        let link = vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString("foo".to_string()),
        }];

        let attributes = symmetric_key.attributes_mut()?;
        attributes.link = Some(link.clone());

        let uid_ = db
            .create(Some(uid.clone()), owner, &symmetric_key, None)
            .await?;
        assert_eq!(&uid, &uid_);

        match db
            .retrieve(&uid, owner, ObjectOperationTypes::Get, None)
            .await?
        {
            Some((obj_, state_)) => {
                assert_eq!(StateEnumeration::Active, state_);
                assert_eq!(&symmetric_key, &obj_);
                assert_eq!(
                    obj_.attributes()?.link.as_ref().unwrap()[0].linked_object_identifier,
                    LinkedObjectIdentifier::TextString("foo".to_string())
                );
            }
            None => kms_bail!("There should be an object"),
        }

        let researched_attributes = Some(Attributes {
            link: Some(link.clone()),
            ..Attributes::new(ObjectType::SymmetricKey)
        });
        let found = db
            .find(
                researched_attributes.as_ref(),
                Some(StateEnumeration::Active),
                owner,
                None,
            )
            .await?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, uid);

        Ok(())
    }
}
*/
