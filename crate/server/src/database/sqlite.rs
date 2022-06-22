use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    kmip_objects,
    kmip_operations::ErrorReason,
    kmip_types::{Attributes, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_utils::types::{ExtraDatabaseParams, ObjectOperationTypes};
use serde_json::Value;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow},
    ConnectOptions, Executor, Pool, Row, Sqlite,
};
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{
    database::{
        query_from_attributes, state_from_string, DBObject, Database, SqlitePlaceholder,
        SQLITE_QUERIES,
    },
    error::KmsError,
    kms_bail, kms_error,
    result::{KResult, KResultHelper},
};
pub(crate) struct SqlitePool {
    pool: Pool<Sqlite>,
}

impl SqlitePool {
    /// Instantiate a new `SQLite` database
    /// and create the appropriate table(s) if need be
    pub async fn instantiate(path: &Path) -> KResult<SqlitePool> {
        let mut options = SqliteConnectOptions::new()
            .filename(path)
            // Sets a timeout value to wait when the database is locked, before returning a busy timeout error.
            .busy_timeout(Duration::from_secs(120))
            .create_if_missing(true);
        // disable logging of each query
        options.disable_statement_logging();

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

        Ok(SqlitePool { pool })
    }

    #[cfg(test)]
    pub async fn perms(&self, uid: &str, userid: &str) -> KResult<Vec<ObjectOperationTypes>> {
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
        owner: &str,
        object: &kmip_objects::Object,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<UniqueIdentifier> {
        create_(uid, owner, object, &self.pool).await
    }

    async fn create_objects(
        &self,
        owner: &str,
        objects: &[(Option<String>, kmip_objects::Object)],
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<UniqueIdentifier>> {
        let mut res = vec![];
        let mut tx = self.pool.begin().await?;
        for (uid, object) in objects {
            match create_(uid.to_owned(), owner, object, &mut tx).await {
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
        uid: &str,
        owner: &str,
        operation_type: ObjectOperationTypes,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Option<(kmip_objects::Object, StateEnumeration)>> {
        retrieve_(uid, owner, operation_type, &self.pool).await
    }

    async fn update_object(
        &self,
        uid: &str,
        owner: &str,
        object: &kmip_objects::Object,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        update_object_(uid, owner, object, &self.pool).await
    }

    async fn update_state(
        &self,
        uid: &str,
        owner: &str,
        state: StateEnumeration,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        update_state_(uid, owner, state, &self.pool).await
    }

    async fn upsert(
        &self,
        uid: &str,
        owner: &str,
        object: &kmip_objects::Object,
        state: StateEnumeration,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        upsert_(uid, owner, object, state, &self.pool).await
    }

    async fn delete(
        &self,
        uid: &str,
        owner: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        delete_(uid, owner, &self.pool).await
    }

    async fn list_shared_objects(
        &self,
        owner: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<
        Vec<(
            UniqueIdentifier,
            String,
            StateEnumeration,
            Vec<ObjectOperationTypes>,
        )>,
    > {
        list_shared_objects_(owner, &self.pool).await
    }

    async fn list_accesses(
        &self,
        uid: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(String, Vec<ObjectOperationTypes>)>> {
        list_accesses_(uid, &self.pool).await
    }

    async fn insert_access(
        &self,
        uid: &str,
        userid: &str,
        operation_type: ObjectOperationTypes,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        insert_access_(uid, userid, operation_type, &self.pool).await
    }

    async fn delete_access(
        &self,
        uid: &str,
        userid: &str,
        operation_type: ObjectOperationTypes,
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
    ) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes)>> {
        find_(researched_attributes, state, owner, &self.pool).await
    }
}

pub(crate) async fn create_<'e, E>(
    uid: Option<String>,
    owner: &str,
    object: &kmip_objects::Object,
    executor: E,
) -> KResult<UniqueIdentifier>
where
    E: Executor<'e, Database = Sqlite>,
{
    let object_json = serde_json::to_value(&DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());

    sqlx::query(
        SQLITE_QUERIES
            .get("insert-row-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid.clone())
    .bind(object_json)
    .bind(StateEnumeration::Active.to_string())
    .bind(owner)
    .execute(executor)
    .await?;
    trace!("Created in DB: {uid} / {owner}");
    Ok(uid)
}

pub(crate) async fn retrieve_<'e, E>(
    uid: &str,
    owner_or_userid: &str,
    operation_type: ObjectOperationTypes,
    executor: E,
) -> KResult<Option<(kmip_objects::Object, StateEnumeration)>>
where
    E: Executor<'e, Database = Sqlite> + Copy,
{
    let row: Option<SqliteRow> = sqlx::query(
        SQLITE_QUERIES
            .get("select-row-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(owner_or_userid)
    .fetch_optional(executor)
    .await?;

    if let Some(row) = row {
        let raw = row.get::<Vec<u8>, _>(0);
        let db_object: DBObject = serde_json::from_slice(&raw)
            .context("failed deserializing the object")
            .reason(ErrorReason::Internal_Server_Error)?;
        let object = kmip_objects::Object::post_fix(db_object.object_type, db_object.object);
        let state = state_from_string(&row.get::<String, _>(1))?;
        return Ok(Some((object, state)))
    }

    let row: Option<SqliteRow> = sqlx::query(
        SQLITE_QUERIES
            .get("select-row-objects-join-read_access")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(owner_or_userid)
    .fetch_optional(executor)
    .await?;

    row.map_or(Ok(None), |row| {
        let perms_raw = row.get::<Vec<u8>, _>(2);
        let perms: Vec<ObjectOperationTypes> = serde_json::from_slice(&perms_raw)
            .context("failed deserializing the permissions")
            .reason(ErrorReason::Internal_Server_Error)?;

        // Check this operation is legit to fetch this object
        if perms.into_iter().all(|p| p != operation_type) {
            kms_bail!("No authorization to perform this operation");
        }

        let raw = row.get::<Vec<u8>, _>(0);
        let db_object: DBObject = serde_json::from_slice(&raw)
            .context("failed deserializing the object")
            .reason(ErrorReason::Internal_Server_Error)?;
        let object = kmip_objects::Object::post_fix(db_object.object_type, db_object.object);
        let state = state_from_string(&row.get::<String, _>(1))?;

        Ok(Some((object, state)))
    })
}

pub(crate) async fn update_object_<'e, E>(
    uid: &str,
    owner: &str,
    object: &kmip_objects::Object,
    executor: E,
) -> KResult<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    let object_json = serde_json::to_value(&DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    sqlx::query(
        SQLITE_QUERIES
            .get("update-rows-objects-with-object")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(object_json)
    .bind(uid)
    .bind(owner)
    .execute(executor)
    .await?;
    trace!("Updated in DB: {uid}");
    Ok(())
}

pub(crate) async fn update_state_<'e, E>(
    uid: &str,
    owner: &str,
    state: StateEnumeration,
    executor: E,
) -> KResult<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        SQLITE_QUERIES
            .get("update-rows-objects-with-state")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(state.to_string())
    .bind(uid)
    .bind(owner)
    .execute(executor)
    .await?;
    trace!("Updated in DB: {uid}");
    Ok(())
}

pub(crate) async fn delete_<'e, E>(uid: &str, owner: &str, executor: E) -> KResult<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        SQLITE_QUERIES
            .get("delete-rows-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(owner)
    .execute(executor)
    .await?;
    trace!("Deleted in DB: {uid}");
    Ok(())
}

pub(crate) async fn upsert_<'e, E>(
    uid: &str,
    owner: &str,
    object: &kmip_objects::Object,
    state: StateEnumeration,
    executor: E,
) -> KResult<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    let object_json = serde_json::to_value(&DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    sqlx::query(
        SQLITE_QUERIES
            .get("upsert-row-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(object_json)
    .bind(state.to_string())
    .bind(owner)
    .execute(executor)
    .await?;
    trace!("Upserted in DB: {uid}");
    Ok(())
}

pub(crate) async fn list_accesses_<'e, E>(
    uid: &str,
    executor: E,
) -> KResult<Vec<(String, Vec<ObjectOperationTypes>)>>
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
    let mut ids: Vec<(String, Vec<ObjectOperationTypes>)> = Vec::with_capacity(list.len());
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
        Vec<ObjectOperationTypes>,
    )>,
>
where
    E: Executor<'e, Database = Sqlite>,
{
    debug!("Owner = {}", user);
    let list = sqlx::query(
        SQLITE_QUERIES
            .get("select-rows-objects-shared")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(user)
    .fetch_all(executor)
    .await?;
    let mut ids: Vec<(
        UniqueIdentifier,
        String,
        StateEnumeration,
        Vec<ObjectOperationTypes>,
    )> = Vec::with_capacity(list.len());
    for row in list {
        ids.push((
            row.get::<String, _>(0),
            row.get::<String, _>(1),
            state_from_string(&row.get::<String, _>(2))?,
            serde_json::from_slice(&row.get::<Vec<u8>, _>(3))?,
        ));
    }
    debug!("Listed {} rows", ids.len());
    Ok(ids)
}

pub(crate) async fn fetch_permissions_<'e, E>(
    uid: &str,
    userid: &str,
    executor: E,
) -> KResult<Vec<ObjectOperationTypes>>
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
        let perms: Vec<ObjectOperationTypes> = serde_json::from_slice(&perms_raw)
            .context("failed deserializing the permissions")
            .reason(ErrorReason::Internal_Server_Error)?;
        Ok(perms)
    })
}

pub(crate) async fn insert_access_<'e, E>(
    uid: &str,
    userid: &str,
    operation_type: ObjectOperationTypes,
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
    operation_type: ObjectOperationTypes,
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
) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes)>>
where
    E: Executor<'e, Database = Sqlite> + Copy,
{
    let query = query_from_attributes::<SqlitePlaceholder>(researched_attributes, state, owner)?;

    let query = sqlx::query(&query);
    let list = query.fetch_all(executor).await?;

    let mut uids = Vec::with_capacity(list.len());
    for row in list {
        let raw = row.get::<Vec<u8>, _>(2);
        let attrs: Attributes = serde_json::from_slice(&raw)
            .context("failed deserializing attributes")
            .map_err(|e| KmsError::DatabaseError(e.to_string()))?;

        uids.push((
            row.get::<String, _>(0),
            state_from_string(&row.get::<String, _>(1))?,
            attrs,
        ));
    }

    Ok(uids)
}

#[cfg(test)]
mod tests {
    use cosmian_kmip::kmip::{
        kmip_objects::ObjectType,
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType,
            StateEnumeration,
        },
    };
    use cosmian_kms_utils::{crypto::aes::create_aes_symmetric_key, types::ObjectOperationTypes};
    use tempfile::tempdir;
    use uuid::Uuid;

    use super::SqlitePool;
    use crate::{database::Database, kms_bail, log_utils::log_init, result::KResult};

    #[actix_rt::test]
    pub async fn test_owner() -> KResult<()> {
        log_init("info");
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

        let symmetric_key = create_aes_symmetric_key(None)?;
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

        db.insert_access(&uid, userid, ObjectOperationTypes::Get, None)
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

        db.insert_access(&uid, userid2, ObjectOperationTypes::Get, None)
            .await?;

        // Try to add same access again - OK

        db.insert_access(&uid, userid2, ObjectOperationTypes::Get, None)
            .await?;

        let objects = db.find(None, None, owner, None).await?;
        assert_eq!(objects.len(), 1);
        let (o_uid, o_state, _) = &objects[0];
        assert_eq!(o_uid, &uid);
        assert_eq!(o_state, &StateEnumeration::Active);

        let objects = db.find(None, None, userid2, None).await?;
        assert!(objects.is_empty());

        let objects = db.list_shared_objects(userid2, None).await?;
        assert_eq!(
            objects,
            vec![(
                uid.clone(),
                String::from(owner),
                StateEnumeration::Active,
                vec![ObjectOperationTypes::Get]
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

        db.delete_access(&uid, userid2, ObjectOperationTypes::Get, None)
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
        db.insert_access(&uid, userid, ObjectOperationTypes::Get, None)
            .await?;

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        // double insert, expect no duplicate
        db.insert_access(&uid, userid, ObjectOperationTypes::Get, None)
            .await?;

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        // insert other operation type
        db.insert_access(&uid, userid, ObjectOperationTypes::Encrypt, None)
            .await?;

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(
            perms,
            vec![ObjectOperationTypes::Get, ObjectOperationTypes::Encrypt]
        );

        // insert other `userid2`, check it is ok and it didn't change anything for `userid`
        db.insert_access(&uid, userid2, ObjectOperationTypes::Get, None)
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
        db.delete_access(&uid, userid, ObjectOperationTypes::Get, None)
            .await?;

        let perms = db.perms(&uid, userid2).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Encrypt]);

        Ok(())
    }

    #[actix_rt::test]
    #[ignore]
    pub async fn test_json_access() -> KResult<()> {
        log_init("debug");
        let owner = "eyJhbGciOiJSUzI1Ni";
        let dir = tempdir()?;
        let file_path = dir.path().join("test_sqlite.db");
        if file_path.exists() {
            std::fs::remove_file(&file_path).unwrap();
        }

        let db = SqlitePool::instantiate(&file_path).await?;

        //

        let symmetric_key = create_aes_symmetric_key(None)?;
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
            cryptographic_algorithm: Some(CryptographicAlgorithm::ABE),
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
            key_format_type: Some(KeyFormatType::AbeUserDecryptionKey),
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
}
