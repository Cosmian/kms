use std::path::Path;

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    access::ObjectOperationTypes,
    kmip_objects,
    kmip_operations::ErrorReason,
    kmip_types::{StateEnumeration, UniqueIdentifier},
};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow},
    ConnectOptions, Executor, Pool, Row, Sqlite,
};
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{
    database::{state_from_string, DBObject, Database, SQLITE_QUERIES},
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
            .create_if_missing(true);
        // disable logging of each query
        options.disable_statement_logging();

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
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
    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &kmip_objects::Object,
    ) -> KResult<UniqueIdentifier> {
        create_(uid, owner, object, &self.pool).await
    }

    async fn create_objects(
        &self,
        owner: &str,
        objects: &[(Option<String>, kmip_objects::Object)],
    ) -> KResult<Vec<UniqueIdentifier>> {
        let mut res: Vec<UniqueIdentifier> = vec![];
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
    ) -> KResult<Option<(kmip_objects::Object, StateEnumeration)>> {
        retrieve_(uid, owner, operation_type, &self.pool).await
    }

    async fn update_object(
        &self,
        uid: &str,
        owner: &str,
        object: &kmip_objects::Object,
    ) -> KResult<()> {
        update_object_(uid, owner, object, &self.pool).await
    }

    async fn update_state(&self, uid: &str, owner: &str, state: StateEnumeration) -> KResult<()> {
        update_state_(uid, owner, state, &self.pool).await
    }

    async fn upsert(
        &self,
        uid: &str,
        owner: &str,
        object: &kmip_objects::Object,
        state: StateEnumeration,
    ) -> KResult<()> {
        upsert_(uid, owner, object, state, &self.pool).await
    }

    async fn delete(&self, uid: &str, owner: &str) -> KResult<()> {
        delete_(uid, owner, &self.pool).await
    }

    async fn list(&self, owner: &str) -> KResult<Vec<(UniqueIdentifier, StateEnumeration)>> {
        list_(owner, &self.pool).await
    }

    async fn insert_access(
        &self,
        uid: &str,
        userid: &str,
        operation_type: ObjectOperationTypes,
    ) -> KResult<()> {
        insert_access_(uid, userid, operation_type, &self.pool).await
    }

    async fn delete_access(
        &self,
        uid: &str,
        userid: &str,
        operation_type: ObjectOperationTypes,
    ) -> KResult<()> {
        delete_access_(uid, userid, operation_type, &self.pool).await
    }

    async fn is_object_owned_by(&self, uid: &str, userid: &str) -> KResult<bool> {
        is_object_owned_by_(uid, userid, &self.pool).await
    }
}

async fn create_<'e, E>(
    uid: Option<String>,
    owner: &str,
    object: &kmip_objects::Object,
    executor: E,
) -> KResult<UniqueIdentifier>
where
    E: Executor<'e, Database = Sqlite>,
{
    let json = serde_json::to_value(&DBObject {
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
    .bind(json)
    .bind(StateEnumeration::Active.to_string())
    .bind(owner)
    .execute(executor)
    .await?;
    trace!("Created in DB: {uid} / {owner}");
    Ok(uid)
}

async fn retrieve_<'e, E>(
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

async fn update_object_<'e, E>(
    uid: &str,
    owner: &str,
    object: &kmip_objects::Object,
    executor: E,
) -> KResult<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    let json = serde_json::to_value(&DBObject {
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
    .bind(json)
    .bind(uid)
    .bind(owner)
    .execute(executor)
    .await?;
    trace!("Updated in DB: {uid}");
    Ok(())
}

async fn update_state_<'e, E>(
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

async fn delete_<'e, E>(uid: &str, owner: &str, executor: E) -> KResult<()>
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

async fn upsert_<'e, E>(
    uid: &str,
    owner: &str,
    object: &kmip_objects::Object,
    state: StateEnumeration,
    executor: E,
) -> KResult<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    let json = serde_json::to_value(&DBObject {
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
    .bind(json)
    .bind(state.to_string())
    .bind(owner)
    .execute(executor)
    .await?;
    trace!("Upserted in DB: {uid}");
    Ok(())
}

async fn list_<'e, E>(
    owner: &str,
    executor: E,
) -> KResult<Vec<(UniqueIdentifier, StateEnumeration)>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let list = sqlx::query(
        SQLITE_QUERIES
            .get("select-row-objects-where-owner")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(owner)
    .fetch_all(executor)
    .await?;
    let mut ids: Vec<(String, StateEnumeration)> = Vec::with_capacity(list.len());
    for row in list {
        ids.push((
            row.get::<String, _>(0),
            state_from_string(&row.get::<String, _>(1))?,
        ));
    }
    debug!("Listed {} rows", ids.len());
    Ok(ids)
}

async fn fetch_permissions_<'e, E>(
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

async fn insert_access_<'e, E>(
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

async fn delete_access_<'e, E>(
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

async fn is_object_owned_by_<'e, E>(uid: &str, owner: &str, executor: E) -> KResult<bool>
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

#[cfg(test)]
mod tests {
    use cosmian_kmip::kmip::{access::ObjectOperationTypes, kmip_types::StateEnumeration};
    use cosmian_kms_utils::crypto::aes::create_aes_symmetric_key;
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

        db.upsert(&uid, owner, &symmetric_key, StateEnumeration::Active)
            .await?;

        assert!(db.is_object_owned_by(&uid, owner).await?);

        // Retrieve object with valid owner with `Get` operation type - OK

        match db.retrieve(&uid, owner, ObjectOperationTypes::Get).await? {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Retrieve object with invalid owner with `Get` operation type - ko

        if db
            .retrieve(&uid, invalid_owner, ObjectOperationTypes::Get)
            .await?
            .is_some()
        {
            kms_bail!("It should not be possible to get this object")
        }

        // Add authorized `userid` to `read_access` table

        db.insert_access(&uid, userid, ObjectOperationTypes::Get)
            .await?;

        // Retrieve object with authorized `userid` with `Create` operation type - ko

        if db
            .retrieve(&uid, userid, ObjectOperationTypes::Create)
            .await
            .is_ok()
        {
            kms_bail!("It should not be possible to get this object with `Create` request")
        }

        // Retrieve object with authorized `userid` with `Get` operation type - OK

        match db.retrieve(&uid, userid, ObjectOperationTypes::Get).await? {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Add authorized `userid2` to `read_access` table

        db.insert_access(&uid, userid2, ObjectOperationTypes::Get)
            .await?;

        // Try to add same access again - OK

        db.insert_access(&uid, userid2, ObjectOperationTypes::Get)
            .await?;

        // Retrieve object with authorized `userid2` with `Create` operation type - ko

        if db
            .retrieve(&uid, userid2, ObjectOperationTypes::Create)
            .await
            .is_ok()
        {
            kms_bail!("It should not be possible to get this object with `Create` request")
        }

        // Retrieve object with authorized `userid` with `Get` operation type - OK

        match db
            .retrieve(&uid, userid2, ObjectOperationTypes::Get)
            .await?
        {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Be sure we can still retrieve object with authorized `userid` with `Get` operation type - OK

        match db.retrieve(&uid, userid, ObjectOperationTypes::Get).await? {
            Some((obj, state)) => {
                assert_eq!(StateEnumeration::Active, state);
                assert_eq!(&symmetric_key, &obj);
            }
            None => kms_bail!("There should be an object"),
        }

        // Remove `userid2` authorization

        db.delete_access(&uid, userid2, ObjectOperationTypes::Get)
            .await?;

        // Retrieve object with `userid2` with `Get` operation type - ko

        if db
            .retrieve(&uid, userid2, ObjectOperationTypes::Get)
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
        db.insert_access(&uid, userid, ObjectOperationTypes::Get)
            .await?;

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        // double insert, expect no duplicate
        db.insert_access(&uid, userid, ObjectOperationTypes::Get)
            .await?;

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        // insert other operation type
        db.insert_access(&uid, userid, ObjectOperationTypes::Encrypt)
            .await?;

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(
            perms,
            vec![ObjectOperationTypes::Get, ObjectOperationTypes::Encrypt]
        );

        // insert other `userid2`, check it is ok and it didn't change anything for `userid`
        db.insert_access(&uid, userid2, ObjectOperationTypes::Get)
            .await?;

        let perms = db.perms(&uid, userid2).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(
            perms,
            vec![ObjectOperationTypes::Get, ObjectOperationTypes::Encrypt]
        );

        // remove `Get` access for `userid`
        db.delete_access(&uid, userid, ObjectOperationTypes::Get)
            .await?;

        let perms = db.perms(&uid, userid2).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        let perms = db.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Encrypt]);

        Ok(())
    }
}
