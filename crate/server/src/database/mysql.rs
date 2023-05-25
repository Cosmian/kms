use std::{path::PathBuf, str::FromStr};

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    kmip_objects::{self, Object},
    kmip_operations::ErrorReason,
    kmip_types::{Attributes, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_utils::types::{ExtraDatabaseParams, IsWrapped, ObjectOperationTypes};
use serde_json::Value;
use sqlx::{
    mysql::{MySqlConnectOptions, MySqlPoolOptions, MySqlRow},
    ConnectOptions, Executor, MySql, Pool, Row,
};
use tracing::trace;
use uuid::Uuid;

use super::{
    query_from_attributes, state_from_string, DBObject, Database, MySqlPlaceholder, MYSQL_QUERIES,
};
use crate::{
    error::KmsError,
    kms_bail, kms_error,
    result::{KResult, KResultHelper},
};

/// The `MySQL` connector is also compatible to connect a `MariaDB`
/// see: https://mariadb.com/kb/en/mariadb-vs-mysql-compatibility/
pub struct Sql {
    pool: Pool<MySql>,
}

impl Sql {
    pub async fn instantiate(connection_url: &str) -> KResult<Self> {
        let options = MySqlConnectOptions::from_str(connection_url)?
            // disable logging of each query
            .disable_statement_logging();

        let pool = MySqlPoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        sqlx::query(
            MYSQL_QUERIES
                .get("create-table-objects")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            MYSQL_QUERIES
                .get("create-table-read_access")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    #[cfg(test)]
    pub async fn clean_database(&self) {
        // Erase `objects` table
        sqlx::query(
            MYSQL_QUERIES
                .get("clean-table-objects")
                .expect("SQL query can't be found"),
        )
        .execute(&self.pool)
        .await
        .expect("cannot truncate objects table");
        // Erase `read_access` table
        sqlx::query(
            MYSQL_QUERIES
                .get("clean-table-read_access")
                .expect("SQL query can't be found"),
        )
        .execute(&self.pool)
        .await
        .expect("cannot truncate read_access table");
    }

    #[cfg(test)]
    pub async fn perms(&self, uid: &str, userid: &str) -> KResult<Vec<ObjectOperationTypes>> {
        fetch_permissions_(uid, userid, &self.pool).await
    }
}

async fn create_<'e, E>(
    uid: Option<String>,
    owner: &str,
    object: &kmip_objects::Object,
    executor: E,
) -> KResult<UniqueIdentifier>
where
    E: Executor<'e, Database = MySql>,
{
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());

    sqlx::query(
        MYSQL_QUERIES
            .get("insert-row-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid.clone())
    .bind(object_json)
    .bind(StateEnumeration::Active.to_string())
    .bind(owner)
    .execute(executor)
    .await?;
    Ok(uid)
}

async fn retrieve_<'e, E>(
    uid: &str,
    owner_or_userid: &str,
    operation_type: ObjectOperationTypes,
    executor: E,
) -> KResult<Option<(kmip_objects::Object, StateEnumeration)>>
where
    E: Executor<'e, Database = MySql> + Copy,
{
    let row: Option<MySqlRow> = sqlx::query(
        MYSQL_QUERIES
            .get("select-row-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(owner_or_userid)
    .fetch_optional(executor)
    .await?;

    if let Some(row) = row {
        let json = row.get::<Value, _>(0);
        let db_object: DBObject = serde_json::from_value(json)
            .context("failed deserializing the object")
            .reason(ErrorReason::Internal_Server_Error)?;
        let object = Object::post_fix(db_object.object_type, db_object.object);
        let state = state_from_string(&row.get::<String, _>(1))?;
        return Ok(Some((object, state)))
    }

    let row: Option<MySqlRow> = sqlx::query(
        MYSQL_QUERIES
            .get("select-row-objects-join-read_access")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(uid)
    .bind(owner_or_userid)
    .fetch_optional(executor)
    .await?;

    row.map_or(Ok(None), |row| {
        let perms_raw = row.get::<Value, _>(2);
        let perms: Vec<ObjectOperationTypes> = serde_json::from_value(perms_raw)
            .context("failed deserializing the permissions")
            .reason(ErrorReason::Internal_Server_Error)?;

        // Check this operation is legit to fetch this object
        if perms.into_iter().all(|p| p != operation_type) {
            return Err(KmsError::Unauthorized(format!(
                "No authorization to perform the operation {operation_type} on the object {uid} / \
                 {owner_or_userid}"
            )))
        }

        let json = row.get::<Value, _>(0);
        let db_object: DBObject = serde_json::from_value(json)
            .context("failed deserializing the object")
            .reason(ErrorReason::Internal_Server_Error)?;
        let object = Object::post_fix(db_object.object_type, db_object.object);
        let state = state_from_string(&row.get::<String, _>(1))?;

        Ok(Some((object, state)))
    })
}

async fn update_object_<'e, E>(uid: &str, object: &kmip_objects::Object, executor: E) -> KResult<()>
where
    E: Executor<'e, Database = MySql>,
{
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    sqlx::query(
        MYSQL_QUERIES
            .get("update-rows-objects-with-object")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(object_json)
    .bind(uid)
    .execute(executor)
    .await?;
    Ok(())
}

async fn update_state_<'e, E>(uid: &str, state: StateEnumeration, executor: E) -> KResult<()>
where
    E: Executor<'e, Database = MySql>,
{
    sqlx::query(
        MYSQL_QUERIES
            .get("update-rows-objects-with-state")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(state.to_string())
    .bind(uid)
    .execute(executor)
    .await?;
    Ok(())
}

async fn delete_<'e, E>(uid: &str, owner: &str, executor: E) -> KResult<()>
where
    E: Executor<'e, Database = MySql>,
{
    sqlx::query(
        MYSQL_QUERIES
            .get("delete-rows-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(owner)
    .execute(executor)
    .await?;
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
    E: Executor<'e, Database = MySql>,
{
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    sqlx::query(
        MYSQL_QUERIES
            .get("upsert-row-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(object_json)
    .bind(state.to_string())
    .bind(owner)
    .bind(owner)
    .bind(owner)
    .execute(executor)
    .await?;
    Ok(())
}

async fn list_accesses_<'e, E>(
    uid: &str,
    executor: E,
) -> KResult<Vec<(String, Vec<ObjectOperationTypes>)>>
where
    E: Executor<'e, Database = MySql>,
{
    let list = sqlx::query(
        MYSQL_QUERIES
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
        ))
    }
    Ok(ids)
}

async fn list_shared_objects_<'e, E>(
    user: &str,
    executor: E,
) -> KResult<
    Vec<(
        UniqueIdentifier,
        String,
        StateEnumeration,
        Vec<ObjectOperationTypes>,
        IsWrapped,
    )>,
>
where
    E: Executor<'e, Database = MySql>,
{
    let list = sqlx::query(
        MYSQL_QUERIES
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
        Vec<ObjectOperationTypes>,
        IsWrapped,
    )> = Vec::with_capacity(list.len());
    for row in list {
        ids.push((
            row.get::<String, _>(0),
            row.get::<String, _>(1),
            state_from_string(&row.get::<String, _>(2))?,
            serde_json::from_value(row.get::<Value, _>(3))?,
            false, // TODO: unharcode this value by updating the query. See issue: http://gitlab.cosmian.com/core/kms/-/issues/15
        ));
    }
    Ok(ids)
}

async fn fetch_permissions_<'e, E>(
    uid: &str,
    userid: &str,
    executor: E,
) -> KResult<Vec<ObjectOperationTypes>>
where
    E: Executor<'e, Database = MySql>,
{
    let row: Option<MySqlRow> = sqlx::query(
        MYSQL_QUERIES
            .get("select-row-read_access")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(userid)
    .fetch_optional(executor)
    .await?;

    row.map_or(Ok(vec![]), |row| {
        let perms_raw = row.get::<Value, _>(0);
        let perms: Vec<ObjectOperationTypes> = serde_json::from_value(perms_raw)
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
    E: Executor<'e, Database = MySql> + Copy,
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
        MYSQL_QUERIES
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
    E: Executor<'e, Database = MySql> + Copy,
{
    // Retrieve existing permissions if any
    let mut perms = fetch_permissions_(uid, userid, executor).await?;
    perms.retain(|p| *p != operation_type);

    // No remaining permissions, delete the row
    if perms.is_empty() {
        sqlx::query(
            MYSQL_QUERIES
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
        MYSQL_QUERIES
            .get("update-rows-read_access-with-permission")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(json)
    .bind(uid)
    .bind(userid)
    .execute(executor)
    .await?;
    trace!("Deleted in DB: {uid} / {userid}");
    Ok(())
}

async fn is_object_owned_by_<'e, E>(uid: &str, owner: &str, executor: E) -> KResult<bool>
where
    E: Executor<'e, Database = MySql> + Copy,
{
    let row: Option<MySqlRow> = sqlx::query(
        MYSQL_QUERIES
            .get("has-row-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(owner)
    .fetch_optional(executor)
    .await?;

    Ok(row.is_some())
}

async fn find_<'e, E>(
    researched_attributes: Option<&Attributes>,
    state: Option<StateEnumeration>,
    owner: &str,
    executor: E,
) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes, IsWrapped)>>
where
    E: Executor<'e, Database = MySql> + Copy,
{
    let query = query_from_attributes::<MySqlPlaceholder>(researched_attributes, state, owner)?;

    let query = sqlx::query(&query);
    let list = query.fetch_all(executor).await?;

    let mut uids = Vec::with_capacity(list.len());
    for row in list {
        let raw = row.get::<serde_json::Value, _>(2);

        let attrs: Attributes = serde_json::from_value(raw)
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

#[async_trait]
impl Database for Sql {
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
            match create_(uid.clone(), owner, object, &mut *tx).await {
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
        object: &kmip_objects::Object,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        update_object_(uid, object, &self.pool).await
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
            IsWrapped,
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
        owner: &str,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<bool> {
        is_object_owned_by_(uid, owner, &self.pool).await
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

// Run these tests using: `cargo make rust-tests`
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
    use cosmian_kms_utils::{crypto::symmetric::create_symmetric_key, types::ObjectOperationTypes};
    use serial_test::serial;
    use uuid::Uuid;

    use super::Sql;
    use crate::{database::Database, error::KmsError, kms_bail, kms_error, result::KResult};

    #[actix_rt::test]
    #[serial(mysql)]
    pub async fn test_crud() -> KResult<()> {
        let mut rng = CsRng::from_entropy();
        let mysql_url = std::option_env!("KMS_MYSQL_URL")
            .ok_or_else(|| kms_error!("No MySQL database configured"))?;
        let mysql = Sql::instantiate(mysql_url).await?;
        mysql.clean_database().await;

        let owner = "eyJhbGciOiJSUzI1Ni";

        // test non existent row (with very high probability)
        if mysql
            .retrieve(
                &Uuid::new_v4().to_string(),
                owner,
                ObjectOperationTypes::Get,
                None,
            )
            .await?
            .is_some()
        {
            kms_bail!("There should be no object");
        }

        // Insert an object and query it, update it, delete it, query it
        let mut symmetric_key = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key);
        let mut symmetric_key =
            create_symmetric_key(symmetric_key.as_slice(), CryptographicAlgorithm::AES);

        let uid = Uuid::new_v4().to_string();

        let uid_ = mysql
            .create(Some(uid.clone()), owner, &symmetric_key, None)
            .await?;
        assert_eq!(&uid, &uid_);

        match mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get, None)
            .await?
        {
            Some((obj_, state_)) => {
                assert_eq!(StateEnumeration::Active, state_);
                assert_eq!(&symmetric_key, &obj_);
            }
            None => kms_bail!("There should be an object"),
        }

        let mut attributes = symmetric_key.attributes_mut()?;
        attributes.link = Some(vec![Link {
            link_type: LinkType::PreviousLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString("foo".to_string()),
        }]);

        mysql.update_object(&uid, &symmetric_key, None).await?;

        match mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get, None)
            .await?
        {
            Some((obj_, state_)) => {
                assert_eq!(StateEnumeration::Active, state_);
                assert_eq!(
                    obj_.attributes()?
                        .link
                        .as_ref()
                        .ok_or_else(|| KmsError::ServerError(
                            "links should not be empty".to_string()
                        ))?[0]
                        .linked_object_identifier,
                    LinkedObjectIdentifier::TextString("foo".to_string())
                );
            }
            None => kms_bail!("There should be an object"),
        }

        mysql
            .update_state(&uid, StateEnumeration::Deactivated, None)
            .await?;

        match mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get, None)
            .await?
        {
            Some((obj_, state_)) => {
                assert_eq!(StateEnumeration::Deactivated, state_);
                assert_eq!(&symmetric_key, &obj_);
            }
            None => kms_bail!("There should be an object"),
        }

        mysql.delete(&uid, owner, None).await?;

        if mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get, None)
            .await?
            .is_some()
        {
            kms_bail!("The object should have been deleted");
        }

        Ok(())
    }

    #[actix_rt::test]
    #[serial(mysql)]
    pub async fn test_upsert() -> KResult<()> {
        let mut rng = CsRng::from_entropy();
        let mysql_url = std::option_env!("KMS_MYSQL_URL")
            .ok_or_else(|| kms_error!("No MySQL database configured"))?;
        let mysql = Sql::instantiate(mysql_url).await?;
        mysql.clean_database().await;

        let owner = "eyJhbGciOiJSUzI1Ni";

        // Create key

        let mut symmetric_key = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key);
        let mut symmetric_key =
            create_symmetric_key(symmetric_key.as_slice(), CryptographicAlgorithm::AES);

        let uid = Uuid::new_v4().to_string();

        mysql
            .upsert(&uid, owner, &symmetric_key, StateEnumeration::Active, None)
            .await?;

        match mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get, None)
            .await?
        {
            Some((obj_, state_)) => {
                assert_eq!(StateEnumeration::Active, state_);
                assert_eq!(&symmetric_key, &obj_);
            }
            None => kms_bail!("There should be an object"),
        }

        let mut attributes = symmetric_key.attributes_mut()?;
        attributes.link = Some(vec![Link {
            link_type: LinkType::PreviousLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString("foo".to_string()),
        }]);

        mysql
            .upsert(
                &uid,
                owner,
                &symmetric_key,
                StateEnumeration::PreActive,
                None,
            )
            .await?;

        match mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get, None)
            .await?
        {
            Some((obj_, state_)) => {
                assert_eq!(StateEnumeration::PreActive, state_);
                assert_eq!(
                    obj_.attributes()?
                        .link
                        .as_ref()
                        .ok_or_else(|| KmsError::ServerError(
                            "links should not be empty".to_string()
                        ))?[0]
                        .linked_object_identifier,
                    LinkedObjectIdentifier::TextString("foo".to_string())
                );
            }
            None => kms_bail!("There should be an object"),
        }

        mysql.delete(&uid, owner, None).await?;

        if mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get, None)
            .await?
            .is_some()
        {
            kms_bail!("The object should have been deleted");
        }

        Ok(())
    }

    #[actix_rt::test]
    #[serial(mysql)]
    pub async fn test_tx_and_list() -> KResult<()> {
        let mut rng = CsRng::from_entropy();
        let mysql_url = std::option_env!("KMS_MYSQL_URL")
            .ok_or_else(|| kms_error!("No MySQL database configured"))?;
        let mysql = Sql::instantiate(mysql_url).await?;
        mysql.clean_database().await;

        let owner = "eyJhbGciOiJSUzI1Ni";

        // Create key

        let mut symmetric_key = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key);
        let symmetric_key_1 =
            create_symmetric_key(symmetric_key.as_slice(), CryptographicAlgorithm::AES);

        let uid_1 = Uuid::new_v4().to_string();

        let mut symmetric_key = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key);
        let symmetric_key_2 =
            create_symmetric_key(symmetric_key.as_slice(), CryptographicAlgorithm::AES);

        let uid_2 = Uuid::new_v4().to_string();

        let ids = mysql
            .create_objects(
                owner,
                &[
                    (Some(uid_1.clone()), symmetric_key_1.clone()),
                    (Some(uid_2.clone()), symmetric_key_2.clone()),
                ],
                None,
            )
            .await?;

        assert_eq!(&uid_1, &ids[0]);
        assert_eq!(&uid_2, &ids[1]);

        let list = mysql.find(None, None, owner, None).await?;
        match list
            .iter()
            .find(|(id, _state, _attrs, _is_wrapped)| id == &uid_1)
        {
            Some((uid_, state_, _attrs, is_wrapped)) => {
                assert_eq!(&uid_1, uid_);
                assert_eq!(&StateEnumeration::Active, state_);
                assert!(!*is_wrapped);
            }
            None => todo!(),
        }
        match list
            .iter()
            .find(|(id, _state, _attrs, _is_wrapped)| id == &uid_2)
        {
            Some((uid_, state_, _attrs, is_wrapped)) => {
                assert_eq!(&uid_2, uid_);
                assert_eq!(&StateEnumeration::Active, state_);
                assert!(!*is_wrapped);
            }
            None => todo!(),
        }

        mysql.delete(&uid_1, owner, None).await?;
        mysql.delete(&uid_2, owner, None).await?;

        if mysql
            .retrieve(&uid_1, owner, ObjectOperationTypes::Get, None)
            .await?
            .is_some()
        {
            kms_bail!("The object 1 should have been deleted");
        }
        if mysql
            .retrieve(&uid_2, owner, ObjectOperationTypes::Get, None)
            .await?
            .is_some()
        {
            kms_bail!("The object 2 should have been deleted");
        }

        Ok(())
    }

    #[actix_rt::test]
    #[serial(mysql)]
    pub async fn test_owner() -> KResult<()> {
        let mut rng = CsRng::from_entropy();
        let mysql_url = std::option_env!("KMS_MYSQL_URL")
            .ok_or_else(|| kms_error!("No MySQL database configured"))?;
        let mysql = Sql::instantiate(mysql_url).await?;
        mysql.clean_database().await;

        let owner = "eyJhbGciOiJSUzI1Ni";
        let userid = "foo@example.org";
        let userid2 = "bar@example.org";
        let invalid_owner = "invalid_owner";

        // Create key

        let mut symmetric_key = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key);
        let symmetric_key =
            create_symmetric_key(symmetric_key.as_slice(), CryptographicAlgorithm::AES);

        let uid = Uuid::new_v4().to_string();

        // test non existent row (with very high probability)
        if mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get, None)
            .await?
            .is_some()
        {
            kms_bail!("There should be no object");
        }

        mysql
            .upsert(&uid, owner, &symmetric_key, StateEnumeration::Active, None)
            .await?;

        assert!(mysql.is_object_owned_by(&uid, owner, None).await?);

        // Retrieve object with valid owner with `Get` operation type - OK

        match mysql
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

        if mysql
            .retrieve(&uid, invalid_owner, ObjectOperationTypes::Get, None)
            .await?
            .is_some()
        {
            kms_bail!("It should not be possible to get this object")
        }

        // Add authorized `userid` to `read_access` table

        mysql
            .insert_access(&uid, userid, ObjectOperationTypes::Get, None)
            .await?;

        // Retrieve object with authorized `userid` with `Create` operation type - ko

        if mysql
            .retrieve(&uid, userid, ObjectOperationTypes::Create, None)
            .await
            .is_ok()
        {
            kms_bail!("It should not be possible to get this object with `Create` request")
        }

        // Retrieve object with authorized `userid` with `Get` operation type - OK

        match mysql
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

        mysql
            .insert_access(&uid, userid2, ObjectOperationTypes::Get, None)
            .await?;

        // Try to add same access again - OK

        mysql
            .insert_access(&uid, userid2, ObjectOperationTypes::Get, None)
            .await?;

        let objects = mysql.find(None, None, owner, None).await?;
        assert_eq!(objects.len(), 1);
        let (o_uid, o_state, _, _) = &objects[0];
        assert_eq!(o_uid, &uid);
        assert_eq!(o_state, &StateEnumeration::Active);

        let objects = mysql.find(None, None, userid2, None).await?;
        assert!(objects.is_empty());

        let objects = mysql.list_shared_objects(userid2, None).await?;
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

        if mysql
            .retrieve(&uid, userid2, ObjectOperationTypes::Create, None)
            .await
            .is_ok()
        {
            kms_bail!("It should not be possible to get this object with `Create` request")
        }

        // Retrieve object with authorized `userid` with `Get` operation type - OK

        match mysql
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

        match mysql
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

        mysql
            .delete_access(&uid, userid2, ObjectOperationTypes::Get, None)
            .await?;

        // Retrieve object with `userid2` with `Get` operation type - ko

        if mysql
            .retrieve(&uid, userid2, ObjectOperationTypes::Get, None)
            .await?
            .is_some()
        {
            kms_bail!("It should not be possible to get this object with `Get` request")
        }

        Ok(())
    }

    #[actix_rt::test]
    #[serial(mysql)]
    pub async fn test_permissions() -> KResult<()> {
        let userid = "foo@example.org";
        let userid2 = "bar@example.org";
        let mysql_url = std::option_env!("KMS_MYSQL_URL")
            .ok_or_else(|| kms_error!("No MySQL database configured"))?;
        let mysql = Sql::instantiate(mysql_url).await?;
        mysql.clean_database().await;

        let uid = Uuid::new_v4().to_string();

        // simple insert
        mysql
            .insert_access(&uid, userid, ObjectOperationTypes::Get, None)
            .await?;

        let perms = mysql.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        // double insert, expect no duplicate
        mysql
            .insert_access(&uid, userid, ObjectOperationTypes::Get, None)
            .await?;

        let perms = mysql.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        // insert other operation type
        mysql
            .insert_access(&uid, userid, ObjectOperationTypes::Encrypt, None)
            .await?;

        let perms = mysql.perms(&uid, userid).await?;
        assert_eq!(
            perms,
            vec![ObjectOperationTypes::Get, ObjectOperationTypes::Encrypt]
        );

        // insert other `userid2`, check it is ok and it didn't change anything for `userid`
        mysql
            .insert_access(&uid, userid2, ObjectOperationTypes::Get, None)
            .await?;

        let perms = mysql.perms(&uid, userid2).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        let perms = mysql.perms(&uid, userid).await?;
        assert_eq!(
            perms,
            vec![ObjectOperationTypes::Get, ObjectOperationTypes::Encrypt]
        );

        let accesses = mysql.list_accesses(&uid, None).await?;
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
        mysql
            .delete_access(&uid, userid, ObjectOperationTypes::Get, None)
            .await?;

        let perms = mysql.perms(&uid, userid2).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        let perms = mysql.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Encrypt]);

        Ok(())
    }

    #[actix_rt::test]
    #[serial(mysql)]
    pub async fn test_json_access() -> KResult<()> {
        let mut rng = CsRng::from_entropy();
        let mysql_url = std::option_env!("KMS_MYSQL_URL")
            .ok_or_else(|| kms_error!("No MySQL database configured"))?;
        let db = Sql::instantiate(mysql_url).await?;
        db.clean_database().await;

        let owner = "eyJhbGciOiJSUzI1Ni";

        // Create key

        let mut symmetric_key = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key);
        let symmetric_key =
            create_symmetric_key(symmetric_key.as_slice(), CryptographicAlgorithm::AES);

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
    #[serial(mysql)]
    pub async fn test_find_attrs() -> KResult<()> {
        let mut rng = CsRng::from_entropy();
        let mysql_url = std::option_env!("KMS_MYSQL_URL")
            .ok_or_else(|| kms_error!("No MySQL database configured"))?;
        let db = Sql::instantiate(mysql_url).await?;
        db.clean_database().await;

        let owner = "eyJhbGciOiJSUzI1Ni";

        // Insert an object and query it, update it, delete it, query it
        let mut symmetric_key = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key);
        let mut symmetric_key =
            create_symmetric_key(symmetric_key.as_slice(), CryptographicAlgorithm::AES);

        let uid = Uuid::new_v4().to_string();

        // Define the link vector
        let link = vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString("foo".to_string()),
        }];

        let mut attributes = symmetric_key.attributes_mut()?;
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
