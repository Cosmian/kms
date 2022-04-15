use std::str::FromStr;

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    access::ObjectOperationTypes,
    kmip_objects::{self, Object},
    kmip_operations::ErrorReason,
    kmip_types::{StateEnumeration, UniqueIdentifier},
};
use serde_json::Value;
use sqlx::{
    mysql::{MySqlConnectOptions, MySqlPoolOptions, MySqlRow},
    ConnectOptions, Executor, MySql, Pool, Row,
};
use tracing::trace;
use uuid::Uuid;

use super::database::{state_from_string, DBObject, Database};
use crate::{
    kms_bail,
    result::{KResult, KResultHelper},
};

/// The MySQL connector is also compatible to connect a MariaDB
/// see: https://mariadb.com/kb/en/mariadb-vs-mysql-compatibility/
pub(crate) struct Sql {
    pool: Pool<MySql>,
}

impl Sql {
    pub async fn instantiate(connection_url: &str) -> KResult<Sql> {
        let mut options = MySqlConnectOptions::from_str(connection_url)?;
        // disable logging of each query
        options.disable_statement_logging();

        let pool = MySqlPoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS objects (
                id VARCHAR(40) PRIMARY KEY,
                object json NOT NULL,
                state VARCHAR(32),
                owner VARCHAR(255)
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS read_access (
                id VARCHAR(255),
                userid VARCHAR(255),
                permissions json NOT NULL,
                UNIQUE (id, userid)
            )",
        )
        .execute(&pool)
        .await?;

        Ok(Sql { pool })
    }

    #[cfg(test)]
    pub async fn clean_database(&self) {
        // Erase `objects` table
        sqlx::query("TRUNCATE objects")
            .execute(&self.pool)
            .await
            .expect("cannot truncate objects table");
        // Erase `read_access` table
        sqlx::query("TRUNCATE read_access")
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
    let json = serde_json::to_value(&DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;
    let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());
    sqlx::query("INSERT INTO objects (id, object, state, owner) VALUES (?, ?, ?, ?)")
        .bind(uid.clone())
        .bind(json)
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
    let row: Option<MySqlRow> =
        sqlx::query("SELECT object, state FROM objects WHERE id=? AND owner=?")
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
        "SELECT objects.object, objects.state, read_access.permissions
        FROM objects, read_access
        WHERE objects.id=? AND read_access.id=? AND read_access.userid=?",
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
            kms_bail!("No authorization to perform this operation");
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

async fn update_object_<'e, E>(
    uid: &str,
    owner: &str,
    object: &kmip_objects::Object,
    executor: E,
) -> KResult<()>
where
    E: Executor<'e, Database = MySql>,
{
    let json = serde_json::to_value(&DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;
    sqlx::query("UPDATE objects SET object=? WHERE id=? AND owner=?")
        .bind(json)
        .bind(uid)
        .bind(owner)
        .execute(executor)
        .await?;
    Ok(())
}

async fn update_state_<'e, E>(
    uid: &str,
    owner: &str,
    state: StateEnumeration,
    executor: E,
) -> KResult<()>
where
    E: Executor<'e, Database = MySql>,
{
    sqlx::query("UPDATE objects SET state=? WHERE id=? AND owner=?")
        .bind(state.to_string())
        .bind(uid)
        .bind(owner)
        .execute(executor)
        .await?;
    Ok(())
}

async fn delete_<'e, E>(uid: &str, owner: &str, executor: E) -> KResult<()>
where
    E: Executor<'e, Database = MySql>,
{
    sqlx::query("DELETE FROM objects WHERE id=? AND owner=?")
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
    let json = serde_json::to_value(&DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;
    sqlx::query(
        "INSERT INTO objects (id, object, state, owner) VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            object = IF(objects.owner=?, VALUES(object), object),
            state = IF(objects.owner=?, VALUES(state), state)",
    )
    .bind(uid)
    .bind(json.clone())
    .bind(state.to_string())
    .bind(owner)
    .bind(owner)
    .bind(owner)
    .execute(executor)
    .await?;
    Ok(())
}

async fn list_<'e, E>(
    executor: E,
    owner: &str,
) -> KResult<Vec<(UniqueIdentifier, StateEnumeration)>>
where
    E: Executor<'e, Database = MySql>,
{
    let list = sqlx::query("SELECT id, state FROM objects WHERE owner=?")
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
        "SELECT permissions
        FROM read_access
        WHERE id=? AND userid=?",
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
        "INSERT INTO read_access (id, userid, permissions) VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE
        permissions = IF((id=VALUES(id)) AND (userid=VALUES(userid)), VALUES(permissions), \
         permissions)",
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
        sqlx::query("DELETE FROM read_access WHERE id=? AND userid=?")
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
        "UPDATE read_access SET permissions=?
        WHERE id=? AND userid=?",
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
    let row: Option<MySqlRow> = sqlx::query("SELECT 1 FROM objects WHERE id=? AND owner=?")
        .bind(uid)
        .bind(owner)
        .fetch_optional(executor)
        .await?;

    Ok(row.is_some())
}

#[async_trait]
impl Database for Sql {
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
        list_(&self.pool, owner).await
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

    async fn is_object_owned_by(&self, uid: &str, owner: &str) -> KResult<bool> {
        is_object_owned_by_(uid, owner, &self.pool).await
    }
}

// Run these tests using: `cargo make rust-tests`
#[cfg(test)]
mod tests {
    use cosmian_kmip::kmip::{
        access::ObjectOperationTypes,
        kmip_types::{Link, LinkType, LinkedObjectIdentifier, StateEnumeration},
    };
    use cosmian_kms_utils::crypto::aes::create_aes_symmetric_key;
    use serial_test::serial;
    use uuid::Uuid;

    use super::Sql;
    use crate::{
        kmip::kmip_server::database::Database,
        kms_bail, kms_error,
        result::{KResult, KResultHelper},
    };

    #[actix_rt::test]
    #[serial(mysql)]
    #[ignore]
    pub async fn test_crud() -> KResult<()> {
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
            )
            .await?
            .is_some()
        {
            kms_bail!("There should be no object");
        }

        // Insert an object and query it, update it, delete it, query it
        let mut symmetric_key = create_aes_symmetric_key(None)?;
        let uid = Uuid::new_v4().to_string();

        let uid_ = mysql
            .create(Some(uid.clone()), owner, &symmetric_key)
            .await?;
        assert_eq!(&uid, &uid_);

        match mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get)
            .await?
        {
            Some((obj_, state_)) => {
                assert_eq!(StateEnumeration::Active, state_);
                assert_eq!(&symmetric_key, &obj_);
            }
            None => kms_bail!("There should be an object"),
        }

        let mut attributes = symmetric_key
            .attributes_mut()?
            .context("there should be attributes")?;
        attributes.link = vec![Link {
            link_type: LinkType::PreviousLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString("foo".to_string()),
        }];

        mysql.update_object(&uid, owner, &symmetric_key).await?;

        match mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get)
            .await?
        {
            Some((obj_, state_)) => {
                assert_eq!(StateEnumeration::Active, state_);
                assert_eq!(
                    &obj_
                        .attributes()
                        .context("there should be attributes")?
                        .context("there should be attributes")?
                        .link[0]
                        .linked_object_identifier,
                    &LinkedObjectIdentifier::TextString("foo".to_string())
                );
            }
            None => kms_bail!("There should be an object"),
        }

        mysql
            .update_state(&uid, owner, StateEnumeration::Deactivated)
            .await?;

        match mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get)
            .await?
        {
            Some((obj_, state_)) => {
                assert_eq!(StateEnumeration::Deactivated, state_);
                assert_eq!(&symmetric_key, &obj_);
            }
            None => kms_bail!("There should be an object"),
        }

        mysql.delete(&uid, owner).await?;

        if mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get)
            .await?
            .is_some()
        {
            kms_bail!("The object should have been deleted");
        }

        Ok(())
    }

    #[actix_rt::test]
    #[serial(mysql)]
    #[ignore]
    pub async fn test_upsert() -> KResult<()> {
        let mysql_url = std::option_env!("KMS_MYSQL_URL")
            .ok_or_else(|| kms_error!("No MySQL database configured"))?;
        let mysql = Sql::instantiate(mysql_url).await?;
        mysql.clean_database().await;

        let owner = "eyJhbGciOiJSUzI1Ni";

        let mut symmetric_key = create_aes_symmetric_key(None)?;
        let uid = Uuid::new_v4().to_string();

        mysql
            .upsert(&uid, owner, &symmetric_key, StateEnumeration::Active)
            .await?;

        match mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get)
            .await?
        {
            Some((obj_, state_)) => {
                assert_eq!(StateEnumeration::Active, state_);
                assert_eq!(&symmetric_key, &obj_);
            }
            None => kms_bail!("There should be an object"),
        }

        let mut attributes = symmetric_key
            .attributes_mut()?
            .context("there should be attributes")?;
        attributes.link = vec![Link {
            link_type: LinkType::PreviousLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString("foo".to_string()),
        }];

        mysql
            .upsert(&uid, owner, &symmetric_key, StateEnumeration::PreActive)
            .await?;

        match mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get)
            .await?
        {
            Some((obj_, state_)) => {
                assert_eq!(StateEnumeration::PreActive, state_);
                assert_eq!(
                    &obj_
                        .attributes()
                        .context("there should be attributes")?
                        .context("there should be attributes")?
                        .link[0]
                        .linked_object_identifier,
                    &LinkedObjectIdentifier::TextString("foo".to_string())
                );
            }
            None => kms_bail!("There should be an object"),
        }

        mysql.delete(&uid, owner).await?;

        if mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get)
            .await?
            .is_some()
        {
            kms_bail!("The object should have been deleted");
        }

        Ok(())
    }

    #[actix_rt::test]
    #[serial(mysql)]
    #[ignore]
    pub async fn test_tx_and_list() -> KResult<()> {
        let mysql_url = std::option_env!("KMS_MYSQL_URL")
            .ok_or_else(|| kms_error!("No MySQL database configured"))?;
        let mysql = Sql::instantiate(mysql_url).await?;
        mysql.clean_database().await;

        let owner = "eyJhbGciOiJSUzI1Ni";

        let symmetric_key_1 = create_aes_symmetric_key(None)?;
        let uid_1 = Uuid::new_v4().to_string();

        let symmetric_key_2 = create_aes_symmetric_key(None)?;
        let uid_2 = Uuid::new_v4().to_string();

        let ids = mysql
            .create_objects(
                owner,
                &[
                    (Some(uid_1.clone()), symmetric_key_1.clone()),
                    (Some(uid_2.clone()), symmetric_key_2.clone()),
                ],
            )
            .await?;

        assert_eq!(&uid_1, &ids[0]);
        assert_eq!(&uid_2, &ids[1]);

        let list = mysql.list(owner).await?;
        match list.iter().find(|(id, _state)| id == &uid_1) {
            Some((uid_, state_)) => {
                assert_eq!(&uid_1, uid_);
                assert_eq!(&StateEnumeration::Active, state_);
            }
            None => todo!(),
        }
        match list.iter().find(|(id, _state)| id == &uid_2) {
            Some((uid_, state_)) => {
                assert_eq!(&uid_2, uid_);
                assert_eq!(&StateEnumeration::Active, state_);
            }
            None => todo!(),
        }

        mysql.delete(&uid_1, owner).await?;
        mysql.delete(&uid_2, owner).await?;

        if mysql
            .retrieve(&uid_1, owner, ObjectOperationTypes::Get)
            .await?
            .is_some()
        {
            kms_bail!("The object 1 should have been deleted");
        }
        if mysql
            .retrieve(&uid_2, owner, ObjectOperationTypes::Get)
            .await?
            .is_some()
        {
            kms_bail!("The object 2 should have been deleted");
        }

        Ok(())
    }

    #[actix_rt::test]
    #[serial(mysql)]
    #[ignore]
    pub async fn test_owner() -> KResult<()> {
        let mysql_url = std::option_env!("KMS_MYSQL_URL")
            .ok_or_else(|| kms_error!("No MySQL database configured"))?;
        let mysql = Sql::instantiate(mysql_url).await?;
        mysql.clean_database().await;

        let owner = "eyJhbGciOiJSUzI1Ni";
        let userid = "foo@example.org";
        let userid2 = "bar@example.org";
        let invalid_owner = "invalid_owner";

        let symmetric_key = create_aes_symmetric_key(None)?;
        let uid = Uuid::new_v4().to_string();

        // test non existent row (with very high probability)
        if mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get)
            .await?
            .is_some()
        {
            kms_bail!("There should be no object");
        }

        mysql
            .upsert(&uid, owner, &symmetric_key, StateEnumeration::Active)
            .await?;

        assert!(mysql.is_object_owned_by(&uid, owner).await?);

        // Retrieve object with valid owner with `Get` operation type - OK

        match mysql
            .retrieve(&uid, owner, ObjectOperationTypes::Get)
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
            .retrieve(&uid, invalid_owner, ObjectOperationTypes::Get)
            .await?
            .is_some()
        {
            kms_bail!("It should not be possible to get this object")
        }

        // Add authorized `userid` to `read_access` table

        mysql
            .insert_access(&uid, userid, ObjectOperationTypes::Get)
            .await?;

        // Retrieve object with authorized `userid` with `Create` operation type - ko

        if mysql
            .retrieve(&uid, userid, ObjectOperationTypes::Create)
            .await
            .is_ok()
        {
            kms_bail!("It should not be possible to get this object with `Create` request")
        }

        // Retrieve object with authorized `userid` with `Get` operation type - OK

        match mysql
            .retrieve(&uid, userid, ObjectOperationTypes::Get)
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
            .insert_access(&uid, userid2, ObjectOperationTypes::Get)
            .await?;

        // Try to add same access again - OK

        mysql
            .insert_access(&uid, userid2, ObjectOperationTypes::Get)
            .await?;

        // Retrieve object with authorized `userid2` with `Create` operation type - ko

        if mysql
            .retrieve(&uid, userid2, ObjectOperationTypes::Create)
            .await
            .is_ok()
        {
            kms_bail!("It should not be possible to get this object with `Create` request")
        }

        // Retrieve object with authorized `userid` with `Get` operation type - OK

        match mysql
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

        match mysql
            .retrieve(&uid, userid, ObjectOperationTypes::Get)
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
            .delete_access(&uid, userid2, ObjectOperationTypes::Get)
            .await?;

        // Retrieve object with `userid2` with `Get` operation type - ko

        if mysql
            .retrieve(&uid, userid2, ObjectOperationTypes::Get)
            .await?
            .is_some()
        {
            kms_bail!("It should not be possible to get this object with `Get` request")
        }

        Ok(())
    }

    #[actix_rt::test]
    #[serial(mysql)]
    #[ignore]
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
            .insert_access(&uid, userid, ObjectOperationTypes::Get)
            .await?;

        let perms = mysql.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        // double insert, expect no duplicate
        mysql
            .insert_access(&uid, userid, ObjectOperationTypes::Get)
            .await?;

        let perms = mysql.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        // insert other operation type
        mysql
            .insert_access(&uid, userid, ObjectOperationTypes::Encrypt)
            .await?;

        let perms = mysql.perms(&uid, userid).await?;
        assert_eq!(
            perms,
            vec![ObjectOperationTypes::Get, ObjectOperationTypes::Encrypt]
        );

        // insert other `userid2`, check it is ok and it didn't change anything for `userid`
        mysql
            .insert_access(&uid, userid2, ObjectOperationTypes::Get)
            .await?;

        let perms = mysql.perms(&uid, userid2).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        let perms = mysql.perms(&uid, userid).await?;
        assert_eq!(
            perms,
            vec![ObjectOperationTypes::Get, ObjectOperationTypes::Encrypt]
        );

        // remove `Get` access for `userid`
        mysql
            .delete_access(&uid, userid, ObjectOperationTypes::Get)
            .await?;

        let perms = mysql.perms(&uid, userid2).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        let perms = mysql.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Encrypt]);

        Ok(())
    }
}
