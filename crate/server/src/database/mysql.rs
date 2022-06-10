use std::path::PathBuf;

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    kmip_objects::{self, Object},
    kmip_operations::ErrorReason,
    kmip_types::{Attributes, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_utils::types::ObjectOperationTypes;
use mysql::{prelude::*, Opts, OptsBuilder, Pool, Row, SslOpts};
use serde_json::Value;
use tracing::{debug, trace};
use uuid::Uuid;

use super::{query_from_attributes, state_from_string, DBObject, Database, MySqlPlaceholder};
use crate::{
    database::MYSQL_QUERIES,
    error::KmsError,
    kms_bail, kms_error,
    result::{KResult, KResultHelper},
};

/// The MySQL connector is also compatible to connect a MariaDB
/// see: https://mariadb.com/kb/en/mariadb-vs-mysql-compatibility/
pub(crate) struct Sql {
    pool: Pool,
}

impl Sql {
    pub async fn instantiate(connection_url: &str, user_cert: PathBuf) -> KResult<Sql> {
        let client = SslOpts::default();
        let ssl_opts = client
            .with_pkcs12_path(Some(user_cert))
            .with_danger_accept_invalid_certs(true);
        debug!("{ssl_opts:#?}");

        let opts =
            Opts::from_url(connection_url).map_err(|e| KmsError::DatabaseError(e.to_string()))?;
        let builder = OptsBuilder::from_opts(opts).ssl_opts(ssl_opts);

        let pool = Pool::new(builder)?;
        let mut conn = pool.get_conn()?;

        conn.query_drop(
            MYSQL_QUERIES
                .get("create-table-objects")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )?;
        conn.query_drop(
            MYSQL_QUERIES
                .get("create-table-read_access")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )?;
        Ok(Sql { pool })
    }

    #[cfg(test)]
    pub async fn clean_database(&self) {
        let mut conn = self
            .pool
            .get_conn()
            .expect("cannot get connection from pool");

        // Erase `objects` table
        conn.query_drop(
            MYSQL_QUERIES
                .get("clean-table-objects")
                .expect("SQL query can't be found"),
        )
        .expect("cannot truncate objects table");

        // Erase `read_access` table
        conn.query_drop(
            MYSQL_QUERIES
                .get("clean-table-read_access")
                .expect("SQL query can't be found"),
        )
        .expect("cannot truncate read_access table");
    }

    #[cfg(test)]
    pub async fn perms(&self, uid: &str, userid: &str) -> KResult<Vec<ObjectOperationTypes>> {
        fetch_permissions_(uid, userid, &self.pool).await
    }
}

async fn create_(
    uid: Option<String>,
    owner: &str,
    object: &kmip_objects::Object,
    executor: &Pool,
) -> KResult<UniqueIdentifier> {
    let object_json = serde_json::to_value(&DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());

    let mut conn = executor.get_conn()?;
    conn.exec_drop(
        MYSQL_QUERIES
            .get("insert-row-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        (
            uid.clone(),
            object_json,
            StateEnumeration::Active.to_string(),
            owner,
        ),
    )?;
    Ok(uid)
}

async fn retrieve_(
    uid: &str,
    owner_or_userid: &str,
    operation_type: ObjectOperationTypes,
    executor: &Pool,
) -> KResult<Option<(kmip_objects::Object, StateEnumeration)>> {
    let mut conn = executor.get_conn()?;

    let row: Option<Row> = conn.exec_first(
        MYSQL_QUERIES
            .get("select-row-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        (uid, owner_or_userid),
    )?;

    if let Some(row) = row {
        let json = row
            .get::<Value, _>(0)
            .ok_or_else(|| kms_error!("no value in field 0 (object)"))?;
        let db_object: DBObject = serde_json::from_value(json)
            .context("failed deserializing the object")
            .reason(ErrorReason::Internal_Server_Error)?;
        let object = Object::post_fix(db_object.object_type, db_object.object);
        let state = state_from_string(
            &row.get::<String, _>(1)
                .ok_or_else(|| kms_error!("no value in field 1 (state)"))?,
        )?;
        return Ok(Some((object, state)))
    }

    let row: Option<Row> = conn.exec_first(
        MYSQL_QUERIES
            .get("select-row-objects-join-read_access")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        (uid, uid, owner_or_userid),
    )?;

    row.map_or(Ok(None), |row| {
        let perms_raw = row
            .get::<Value, _>(2)
            .ok_or_else(|| kms_error!("no value in field 2 (permissions)"))?;
        let perms: Vec<ObjectOperationTypes> = serde_json::from_value(perms_raw)
            .context("failed deserializing the permissions")
            .reason(ErrorReason::Internal_Server_Error)?;

        // Check this operation is legit to fetch this object
        if perms.into_iter().all(|p| p != operation_type) {
            kms_bail!("No authorization to perform this operation");
        }

        let json = row
            .get::<Value, _>(0)
            .ok_or_else(|| kms_error!("no value in field 0 (object)"))?;
        let db_object: DBObject = serde_json::from_value(json)
            .context("failed deserializing the object")
            .reason(ErrorReason::Internal_Server_Error)?;
        let object = Object::post_fix(db_object.object_type, db_object.object);
        let state = state_from_string(
            &row.get::<String, _>(1)
                .ok_or_else(|| kms_error!("no value in field 1 (state)"))?,
        )?;

        Ok(Some((object, state)))
    })
}

async fn update_object_(
    uid: &str,
    owner: &str,
    object: &kmip_objects::Object,
    executor: &Pool,
) -> KResult<()> {
    let mut conn = executor.get_conn()?;

    let object_json = serde_json::to_value(&DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    conn.exec_drop(
        MYSQL_QUERIES
            .get("update-rows-objects-with-object")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        (object_json, uid, owner),
    )?;
    Ok(())
}

async fn update_state_(
    uid: &str,
    owner: &str,
    state: StateEnumeration,
    executor: &Pool,
) -> KResult<()> {
    let mut conn = executor.get_conn()?;

    conn.exec_drop(
        MYSQL_QUERIES
            .get("update-rows-objects-with-state")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        (state.to_string(), uid, owner),
    )?;
    Ok(())
}

async fn delete_(uid: &str, owner: &str, executor: &Pool) -> KResult<()> {
    let mut conn = executor.get_conn()?;

    conn.exec_drop(
        MYSQL_QUERIES
            .get("delete-rows-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        (uid, owner),
    )?;
    Ok(())
}

async fn upsert_(
    uid: &str,
    owner: &str,
    object: &kmip_objects::Object,
    state: StateEnumeration,
    executor: &Pool,
) -> KResult<()> {
    let mut conn = executor.get_conn()?;

    let object_json = serde_json::to_value(&DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    conn.exec_drop(
        MYSQL_QUERIES
            .get("upsert-row-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        (uid, object_json, state.to_string(), owner, owner, owner),
    )?;
    Ok(())
}

async fn list_shared_objects_(
    user: &str,
    executor: &Pool,
) -> KResult<
    Vec<(
        UniqueIdentifier,
        String,
        StateEnumeration,
        Vec<ObjectOperationTypes>,
    )>,
> {
    let mut conn = executor.get_conn()?;

    let list = conn.exec_iter(
        MYSQL_QUERIES
            .get("select-rows-objects-shared")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        (user,),
    )?;
    let mut ids = Vec::new();
    for row in list {
        let row = row?;
        ids.push((
            row.get::<String, _>(0)
                .ok_or_else(|| kms_error!("no value in field 0 (object_id)"))?,
            row.get::<String, _>(1)
                .ok_or_else(|| kms_error!("no value in field 1 (owner_id)"))?,
            state_from_string(
                &row.get::<String, _>(2)
                    .ok_or_else(|| kms_error!("no value in field 2 (state)"))?,
            )?,
            serde_json::from_value(
                row.get::<Value, _>(3)
                    .ok_or_else(|| kms_error!("no value in field 3 (permissions)"))?,
            )?,
        ));
    }
    Ok(ids)
}

async fn list_accesses_(
    executor: &Pool,
    uid: &str,
) -> KResult<Vec<(String, Vec<ObjectOperationTypes>)>> {
    let mut conn = executor.get_conn()?;

    let list = conn.exec_iter(
        MYSQL_QUERIES
            .get("select-rows-read_access-with-object-id")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        (uid,),
    )?;

    let mut ids = Vec::new();
    for row in list {
        let row = row?;
        ids.push((
            row.get::<String, _>(0)
                .ok_or_else(|| kms_error!("no value in field 0 (user_id)"))?,
            serde_json::from_value(
                row.get::<Value, _>(1)
                    .ok_or_else(|| kms_error!("no value in field 1 (permissions)"))?,
            )?,
        ));
    }
    Ok(ids)
}

async fn fetch_permissions_(
    uid: &str,
    userid: &str,
    executor: &Pool,
) -> KResult<Vec<ObjectOperationTypes>> {
    let mut conn = executor.get_conn()?;

    let row: Option<Row> = conn.exec_first(
        MYSQL_QUERIES
            .get("select-row-read_access")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        (uid, userid),
    )?;

    row.map_or(Ok(vec![]), |row| {
        let perms_raw = row
            .get::<Value, _>(0)
            .ok_or_else(|| kms_error!("no value in field 0 (permissions)"))?;
        let perms: Vec<ObjectOperationTypes> = serde_json::from_value(perms_raw)
            .context("failed deserializing the permissions")
            .reason(ErrorReason::Internal_Server_Error)?;
        Ok(perms)
    })
}

async fn insert_access_(
    uid: &str,
    userid: &str,
    operation_type: ObjectOperationTypes,
    executor: &Pool,
) -> KResult<()> {
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

    let mut conn = executor.get_conn()?;

    // Upsert the DB
    conn.exec_drop(
        MYSQL_QUERIES
            .get("upsert-row-read_access")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        (uid, userid, json),
    )?;
    trace!("Insert read access right in DB: {uid} / {userid}");
    Ok(())
}

async fn delete_access_(
    uid: &str,
    userid: &str,
    operation_type: ObjectOperationTypes,
    executor: &Pool,
) -> KResult<()> {
    let mut conn = executor.get_conn()?;

    // Retrieve existing permissions if any
    let mut perms = fetch_permissions_(uid, userid, executor).await?;
    perms.retain(|p| *p != operation_type);

    // No remaining permissions, delete the row
    if perms.is_empty() {
        conn.exec_drop(
            MYSQL_QUERIES
                .get("delete-rows-read_access")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
            (uid, userid),
        )?;
        return Ok(())
    }

    // Serialize permissions
    let json = serde_json::to_value(&perms)
        .context("failed serializing the permissions to JSON")
        .reason(ErrorReason::Internal_Server_Error)?;

    // Update the DB
    conn.exec_drop(
        MYSQL_QUERIES
            .get("update-rows-read_access-with-permission")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        (json, uid, userid),
    )?;
    trace!("Deleted in DB: {uid} / {userid}");
    Ok(())
}

async fn is_object_owned_by_(uid: &str, owner: &str, executor: &Pool) -> KResult<bool> {
    let mut conn = executor.get_conn()?;

    let row: Option<Row> = conn.exec_first(
        MYSQL_QUERIES
            .get("has-row-objects")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        (uid, owner),
    )?;

    Ok(row.is_some())
}

async fn find_(
    researched_attributes: Option<&Attributes>,
    state: Option<StateEnumeration>,
    owner: &str,
    executor: &Pool,
) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes)>> {
    let query = query_from_attributes::<MySqlPlaceholder>(researched_attributes, state, owner)?;

    let mut conn = executor.get_conn()?;
    let list = conn.exec_iter(&query, ())?;

    let mut uids = Vec::new();
    for row in list {
        let row = row?;
        let uid = row
            .get::<String, _>(0)
            .ok_or_else(|| kms_error!("no value in field 0 (user_id)"))?;
        let state = state_from_string(
            &row.get::<String, _>(1)
                .ok_or_else(|| kms_error!("no value in field 1 (state)"))?,
        )?;
        let value = row
            .get::<Value, _>(2)
            .ok_or_else(|| kms_error!("no value in field 2 (attributes)"))?;
        let attrs: Attributes = serde_json::from_value(value)
            .context("failed deserializing attributes")
            .map_err(|e| KmsError::DatabaseError(e.to_string()))?;

        uids.push((uid, state, attrs));
    }

    Ok(uids)
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
        let mut res = vec![];
        // let mut tx = self.pool.begin().await?;
        for (uid, object) in objects {
            match create_(uid.to_owned(), owner, object, &self.pool).await {
                Ok(uid) => res.push(uid),
                Err(e) => {
                    // tx.rollback().await.context("transaction failed")?;
                    kms_bail!("creation of objects failed: {}", e);
                }
            };
        }
        // tx.commit().await?;
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

    async fn list_shared_objects(
        &self,
        owner: &str,
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

    async fn list_accesses(&self, uid: &str) -> KResult<Vec<(String, Vec<ObjectOperationTypes>)>> {
        list_accesses_(&self.pool, uid).await
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

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        owner: &str,
    ) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes)>> {
        find_(researched_attributes, state, owner, &self.pool).await
    }
}

// Run these tests using: `cargo make rust-tests`
#[cfg(test)]
mod tests {
    use cosmian_kmip::kmip::{
        kmip_objects::ObjectType,
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, Link,
            LinkType, LinkedObjectIdentifier, StateEnumeration,
        },
    };
    use cosmian_kms_utils::{crypto::aes::create_aes_symmetric_key, types::ObjectOperationTypes};
    use serial_test::serial;
    use uuid::Uuid;

    use super::Sql;
    use crate::{database::Database, kms_bail, result::KResult};

    #[actix_rt::test]
    #[serial(mysql)]
    pub async fn test_crud() -> KResult<()> {
        let mysql_url = std::option_env!("KMS_MYSQL_URL").expect("No MySQL database configured");
        let user_cert = std::option_env!("KMS_USER_CERT_PATH").expect("No user cert configured");
        let mysql = Sql::instantiate(mysql_url, std::path::PathBuf::from(user_cert)).await?;
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

        let mut attributes = symmetric_key.attributes_mut()?;
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
                    obj_.attributes()?.link[0].linked_object_identifier,
                    LinkedObjectIdentifier::TextString("foo".to_string())
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
    pub async fn test_upsert() -> KResult<()> {
        let mysql_url = std::option_env!("KMS_MYSQL_URL").expect("No MySQL database configured");
        let user_cert = std::option_env!("KMS_USER_CERT_PATH").expect("No user cert configured");
        let mysql = Sql::instantiate(mysql_url, std::path::PathBuf::from(user_cert)).await?;
        mysql.clean_database().await;

        let owner = "eyJhbGciOiJSUzI1Ni";

        // Create key

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

        let mut attributes = symmetric_key.attributes_mut()?;
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
                    obj_.attributes()?.link[0].linked_object_identifier,
                    LinkedObjectIdentifier::TextString("foo".to_string())
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
    pub async fn test_tx_and_list() -> KResult<()> {
        let mysql_url = std::option_env!("KMS_MYSQL_URL").expect("No MySQL database configured");
        let user_cert = std::option_env!("KMS_USER_CERT_PATH").expect("No user cert configured");
        let mysql = Sql::instantiate(mysql_url, std::path::PathBuf::from(user_cert)).await?;
        mysql.clean_database().await;

        let owner = "eyJhbGciOiJSUzI1Ni";

        // Create key

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

        let list = mysql.find(None, None, owner).await?;
        match list.iter().find(|(id, _state, _attrs)| id == &uid_1) {
            Some((uid_, state_, _attrs)) => {
                assert_eq!(&uid_1, uid_);
                assert_eq!(&StateEnumeration::Active, state_);
            }
            None => todo!(),
        }
        match list.iter().find(|(id, _state, _attrs)| id == &uid_2) {
            Some((uid_, state_, _attrs)) => {
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
    pub async fn test_owner() -> KResult<()> {
        let mysql_url = std::option_env!("KMS_MYSQL_URL").expect("No MySQL database configured");
        let user_cert = std::option_env!("KMS_USER_CERT_PATH").expect("No user cert configured");
        let mysql = Sql::instantiate(mysql_url, std::path::PathBuf::from(user_cert)).await?;
        mysql.clean_database().await;

        let owner = "eyJhbGciOiJSUzI1Ni";
        let userid = "foo@example.org";
        let userid2 = "bar@example.org";
        let invalid_owner = "invalid_owner";

        // Create key

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

        let objects = mysql.find(None, None, owner).await?;
        assert_eq!(objects.len(), 1);
        let (o_uid, o_state, _) = &objects[0];
        assert_eq!(o_uid, &uid);
        assert_eq!(o_state, &StateEnumeration::Active);

        let objects = mysql.find(None, None, userid2).await?;
        assert!(objects.is_empty());

        let objects = mysql.list_shared_objects(userid2).await?;
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
    pub async fn test_permissions() -> KResult<()> {
        let userid = "foo@example.org";
        let userid2 = "bar@example.org";
        let mysql_url = std::option_env!("KMS_MYSQL_URL").expect("No MySQL database configured");
        let user_cert = std::option_env!("KMS_USER_CERT_PATH").expect("No user cert configured");
        let mysql = Sql::instantiate(mysql_url, std::path::PathBuf::from(user_cert)).await?;
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

        let accesses = mysql.list_accesses(&uid).await?;
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
            .delete_access(&uid, userid, ObjectOperationTypes::Get)
            .await?;

        let perms = mysql.perms(&uid, userid2).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Get]);

        let perms = mysql.perms(&uid, userid).await?;
        assert_eq!(perms, vec![ObjectOperationTypes::Encrypt]);

        Ok(())
    }

    #[actix_rt::test]
    #[serial(mysql)]
    // MySQL part is tested on an EdgelessDB, which doesn't currently support JSON, so this test can't pass.
    #[ignore]
    pub async fn test_json_access() -> KResult<()> {
        let mysql_url = std::option_env!("KMS_MYSQL_URL").expect("No MySQL database configured");
        let user_cert = std::option_env!("KMS_USER_CERT_PATH").expect("No user cert configured");
        let db = Sql::instantiate(mysql_url, std::path::PathBuf::from(user_cert)).await?;
        db.clean_database().await;

        let owner = "eyJhbGciOiJSUzI1Ni";

        // Create key

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
            )
            .await?;
        assert!(found.is_empty());

        Ok(())
    }
}
