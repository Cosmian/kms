use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    str::FromStr,
};

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::ErrorReason,
    kmip_types::{Attributes, StateEnumeration},
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, IsWrapped, ObjectOperationType};
use serde_json::Value;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgRow},
    ConnectOptions, Executor, Pool, Postgres, Row, Transaction,
};
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{
    database::{
        database_trait::AtomicOperation, object_with_metadata::ObjectWithMetadata,
        query_from_attributes, state_from_string, DBObject, Database, PgSqlPlaceholder,
        PGSQL_QUERIES,
    },
    error::KmsError,
    kms_bail, kms_error,
    result::{KResult, KResultHelper},
};

pub struct PgPool {
    pool: Pool<Postgres>,
}

impl PgPool {
    /// Instantiate a new `Postgres` database
    /// and create the appropriate table(s) if need be
    pub async fn instantiate(connection_url: &str, clear_database: bool) -> KResult<Self> {
        let options = PgConnectOptions::from_str(connection_url)?
            // disable logging of each query
            .disable_statement_logging();

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        sqlx::query(
            PGSQL_QUERIES
                .get("create-table-objects")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            PGSQL_QUERIES
                .get("create-table-read_access")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            PGSQL_QUERIES
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

#[async_trait(?Send)]
impl Database for PgPool {
    fn filename(&self, _group_id: u128) -> Option<PathBuf> {
        None
    }

    async fn create(
        &self,
        uid: Option<String>,
        user: &str,
        object: &Object,
        tags: &HashSet<String>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<String> {
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
        objects: Vec<(Option<String>, Object, &HashSet<String>)>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<String>> {
        let mut res = vec![];
        let mut tx = self.pool.begin().await?;
        for (uid, object, tags) in objects {
            match create_(uid.clone(), user, &object, tags, &mut tx).await {
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
    ) -> KResult<HashMap<String, ObjectWithMetadata>> {
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
        object: &Object,
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
        tags: Option<&HashSet<String>>,
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
        userid: &str,
        operation_types: HashSet<ObjectOperationType>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        insert_access_(uid, userid, operation_types, &self.pool).await
    }

    async fn remove_access(
        &self,
        uid: &str,
        userid: &str,
        operation_types: HashSet<ObjectOperationType>,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        remove_access_(uid, userid, operation_types, &self.pool).await
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
        userid: &str,
        no_inherited_access: bool,
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<HashSet<ObjectOperationType>> {
        list_user_access_rights_on_object_(uid, userid, no_inherited_access, &self.pool).await
    }

    async fn atomic(
        &self,
        owner: &str,
        operations: &[AtomicOperation],
        _params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let mut tx = self.pool.begin().await?;
        match atomic_(owner, operations, &mut tx).await {
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
    tags: &HashSet<String>,
    executor: &mut Transaction<'_, Postgres>,
) -> KResult<String> {
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    // If the uid is not provided, generate a new one
    let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());

    sqlx::query(
        PGSQL_QUERIES
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
            PGSQL_QUERIES
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
) -> KResult<HashMap<String, ObjectWithMetadata>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let rows: Vec<PgRow> = if !uid_or_tags.starts_with('[') {
        sqlx::query(
            PGSQL_QUERIES
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
        let raw_sql = PGSQL_QUERIES
            .get("select-from-tags")
            .context("SQL query can't be found")?
            .replace("@TAGS", &tags_params)
            .replace("@LEN", &format!("${}", tags.len() + 1))
            .replace("@USER", &format!("${}", tags.len() + 2));

        // Bind the tags params
        let mut query = sqlx::query::<Postgres>(&raw_sql);
        for tag in &tags {
            query = query.bind(tag);
        }
        // Bind the tags len and the user
        query = query.bind(tags.len() as i16).bind(user);

        // Execute the query
        query.fetch_all(executor).await?
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
    let rows: Vec<PgRow> = sqlx::query(
        PGSQL_QUERIES
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
    object: &Object,
    tags: Option<&HashSet<String>>,
    executor: &mut Transaction<'_, Postgres>,
) -> KResult<()> {
    let object_json = serde_json::to_value(DBObject {
        object_type: object.object_type(),
        object: object.clone(),
    })
    .context("failed serializing the object to JSON")
    .reason(ErrorReason::Internal_Server_Error)?;

    sqlx::query(
        PGSQL_QUERIES
            .get("update-object-with-object")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(object_json)
    .bind(uid)
    .execute(&mut **executor)
    .await?;

    // delete the existing tags
    sqlx::query(
        PGSQL_QUERIES
            .get("delete-tags")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .execute(&mut **executor)
    .await?;

    // Insert the new tags
    if let Some(tags) = tags {
        for tag in tags {
            sqlx::query(
                PGSQL_QUERIES
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

pub(crate) async fn update_state_(
    uid: &str,
    state: StateEnumeration,
    executor: &mut Transaction<'_, Postgres>,
) -> KResult<()> {
    sqlx::query(
        PGSQL_QUERIES
            .get("update-object-with-state")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
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
    sqlx::query(
        PGSQL_QUERIES
            .get("delete-object")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(owner)
    .execute(&mut **executor)
    .await?;

    // delete the tags
    sqlx::query(
        PGSQL_QUERIES
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
    object: &Object,
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

    sqlx::query(
        PGSQL_QUERIES
            .get("upsert-object")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
    .bind(uid)
    .bind(object_json)
    .bind(state.to_string())
    .bind(owner)
    .execute(&mut **executor)
    .await?;

    // Insert the new tags if present
    if let Some(tags) = tags {
        // delete the existing tags
        sqlx::query(
            PGSQL_QUERIES
                .get("delete-tags")
                .ok_or_else(|| kms_error!("SQL query can't be found"))?,
        )
        .bind(uid)
        .execute(&mut **executor)
        .await?;
        // insert the new ones
        for tag in tags {
            sqlx::query(
                PGSQL_QUERIES
                    .get("insert-tags")
                    .ok_or_else(|| kms_error!("SQL query can't be found"))?,
            )
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

    let list = sqlx::query(
        PGSQL_QUERIES
            .get("select-rows-read_access-with-object-id")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
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
    let list = sqlx::query(
        PGSQL_QUERIES
            .get("select-objects-access-obtained")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
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
    let row: Option<PgRow> = sqlx::query(
        PGSQL_QUERIES
            .get("select-user-accesses-for-object")
            .ok_or_else(|| kms_error!("SQL query can't be found"))?,
    )
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
    sqlx::query(
        PGSQL_QUERIES
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
        .cloned()
        .collect::<HashSet<_>>();

    // No remaining permissions, delete the row
    if perms.is_empty() {
        sqlx::query(
            PGSQL_QUERIES
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
        PGSQL_QUERIES
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
    E: Executor<'e, Database = Postgres> + Copy,
{
    let row: Option<PgRow> = sqlx::query(
        PGSQL_QUERIES
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
) -> KResult<Vec<(String, StateEnumeration, Attributes, IsWrapped)>>
where
    E: Executor<'e, Database = Postgres> + Copy,
{
    let query = query_from_attributes::<PgSqlPlaceholder>(
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
    rows: &[PgRow],
) -> KResult<Vec<(String, StateEnumeration, Attributes, IsWrapped)>> {
    let mut uids = Vec::with_capacity(rows.len());
    for row in rows {
        let attrs: Attributes = match row.try_get::<Value, _>(2) {
            Err(_) => return Err(KmsError::DatabaseError("no attributes found".to_string())),
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
    // Erase `objects` table
    sqlx::query(
        PGSQL_QUERIES
            .get("clean-table-objects")
            .expect("SQL query can't be found"),
    )
    .execute(executor)
    .await?;
    // Erase `read_access` table
    sqlx::query(
        PGSQL_QUERIES
            .get("clean-table-read_access")
            .expect("SQL query can't be found"),
    )
    .execute(executor)
    .await?;
    // Erase `tags` table
    sqlx::query(
        PGSQL_QUERIES
            .get("clean-table-tags")
            .expect("SQL query can't be found"),
    )
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
            AtomicOperation::Create((uid, object, tags)) => {
                if let Err(e) = create_(Some(uid.clone()), owner, object, tags, tx).await {
                    kms_bail!("creation of object {uid} failed: {e}");
                }
            }
            AtomicOperation::UpdateObject((uid, object, tags)) => {
                if let Err(e) = update_object_(uid, object, tags.as_ref(), tx).await {
                    kms_bail!("update of object {uid} failed: {e}");
                }
            }
            AtomicOperation::UpdateState((uid, state)) => {
                if let Err(e) = update_state_(uid, *state, tx).await {
                    kms_bail!("update of the state of object {uid} failed: {e}");
                }
            }
            AtomicOperation::Upsert((uid, object, tags, state)) => {
                if let Err(e) = upsert_(uid, owner, object, tags.as_ref(), *state, tx).await {
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
