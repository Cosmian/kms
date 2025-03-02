use async_trait::async_trait;
use cosmian_kmip::kmip_2_1::{
    kmip_objects::{
        Certificate, Object, OpaqueObject, PrivateKey, PublicKey, SecretData, SymmetricKey,
    },
    kmip_types::Attributes,
};
use cosmian_kms_interfaces::{AtomicOperation, ObjectsStore};
use serde_json::Value;
use sqlx::{Executor, IntoArguments, Row};
use tracing::{info, trace};

use crate::{
    error::{DbResult, DbResultHelper},
    migrate::{DbState, Migrate},
    stores::sql::SqlDatabase,
    DbError,
};

#[async_trait(?Send)]
impl<T, DB> Migrate<DB> for T
where
    T: SqlDatabase<DB> + ObjectsStore,
    DB: sqlx::Database,
    for<'z> &'z mut DB::Connection: Executor<'z, Database = DB>,
    for<'z> DB::Arguments<'z>: IntoArguments<'z, DB>,
    for<'z> i16: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> String: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> &'z str: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> Vec<u8>: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'w, 'z> sqlx::types::Json<&'w serde_json::Value>: sqlx::Encode<'z, DB>,
    sqlx::types::Json<serde_json::Value>: sqlx::Type<DB>,
    usize: sqlx::ColumnIndex<<DB as sqlx::Database>::Row>,
{
    async fn get_db_state(&self) -> DbResult<Option<DbState>> {
        match sqlx::query(self.get_query("select-parameter")?)
            .bind("db_state")
            .fetch_optional(self.get_pool())
            .await
            .map_err(DbError::from)?
        {
            None => {
                trace!("No state found, old KMS version database");
                Ok(None)
            }
            Some(row) => {
                let json = row.get::<String, _>(0);
                Ok(Some(
                    serde_json::from_str(&json).context("failed deserializing the DB state")?,
                ))
            }
        }
    }

    async fn set_db_state(&self, state: DbState) -> DbResult<()> {
        sqlx::query(self.get_query("upsert-parameter")?)
            .bind("db_state")
            .bind(serde_json::to_string(&state).context("failed serializing the DB state")?)
            .execute(self.get_pool())
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn get_current_db_version(&self) -> DbResult<Option<String>> {
        (sqlx::query(self.get_query("select-parameter")?)
            .bind("db_version")
            .fetch_optional(self.get_pool())
            .await
            .map_err(DbError::from)?)
        .map_or_else(
            || {
                trace!("No current DB version, old KMS version database");
                Ok(None)
            },
            |row| Ok(Some(row.get::<String, _>(0))),
        )
    }

    async fn set_current_db_version(&self, version: &str) -> DbResult<()> {
        sqlx::query(self.get_query("upsert-parameter")?)
            .bind("db_version")
            .bind(version)
            .execute(self.get_pool())
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn migrate_from_4_12_0_to_4_13_0(&self) -> DbResult<()> {
        trace!("Migrating from 4.12.0 to 4.13.0");

        // Add the column attributes to the objects table
        if sqlx::query("SELECT attributes from objects")
            .execute(self.get_pool())
            .await
            .is_ok()
        {
            trace!("Column attributes already exists, nothing to do");
            return Ok(());
        }

        trace!("Column attributes does not exist, adding it");
        sqlx::query(self.get_query("add-column-attributes")?)
            .execute(self.get_pool())
            .await
            .map_err(DbError::from)?;

        // Select all objects and extract the KMIP attributes to be stored in the new column
        let rows = sqlx::query("SELECT * FROM objects")
            .fetch_all(self.get_pool())
            .await
            .map_err(DbError::from)?;

        let mut operations = Vec::with_capacity(rows.len());
        for row in rows {
            let uid = row.get::<String, _>(0);
            // Before 4.22.1, serialization to JSON was done with the `DBObject` struct
            let db_object: Value = serde_json::from_slice(&row.get::<Vec<u8>, _>(1))
                .context("migrate: failed deserializing the object")?;
            let object = db_object_to_object(&db_object)?;
            trace!(
                "migrate_from_4_12_0_to_4_13_0: object (type: {})={:?}",
                object.object_type(),
                uid
            );
            let attributes = match object.attributes() {
                Ok(attrs) => attrs.clone(),
                Err(_error) => {
                    // For example, a Certificate object has no KMIP-attribute
                    Attributes::default()
                }
            };
            let tags = self.retrieve_tags(&uid, None).await?;
            operations.push(AtomicOperation::UpdateObject((
                uid,
                object,
                attributes,
                Some(tags),
            )));
        }

        self.atomic("this user is not used to update objects", &operations, None)
            .await?;
        Ok(())
    }

    async fn migrate_from_4_13_0_to_4_22_1(&self) -> DbResult<()> {
        tracing::debug!("Migrating from 4.13.0 to 4.22.1");

        let ids = sqlx::query("SELECT id FROM objects")
            .fetch_all(self.get_pool())
            .await?
            .into_iter()
            .map(|row| row.get::<String, _>(0))
            .collect::<Vec<String>>();

        let mut tx =
            self.get_pool().begin().await.map_err(|e| {
                DbError::DatabaseError(format!("failed to start a transaction: {e}"))
            })?;

        let tx_future = async {
            let select_query = format!(
                "SELECT object FROM objects WHERE id = {binder}",
                binder = self.binder(1)
            );
            let update_query = format!(
                "UPDATE objects SET object = {binder1} WHERE id = {binder2}",
                binder1 = self.binder(1),
                binder2 = self.binder(2)
            );
            for id in &ids {
                trace!("migrate_from_4_13_0_to_4_22_1: migrating object with id={id}");
                let json_string = sqlx::query(select_query.as_str())
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await?
                    .get::<String, usize>(0);
                let value: Value = serde_json::from_str(&json_string)
                    .context("failed deserializing the object")?;
                let object_string = serde_json::to_string(&db_object_to_object(&value)?)
                    .context("migration to 4.22.1+ failed: failed to serialize the object")?;
                sqlx::query(update_query.as_str())
                    .bind(&object_string)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
            }
            Ok::<(), DbError>(())
        };

        if let Err(e) = tx_future.await {
            tx.rollback()
                .await
                .context("migration to 4.22.1+ failed:: transaction failed")?;
            return Err(DbError::DatabaseError(format!("{e}")));
        }

        tx.commit().await.map_err(|e| {
            DbError::DatabaseError(format!(
                "migration to 4.22.1+ failed: failed to commit the transaction: {e}"
            ))
        })?;

        info!(
            "Migration from 4.13.0 to 4.22.1 completed: {} objects migrated",
            ids.len()
        );
        Ok(())
    }
}

/// This object was used to serialize the objects in the database
/// before 4.22.1+
/// ```Rust
/// #[derive(Clone)]
/// #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
/// pub(crate) struct DBObject {
///     pub(crate) object_type: ObjectType,
///     pub(crate) object: Object,
/// }
/// ```
fn db_object_to_object(db_object: &Value) -> DbResult<Object> {
    let object_type = db_object["object_type"].as_str().ok_or_else(|| {
        DbError::DatabaseError(format!(
            "migration to 4.22.1+ failed: object_type not found in object: {db_object:?}",
        ))
    })?;
    let content = db_object["object"].clone();
    // make sure we can actually deserialize and re-serialize the objects
    Ok(match object_type {
        "PrivateKey" => {
            let obj = serde_json::from_value::<PrivateKey>(content).map_err(|e| {
                DbError::DatabaseError(format!(
                    "migration to 4.22.1+ failed: failed to deserialize PrivateKey: {e}"
                ))
            })?;
            Object::PrivateKey(obj)
        }
        "PublicKey" => {
            let obj = serde_json::from_value::<PublicKey>(content).map_err(|e| {
                DbError::DatabaseError(format!(
                    "migration to 4.22.1+ failed: failed to deserialize PublicKey: {e}"
                ))
            })?;
            Object::PublicKey(obj)
        }
        "Certificate" => {
            let obj = serde_json::from_value::<Certificate>(content).map_err(|e| {
                DbError::DatabaseError(format!(
                    "migration to 4.22.1+ failed: failed to deserialize Certificate: {e}"
                ))
            })?;
            Object::Certificate(obj)
        }
        "SymmetricKey" => {
            let obj = serde_json::from_value::<SymmetricKey>(content).map_err(|e| {
                DbError::DatabaseError(format!(
                    "migration to 4.22.1+ failed: failed to deserialize SymmetricKey: {e}"
                ))
            })?;
            Object::SymmetricKey(obj)
        }
        "SecretData" => {
            let obj = serde_json::from_value::<SecretData>(content).map_err(|e| {
                DbError::DatabaseError(format!(
                    "migration to 4.22.1+ failed: failed to deserialize SecretData: {e}"
                ))
            })?;
            Object::SecretData(obj)
        }
        "OpaqueObject" => {
            let obj = serde_json::from_value::<OpaqueObject>(content).map_err(|e| {
                DbError::DatabaseError(format!(
                    "migration to 4.22.1+ failed: failed to deserialize OpaqueObject: {e}"
                ))
            })?;
            Object::OpaqueObject(obj)
        }
        x => {
            return Err(DbError::DatabaseError(format!(
                "migration to 4.22.1+ failed: unknown object type: {x}"
            )));
        }
    })
}
