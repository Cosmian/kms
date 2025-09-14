use async_trait::async_trait;
use cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes,
    kmip_data_structures::KeyMaterial,
    kmip_objects::{
        Certificate, Object, OpaqueObject, PrivateKey, PublicKey, SecretData, SymmetricKey,
    },
    kmip_types::KeyFormatType,
};
use cosmian_kms_interfaces::ObjectsStore;
use cosmian_logger::{debug, error, info, trace};
use serde_json::Value;
use sqlx::{Executor, IntoArguments, Row};

use crate::{
    DbError,
    error::{DbResult, DbResultHelper},
    stores::{
        migrate::{DbState, Migrate},
        sql::{database::SqlDatabase, migrations::key_material_old::KeyMaterial421},
    },
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
    for<'w, 'z> sqlx::types::Json<&'w Value>: sqlx::Encode<'z, DB>,
    for<'z> sqlx::types::Json<Value>: sqlx::Decode<'z, DB> + sqlx::Type<DB>,
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
        sqlx::query(self.get_query("select-parameter")?)
            .bind("db_version")
            .fetch_optional(self.get_pool())
            .await
            .map_err(DbError::from)?
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

        // Add the column attributes to the objects' table
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

        // Fill the `attributes` column with the object attributes
        let uids = sqlx::query("SELECT id FROM objects")
            .fetch_all(self.get_pool())
            .await?
            .into_iter()
            .map(|row| row.get::<String, _>(0))
            .collect::<Vec<String>>();
        trace!("uids={}", uids.len());

        let select_query = format!(
            "SELECT object FROM objects WHERE id = {binder}",
            binder = self.binder(1)
        );
        let update_query = self.get_query("update-object-with-object")?;
        for uid in &uids {
            trace!("migrating object with id={uid}");
            let op_fut = async {
                let row = sqlx::query(select_query.as_str())
                    .bind(uid)
                    .fetch_one(self.get_pool())
                    .await?;

                // Before 4.22.1, serialization to JSON was done with the `DBObject` struct
                let db_object: Value = serde_json::from_slice(&row.get::<Vec<u8>, _>(0))
                    .context("migrate_from_4_12_0_to_4_13_0 failed deserializing the object")?;
                let object = db_object_to_object(&db_object)?;
                let object_json = serde_json::to_value(&object).context(
                    "migrate_from_4_12_0_to_4_13_0 failed: failed to serialize the object",
                )?;
                trace!(
                    "migrate_from_4_12_0_to_4_13_0: object (type: {})={:?}",
                    object.object_type(),
                    uid
                );
                let mut attributes = match object.attributes() {
                    Ok(attrs) => attrs.clone(),
                    Err(_error) => {
                        // For example, a Certificate object has no KMIP-attribute
                        Attributes::default()
                    }
                };
                attributes.set_object_type(object.object_type());
                trace!("attributes={}", attributes);
                let attributes_json = serde_json::to_value(&attributes).context(
                    "migrate_from_4_12_0_to_4_13_0: failed serializing the attributes to JSON",
                )?;
                // Update the object and attributes in the database
                sqlx::query(update_query)
                    .bind(object_json)
                    .bind(attributes_json)
                    .bind(uid.to_owned())
                    .execute(self.get_pool())
                    .await?;
                Ok::<_, DbError>(())
            };
            if let Err(e) = op_fut.await {
                error!("migrate_from_4_12_0_to_4_13_0: failed migrating {uid}: {e}");
            }
        }
        info!(
            "Migration from 4.12.0 to 4.13.0 completed: {} objects migrated",
            uids.len()
        );
        Ok(())
    }

    async fn migrate_to_4_22_2(&self) -> DbResult<()> {
        debug!("Migrating to 4.22.1+");

        let uids = sqlx::query("SELECT id FROM objects")
            .fetch_all(self.get_pool())
            .await?
            .into_iter()
            .map(|row| row.get::<String, _>(0))
            .collect::<Vec<String>>();

        let select_query = format!(
            "SELECT object, attributes FROM objects WHERE id = {binder}",
            binder = self.binder(1)
        );
        let update_query = self.get_query("update-object-with-object")?;
        for uid in &uids {
            trace!("migrate to 4_22_1+: migrating object with id={uid}");
            let op_fut = async {
                let row = sqlx::query(select_query.as_str())
                    .bind(uid)
                    .fetch_one(self.get_pool())
                    .await?;
                // Migrate DBObject --> Object
                let db_object_json = row.get::<Value, _>(0);
                if let Ok(_e) = serde_json::from_value::<Object>(db_object_json.clone()) {
                    // already migrated
                    return Ok::<_, DbError>(());
                }
                let db_object_value: Value = serde_json::from_value(db_object_json)
                    .context("failed deserializing the object")?;

                let object = db_object_to_object(&db_object_value)?;

                let object_json = serde_json::to_value(&object)
                    .context("migration to 4.22.1+ failed: failed to serialize the object")?;
                // Migrate Attributes --> Attributes
                let attributes_json = row.get::<Value, usize>(1);
                let mut attributes: Attributes = serde_json::from_value(attributes_json)
                    .context("migration to 4.22.1+ failed: failed to deserialize the attributes")?;
                // update an issue that ObjectType is not always correctly set (e.g., certificates)
                attributes.object_type = Some(object.object_type());
                let attributes_json = serde_json::to_value(attributes)
                    .context("migration to 4.22.1+ failed: serializing the attributes to JSON")?;
                // Update the object and attributes in the database
                sqlx::query(update_query)
                    .bind(object_json)
                    .bind(attributes_json)
                    .bind(uid.to_owned())
                    .execute(self.get_pool())
                    .await?;
                Ok::<_, DbError>(())
            };
            if let Err(e) = op_fut.await {
                error!("migration to 4.22.1+ failed migrating {uid}: {e}");
            }
        }
        info!(
            "Migration to 4.22.1+ completed: {} objects migrated",
            uids.len()
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
#[allow(dead_code)]
fn db_object_to_object(db_object: &Value) -> DbResult<Object> {
    let object_type = db_object["object_type"].as_str().ok_or_else(|| {
        DbError::DatabaseError(format!(
            "migration to 4.22.1+ failed: object_type not found in object: {db_object:?}",
        ))
    })?;
    let mut content = db_object["object"].clone();
    // make sure we can actually deserialize and re-serialize the objects
    Ok(match object_type {
        "PrivateKey" => {
            migrate_key_material(&mut content)?;
            let obj = serde_json::from_value::<PrivateKey>(content).map_err(|e| {
                DbError::DatabaseError(format!(
                    "migration to 4.22.1+ failed: failed to deserialize PrivateKey: {e}"
                ))
            })?;
            Object::PrivateKey(obj)
        }
        "PublicKey" => {
            migrate_key_material(&mut content)?;
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

/// Migrate the `KeyMaterial` which used `BigUint` to `KeyMaterial` which uses `BigInt`
#[allow(dead_code)]
fn migrate_key_material(content: &mut Value) -> Result<(), DbError> {
    let key_format_type =
        KeyFormatType::try_from(content["KeyBlock"]["KeyFormatType"].as_str().ok_or_else(
            || {
                DbError::DatabaseError(format!(
                    "migration to 4.22.1+ failed: KeyFormatType not found in object: {content:?}",
                ))
            },
        )?)
        .map_err(|e| {
            DbError::DatabaseError(format!(
                "migration to 4.22.1+ failed: Unknown KeyFormatType not found in object: {e}"
            ))
        })?;
    let key_material_value = &content["KeyBlock"]["KeyValue"]["KeyMaterial"];
    let key_material_4_21: KeyMaterial421 = serde_json::from_value(key_material_value.clone())
        .map_err(|e| {
            DbError::DatabaseError(format!(
                "migration to 4.22.1+ failed: failed to deserialize KeyMaterial 4.21: {e}"
            ))
        })?;
    let key_material: KeyMaterial = key_material_4_21.into();
    content["KeyBlock"]["KeyValue"]["KeyMaterial"] =
        key_material.to_json_value(key_format_type).map_err(|e| {
            DbError::DatabaseError(format!(
                "migration to 4.22.1+ failed: failed to replace KeyMaterial: {e}"
            ))
        })?;
    Ok(())
}
