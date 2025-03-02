use async_trait::async_trait;
use cosmian_kmip::kmip_2_1::kmip_types::Attributes;
use cosmian_kms_interfaces::{AtomicOperation, ObjectsStore};
use sqlx::{Executor, IntoArguments, Row};
use tracing::trace;

use crate::{
    error::{DbResult, DbResultHelper},
    migrate::{DbState, Migrate},
    stores::{sql::SqlDatabase, DBObject},
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
            let db_object: DBObject = serde_json::from_slice(&row.get::<Vec<u8>, _>(1))
                .context("migrate: failed deserializing the object")?;
            let object = db_object.object;
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
        tracing::info!("Migrating from 4.13.0 to 4.22.1");
        Ok(())
    }
}
