use std::sync::Arc;

use cosmian_kms_interfaces::{
    DbState, InterfaceError, InterfaceResult, Migrate, ObjectWithMetadata,
};
use rawsql::Loader;
use sqlx::{Executor, IntoArguments, Pool, Transaction};

use crate::{
    error::{DbResult, DbResultHelper},
    stores::sql::database::{get_query, SqlDatabase},
    DbError,
};

pub struct SqlMainStore<DB>
where
    DB: sqlx::Database,
    for<'z> &'z mut DB::Connection: Executor<'z, Database = DB>,
    for<'z> DB::Arguments<'z>: IntoArguments<'z, DB>,
    for<'z> i16: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> String: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> &'z str: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'w, 'z> sqlx::types::Json<&'w serde_json::Value>: sqlx::Encode<'z, DB>,
    sqlx::types::Json<serde_json::Value>: sqlx::Type<DB>,
    usize: sqlx::ColumnIndex<<DB as sqlx::Database>::Row>,
{
    sql_database: Arc<dyn SqlDatabase<DB> + Send + Sync>,
}

impl<DB> SqlDatabase<DB> for SqlMainStore<DB>
where
    DB: sqlx::Database,
    for<'z> &'z mut DB::Connection: Executor<'z, Database = DB>,
    for<'z> DB::Arguments<'z>: IntoArguments<'z, DB>,
    for<'z> i16: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> String: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> &'z str: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'w, 'z> sqlx::types::Json<&'w serde_json::Value>: sqlx::Encode<'z, DB>,
    sqlx::types::Json<serde_json::Value>: sqlx::Type<DB>,
    usize: sqlx::ColumnIndex<<DB as sqlx::Database>::Row>,
{
    fn get_pool(&self) -> &Pool<DB> {
        self.sql_database.get_pool()
    }

    fn get_loader(&self) -> &Loader {
        self.sql_database.get_loader()
    }

    fn db_row_to_owm(&self, row: &DB::Row) -> DbResult<ObjectWithMetadata> {
        self.sql_database.db_row_to_owm(row)
    }
}

impl<DB> SqlMainStore<DB>
where
    DB: sqlx::Database,
    for<'z> &'z mut DB::Connection: Executor<'z, Database = DB>,
    for<'z> DB::Arguments<'z>: IntoArguments<'z, DB>,
    for<'z> i16: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> String: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> &'z str: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'w, 'z> sqlx::types::Json<&'w serde_json::Value>: sqlx::Encode<'z, DB>,
    sqlx::types::Json<serde_json::Value>: sqlx::Type<DB>,
    usize: sqlx::ColumnIndex<<DB as sqlx::Database>::Row>,
{
    pub fn new(sql_database: Arc<dyn SqlDatabase<DB> + Send + Sync>) -> Self {
        Self { sql_database }
    }

    /// Start the store, creating the tables if they don't exist
    /// and performing the migration if necessary
    /// # Arguments
    /// * `clear_database` - if `true`, the database will be cleared
    /// # Errors
    /// If the store can't be instantiated
    pub async fn start(&self, clear_database: bool) -> InterfaceResult<()> {
        let is_new_instance = self.setup_database().await?;
        if is_new_instance {
            self.set_current_db_version(env!("CARGO_PKG_VERSION"))
                .await?;
            self.set_db_state(DbState::Ready).await?;
        } else {
            self.migrate().await?;
        }
        if clear_database {
            self.clear_database().await?;
        }
        Ok(())
    }

    /// Set up the database creating the tables if they don't exist
    /// # Returns
    /// `true` if the database is a new instance, `false` otherwise
    /// # Errors
    /// If the tables can't be created
    async fn setup_database(&self) -> InterfaceResult<bool> {
        let is_new_instance = sqlx::query("SELECT * FROM objects LIMIT 1")
            .fetch_optional(self.get_pool())
            .await
            .is_err();

        let mut tx = self
            .get_pool()
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to start a transaction: {e}")))?;

        match create_tables(self.get_loader(), &mut tx).await {
            Ok(()) => {
                tx.commit().await.map_err(|e| {
                    InterfaceError::Db(format!("failed to commit the transaction: {e}"))
                })?;
                Ok(is_new_instance)
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                Err(InterfaceError::Db(format!("{e}")))
            }
        }
    }

    /// Clear the database, namely the `objects`, `read_access` and `tags` tables
    /// # Errors
    /// If the database can't be cleared
    async fn clear_database(&self) -> DbResult<()> {
        // Erase `objects` table
        sqlx::query(self.get_query("clean-table-objects")?)
            .execute(self.get_pool())
            .await?;
        // Erase `read_access` table
        sqlx::query(self.get_query("clean-table-read_access")?)
            .execute(self.get_pool())
            .await?;
        // Erase `tags` table
        sqlx::query(self.get_query("clean-table-tags")?)
            .execute(self.get_pool())
            .await?;
        Ok(())
    }
}

/// Create the tables
async fn create_tables<DB>(
    loader: &Loader,
    executor: &mut Transaction<'_, DB>,
) -> InterfaceResult<()>
where
    DB: sqlx::Database,
    for<'z> &'z mut DB::Connection: Executor<'z, Database = DB>,
    for<'z> DB::Arguments<'z>: IntoArguments<'z, DB>,
    for<'z> i16: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> String: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> &'z str: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'w, 'z> sqlx::types::Json<&'w serde_json::Value>: sqlx::Encode<'z, DB>,
    sqlx::types::Json<serde_json::Value>: sqlx::Type<DB>,
    usize: sqlx::ColumnIndex<<DB as sqlx::Database>::Row>,
{
    sqlx::query(get_query(loader, "create-table-parameters")?)
        .execute(&mut **executor)
        .await
        .map_err(DbError::from)?;

    sqlx::query(get_query(loader, "create-table-objects")?)
        .execute(&mut **executor)
        .await
        .map_err(DbError::from)?;

    sqlx::query(get_query(loader, "create-table-read_access")?)
        .execute(&mut **executor)
        .await
        .map_err(DbError::from)?;

    sqlx::query(get_query(loader, "create-table-tags")?)
        .execute(&mut **executor)
        .await
        .map_err(DbError::from)?;

    // Old table context used between version 4.13.0 and 4.22.1
    let _ = sqlx::query("DROP TABLE context")
        .execute(&mut **executor)
        .await;

    Ok(())
}
