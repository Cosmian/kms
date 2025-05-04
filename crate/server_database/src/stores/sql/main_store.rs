use async_trait::async_trait;
use cosmian_kms_interfaces::{InterfaceError, InterfaceResult};
use rawsql::Loader;
use sqlx::{Executor, IntoArguments, Transaction};
use tracing::debug;

use crate::{
    DbError,
    error::{DbResult, DbResultHelper},
    stores::{
        migrate::{DbState, Migrate},
        sql::database::{SqlDatabase, get_query},
    },
};

#[async_trait(?Send)]
pub(crate) trait SqlMainStore<DB>
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
    /// Start the store, creating the tables if they don't exist
    /// and performing the migration if necessary
    /// # Arguments
    /// * `clear_database` - if `true`, the database will be cleared
    /// # Errors
    /// If the store can't be instantiated
    async fn start(&self, clear_database: bool) -> InterfaceResult<()>;
}

#[async_trait(?Send)]
impl<T, DB> SqlMainStore<DB> for T
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
    T: SqlDatabase<DB> + Migrate<DB>,
{
    /// Start the store, creating the tables if they don't exist
    /// and performing the migration if necessary
    /// # Arguments
    /// * `clear_database` - if `true`, the database will be cleared
    /// # Errors
    /// If the store can't be instantiated
    async fn start(&self, clear_database: bool) -> InterfaceResult<()> {
        let is_new_instance = setup_database(self).await?;
        debug!("Database setup complete, is new instance? {is_new_instance}");
        if is_new_instance {
            self.set_current_db_version(env!("CARGO_PKG_VERSION"))
                .await?;
            self.set_db_state(DbState::Ready).await?;
        } else {
            self.migrate().await?;
        }
        if clear_database {
            clear_db(self).await?;
        }
        Ok(())
    }
}

/// Clear the database, namely the `objects`, `read_access` and `tags` tables
/// # Errors
/// If the database can't be cleared
async fn clear_db<DB>(sql_db: &dyn SqlDatabase<DB>) -> DbResult<()>
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
    // Erase `objects` table
    sqlx::query(sql_db.get_query("clean-table-objects")?)
        .execute(sql_db.get_pool())
        .await?;
    // Erase `read_access` table
    sqlx::query(sql_db.get_query("clean-table-read_access")?)
        .execute(sql_db.get_pool())
        .await?;
    // Erase `tags` table
    sqlx::query(sql_db.get_query("clean-table-tags")?)
        .execute(sql_db.get_pool())
        .await?;
    Ok(())
}

/// Set up the database creating the tables if they don't exist
/// # Returns
/// `true` if the database is a new instance, `false` otherwise
/// # Errors
/// If the tables can't be created
async fn setup_database<DB>(sql_db: &dyn SqlDatabase<DB>) -> InterfaceResult<bool>
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
    let is_new_instance = sqlx::query("SELECT * FROM objects LIMIT 1")
        .fetch_optional(sql_db.get_pool())
        .await
        .is_err();

    let mut tx = sql_db
        .get_pool()
        .begin()
        .await
        .map_err(|e| InterfaceError::Db(format!("failed to start a transaction: {e}")))?;

    match create_tables(sql_db.get_loader(), &mut tx).await {
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
    let _unused = sqlx::query("DROP TABLE IF EXISTS context ")
        .execute(&mut **executor)
        .await;

    Ok(())
}
