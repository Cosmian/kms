use cosmian_kms_interfaces::{DbState, InterfaceError, InterfaceResult, Migrate, ObjectsStore};
use rawsql::Loader;
use sqlx::{Executor, IntoArguments, Pool, Transaction};

use crate::{
    error::{DbResult, DbResultHelper},
    DbError,
};

pub trait SqlMainStore<'s, 'a, DB>: ObjectsStore + Migrate
where
    DB: sqlx::Database,
    for<'z> &'z mut DB::Connection: Executor<'z, Database = DB>,
    DB::Arguments<'a>: IntoArguments<'a, DB>,
    's: 'a,
{
    /// Get the database pool,
    /// For example, `PgPool` or `SqlitePool`
    /// # Returns
    /// The database pool
    fn get_pool(&'s self) -> &'a Pool<DB>;

    /// Get the loader that reads the SQL queries
    fn get_loader(&'s self) -> &'a Loader;

    /// Instantiate the store, creating the tables if they don't exist
    /// and performing the migration if necessary
    /// # Arguments
    /// * `clear_database` - if `true`, the database will be cleared
    /// # Errors
    /// If the store can't be instantiated
    async fn instantiate(&'s self, clear_database: bool) -> InterfaceResult<()> {
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
    async fn setup_database(&'s self) -> InterfaceResult<bool> {
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
    async fn clear_database(&'s self) -> DbResult<()> {
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

    /// Get the SQL query by name using the loader
    /// # Errors
    /// If the query can't be found
    fn get_query(&'s self, name: &str) -> InterfaceResult<&'a str> {
        get_query(self.get_loader(), name)
    }
}

/// Get the SQL query by name using the loader
fn get_query<'a>(loader: &'a Loader, name: &str) -> InterfaceResult<&'a str> {
    loader
        .get(name)
        .map(|sql| sql.as_str())
        .ok_or_else(|| InterfaceError::Db(format!("{} SQL query can't be found", name)))
}

/// Create the tables
async fn create_tables<'a, 'e, DB>(
    loader: &'a Loader,
    executor: &mut Transaction<'e, DB>,
) -> InterfaceResult<()>
where
    DB: sqlx::Database,
    for<'z> &'z mut DB::Connection: Executor<'z, Database = DB>, // DB::Connection: Deref<Target = E>,
    DB::Arguments<'a>: IntoArguments<'a, DB>,
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
