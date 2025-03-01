use cosmian_kms_interfaces::ObjectWithMetadata;
use rawsql::Loader;
use sqlx::{Executor, IntoArguments, Pool};

use crate::{error::DbResult, DbError};

pub trait SqlDatabase<DB>
where
    DB: sqlx::Database,
    for<'z> &'z mut DB::Connection: Executor<'z, Database = DB>,
    for<'z> DB::Arguments<'z>: IntoArguments<'z, DB>,
{
    /// Get the database pool,
    /// For example, `PgPool` or `SqlitePool`
    /// # Returns
    /// The database pool
    fn get_pool(&self) -> &Pool<DB>;

    /// Get the loader that reads the SQL queries
    fn get_loader(&self) -> &Loader;

    /// Convert a database row to an object with metadata
    fn db_row_to_owm(&self, row: &DB::Row) -> DbResult<ObjectWithMetadata>;

    /// Get the SQL query by name using the loader
    /// # Errors
    /// If the query can't be found
    fn get_query<'a>(&'a self, name: &'a str) -> DbResult<&'a str> {
        get_query(self.get_loader(), name)
    }
}

/// Get the SQL query by name using the loader
pub fn get_query<'a>(loader: &'a Loader, name: &'a str) -> DbResult<&'a str> {
    loader
        .get(name)
        .map(|sql| sql.as_str())
        .ok_or_else(|| DbError::DatabaseError(format!("{} SQL query can't be found", name)))
}
