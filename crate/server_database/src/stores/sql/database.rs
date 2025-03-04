// use cosmian_kms_interfaces::ObjectWithMetadata;
use rawsql::Loader;
use sqlx::{Executor, IntoArguments, Pool};

use crate::{error::DbResult, DbError};

pub(crate) trait SqlDatabase<DB>
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

    /// Get the 'binder' used in the SQL queries for this database dialect
    /// e.g. for `Postgres` or `SQLite`, it's `$1`, for `MySQL`, it's `?`
    /// Default is the `Postgres` style
    /// # Arguments
    /// * `param_number` - the number of the parameter
    /// # Returns
    /// The binder
    /// # Example
    /// ```
    /// use crate::stores::sql::database::SqlDatabase;
    /// let binder = SqlDatabase::binder(1);
    /// assert_eq!(binder, "$1");
    /// ```
    fn binder(&self, param_number: usize) -> String {
        if std::any::type_name::<DB>() == "sqlx::mysql::MySql" {
            return "?".to_string();
        }
        format!("${param_number}")
    }

    /// Get the SQL query by name using the loader
    /// # Errors
    /// If the query can't be found
    fn get_query<'a>(&'a self, name: &'a str) -> DbResult<&'a str> {
        get_query(self.get_loader(), name)
    }
}

/// Get the SQL query by name using the loader
pub(crate) fn get_query<'a>(loader: &'a Loader, name: &'a str) -> DbResult<&'a str> {
    loader
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| DbError::DatabaseError(format!("{name} SQL query can't be found")))
}
