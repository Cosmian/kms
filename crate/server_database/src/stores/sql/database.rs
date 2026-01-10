use rawsql::Loader;

use crate::{DbError, error::DbResult};

/// Minimal, backend-agnostic SQL access used across the server database.
/// This trait intentionally avoids any dependency on `sqlx` and only
/// provides shared utilities (loader and binder) that callers use to pick
/// the right SQL and placeholder style per backend.
pub(crate) trait SqlDatabase {
    /// Get the loader that reads the SQL queries for this backend
    fn get_loader(&self) -> &Loader;

    /// Get the 'binder' used in the SQL queries for this database dialect
    /// e.g. for Postgres/SQLite: "$1", for `MySQL`: "?"
    #[allow(dead_code)]
    fn binder(&self, param_number: usize) -> String {
        // Default to Postgres/SQLite style
        format!("${param_number}")
    }

    /// Get the SQL query by name using the loader
    /// # Errors
    /// If the query can't be found
    fn get_query<'a>(&'a self, name: &'a str) -> DbResult<&'a str> {
        get_query(self.get_loader(), name)
    }
}

/// Get the SQL query by name using a loader
pub(super) fn get_query<'a>(loader: &'a Loader, name: &'a str) -> DbResult<&'a str> {
    loader
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| DbError::DatabaseError(format!("{name} SQL query can't be found")))
}
