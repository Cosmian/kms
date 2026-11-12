mod audit;
/// Shared startup migration contracts, including the scenario-test target versions.
pub(crate) mod migrate;
#[cfg(feature = "non-fips")]
pub(crate) mod redis;
mod sql;

use std::sync::OnceLock;

pub use audit::{PgAuditReader, PgAuditSink};
use rawsql::Loader;
#[cfg(all(test, feature = "non-fips"))]
pub(crate) use redis::additional_redis_findex_tests;
#[cfg(feature = "non-fips")]
pub use redis::redis_master_key_from_password;
#[cfg(feature = "non-fips")]
pub(crate) use redis::{REDIS_WITH_FINDEX_MASTER_KEY_LENGTH, RedisWithFindex};
pub(crate) use sql::{MySqlPool, PgPool, SqlitePool};

const PGSQL_FILE_QUERIES: &str = include_str!("sql/query.sql");
const MYSQL_FILE_QUERIES: &str = include_str!("sql/query_mysql.sql");
const SQLITE_FILE_QUERIES: &str = include_str!("sql/query_sqlite.sql");

/// Parse an embedded SQL bundle once and cache it.
fn load_queries(
    cell: &'static OnceLock<Loader>,
    file: &'static str,
) -> crate::error::DbResult<&'static Loader> {
    if let Some(loader) = cell.get() {
        return Ok(loader);
    }
    let loader = Loader::get_queries_from(file).map_err(|e| {
        crate::error::DbError::DatabaseError(format!("Can't parse the SQL file: {e}"))
    })?;
    Ok(cell.get_or_init(|| loader))
}

pub(crate) fn pgsql_queries() -> crate::error::DbResult<&'static Loader> {
    static CELL: OnceLock<Loader> = OnceLock::new();
    load_queries(&CELL, PGSQL_FILE_QUERIES)
}

pub(crate) fn mysql_queries() -> crate::error::DbResult<&'static Loader> {
    static CELL: OnceLock<Loader> = OnceLock::new();
    load_queries(&CELL, MYSQL_FILE_QUERIES)
}

/// SQLite-specific query overrides.  Loaded before `pgsql_queries` so that
/// SQLite-divergent SQL (e.g. JSON functions) takes precedence.
pub(crate) fn sqlite_queries() -> crate::error::DbResult<&'static Loader> {
    static CELL: OnceLock<Loader> = OnceLock::new();
    load_queries(&CELL, SQLITE_FILE_QUERIES)
}

#[cfg(test)]
mod characterization_tests {
    //! Characterization tests pinning that the embedded SQL bundles parse and expose the queries.

    use super::{mysql_queries, pgsql_queries, sqlite_queries};

    #[test]
    fn characterization_embedded_sql_bundles_parse_and_expose_queries() {
        for name in ["select-parameter", "has-row-objects"] {
            assert_ne!(pgsql_queries().unwrap().get(name).unwrap().trim().len(), 0);
            assert_ne!(mysql_queries().unwrap().get(name).unwrap().trim().len(), 0);
        }
        assert_ne!(
            sqlite_queries()
                .unwrap()
                .get("count-non-destroyed-keys")
                .unwrap()
                .trim()
                .len(),
            0
        );
    }

    #[test]
    fn characterization_embedded_sql_unknown_query_is_absent() {
        assert!(pgsql_queries().unwrap().get("no-such-query").is_none());
        assert!(mysql_queries().unwrap().get("no-such-query").is_none());
        assert!(sqlite_queries().unwrap().get("no-such-query").is_none());
    }
}
