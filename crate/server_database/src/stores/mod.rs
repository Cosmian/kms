mod audit;
mod migrate;
#[cfg(feature = "non-fips")]
mod redis;
mod sql;

use std::sync::LazyLock;

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

#[expect(
    clippy::expect_used,
    reason = "embedded SQL is embedded at compile time; every query is exercised by tests"
)]
pub(crate) static PGSQL_QUERIES: LazyLock<Loader> = LazyLock::new(|| {
    // SAFETY: SQL files are included at compile time and should be valid
    Loader::get_queries_from(PGSQL_FILE_QUERIES).expect("Can't parse the SQL file")
});
#[expect(
    clippy::expect_used,
    reason = "embedded SQL is embedded at compile time; every query is exercised by tests"
)]
static MYSQL_QUERIES: LazyLock<Loader> = LazyLock::new(|| {
    // SAFETY: SQL files are included at compile time and should be valid
    Loader::get_queries_from(MYSQL_FILE_QUERIES).expect("Can't parse the SQL file")
});
/// SQLite-specific query overrides.  Loaded before `PGSQL_QUERIES` so that
/// SQLite-divergent SQL (e.g. JSON functions) takes precedence.
#[expect(
    clippy::expect_used,
    reason = "embedded SQL is embedded at compile time; every query is exercised by tests"
)]
pub(crate) static SQLITE_QUERIES: LazyLock<Loader> = LazyLock::new(|| {
    // SAFETY: SQL files are included at compile time and should be valid
    Loader::get_queries_from(SQLITE_FILE_QUERIES).expect("Can't parse the SQLite SQL file")
});

#[cfg(test)]
mod characterization_tests {
    //! Characterization tests pinning that the embedded SQL bundles parse and expose the queries.

    use super::{MYSQL_QUERIES, PGSQL_QUERIES, SQLITE_QUERIES};

    #[test]
    fn characterization_embedded_sql_bundles_parse_and_expose_queries() {
        for name in ["select-parameter", "has-row-objects"] {
            assert_ne!(PGSQL_QUERIES.get(name).unwrap().trim().len(), 0);
            assert_ne!(MYSQL_QUERIES.get(name).unwrap().trim().len(), 0);
        }
        assert_ne!(
            SQLITE_QUERIES
                .get("count-non-destroyed-keys")
                .unwrap()
                .trim()
                .len(),
            0
        );
    }

    #[test]
    fn characterization_embedded_sql_unknown_query_is_absent() {
        assert!(PGSQL_QUERIES.get("no-such-query").is_none());
        assert!(MYSQL_QUERIES.get("no-such-query").is_none());
        assert!(SQLITE_QUERIES.get("no-such-query").is_none());
    }
}
