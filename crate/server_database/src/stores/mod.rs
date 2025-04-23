mod redis;
mod sql;

mod migrate;

use std::sync::LazyLock;

use rawsql::Loader;
#[cfg(test)]
pub(crate) use redis::additional_redis_findex_tests;
pub use redis::redis_master_key_from_password;
pub(crate) use redis::{REDIS_WITH_FINDEX_MASTER_KEY_LENGTH, RedisWithFindex};
pub(crate) use sql::{MySqlPool, PgPool, SqlitePool};

const PGSQL_FILE_QUERIES: &str = include_str!("sql/query.sql");
const MYSQL_FILE_QUERIES: &str = include_str!("sql/query_mysql.sql");
const SQLITE_FILE_QUERIES: &str = include_str!("sql/query.sql");

static PGSQL_QUERIES: LazyLock<Loader> = LazyLock::new(|| {
    Loader::get_queries_from(PGSQL_FILE_QUERIES).expect("Can't parse the SQL file")
});
static MYSQL_QUERIES: LazyLock<Loader> = LazyLock::new(|| {
    Loader::get_queries_from(MYSQL_FILE_QUERIES).expect("Can't parse the SQL file")
});
static SQLITE_QUERIES: LazyLock<Loader> = LazyLock::new(|| {
    Loader::get_queries_from(SQLITE_FILE_QUERIES).expect("Can't parse the SQL file")
});
