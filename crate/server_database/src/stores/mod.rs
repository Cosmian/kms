pub(crate) mod extra_store_params;
mod locate_query;
mod mysql;
mod pgsql;
mod redis;
mod sql;
mod sqlite;

pub use extra_store_params::SqlCipherSessionParams;
use lazy_static::lazy_static;
pub(crate) use mysql::MySqlPool;
pub(crate) use pgsql::PgPool;
use rawsql::Loader;
#[cfg(test)]
pub(crate) use redis::additional_redis_findex_tests;
pub use redis::redis_master_key_from_password;
pub(crate) use redis::{RedisWithFindex, REDIS_WITH_FINDEX_MASTER_KEY_LENGTH};
pub(crate) use sqlite::SqlitePool;

const PGSQL_FILE_QUERIES: &str = include_str!("query.sql");
const MYSQL_FILE_QUERIES: &str = include_str!("query_mysql.sql");
const SQLITE_FILE_QUERIES: &str = include_str!("query.sql");

lazy_static! {
    static ref PGSQL_QUERIES: Loader =
        Loader::get_queries_from(PGSQL_FILE_QUERIES).expect("Can't parse the SQL file");
    static ref MYSQL_QUERIES: Loader =
        Loader::get_queries_from(MYSQL_FILE_QUERIES).expect("Can't parse the SQL file");
    static ref SQLITE_QUERIES: Loader =
        Loader::get_queries_from(SQLITE_FILE_QUERIES).expect("Can't parse the SQL file");
}
