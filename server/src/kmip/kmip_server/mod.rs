use lazy_static::lazy_static;
use rawsql::Loader;

pub(crate) mod database;
pub(crate) mod server;
pub(crate) type KMSServer = server::KMS;
pub(crate) mod pgsql;
pub(crate) mod sqlite;

// the `sqlx` connector for MySQL is unable to connect
// using key-file (instead of password) for EdgelessDB
pub(crate) mod mysql;
#[allow(dead_code)]
pub(crate) mod mysql_sqlx;

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
