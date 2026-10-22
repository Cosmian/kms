pub(crate) mod locate_query;
mod mysql;
pub(crate) use mysql::MySqlPool;
mod pgsql;
pub(crate) use pgsql::{
    PG_MAX_RETRIES, PgPool, is_pg_retryable_error, pg_retry_backoff_ms,
    pg_url_verifies_server_cert, prepare_pg_connection,
};
mod sqlite;
pub(crate) use sqlite::SqlitePool;

mod database;
