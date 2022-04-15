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
