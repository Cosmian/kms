mod cached_sqlcipher;
mod cached_sqlite_struct;
pub mod extra_store_params;
mod hsm;
mod locate_query;
mod mysql;
mod pgsql;
mod redis;
mod sqlite;
mod store_traits;

pub use cached_sqlcipher::CachedSqlCipher;
use cosmian_kmip::kmip::kmip_objects::{Object, ObjectType};
pub use extra_store_params::ExtraStoreParams;
pub use hsm::HsmStore;
use lazy_static::lazy_static;
pub(crate) use mysql::MySqlPool;
pub(crate) use pgsql::PgPool;
use rawsql::Loader;
#[cfg(test)]
pub use redis::additional_redis_findex_tests;
pub use redis::{
    redis_master_key_from_password, RedisWithFindex, REDIS_WITH_FINDEX_MASTER_KEY_LENGTH,
};
use serde::{Deserialize, Serialize};
pub(crate) use sqlite::SqlitePool;
pub use store_traits::{AtomicOperation, ObjectsStore, PermissionsStore};

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

#[derive(Clone)]
/// When using JSON serialization, the Object is untagged
/// and loses its type information, so we have to keep
/// the `ObjectType`. See `Object` and `post_fix()` for details
#[derive(Serialize, Deserialize)]
pub(crate) struct DBObject {
    pub(crate) object_type: ObjectType,
    pub(crate) object: Object,
}
