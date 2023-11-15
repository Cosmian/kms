use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_types::StateEnumeration,
};
use lazy_static::lazy_static;
use rawsql::Loader;
use serde::{Deserialize, Serialize};

use crate::{kms_bail, result::KResult};

pub type KMSServer = crate::core::KMS;

pub(crate) mod cached_sqlcipher;
pub(crate) mod cached_sqlite_struct;
mod database_trait;
pub(crate) mod mysql;
pub(crate) mod object_with_metadata;
pub(crate) mod pgsql;
pub(crate) mod redis;
pub(crate) mod sqlite;
pub(crate) use database_trait::{AtomicOperation, Database};
mod locate_query;
mod retrieve_object_utils;
pub(crate) use locate_query::{
    query_from_attributes, MySqlPlaceholder, PgSqlPlaceholder, SqlitePlaceholder,
};
pub use retrieve_object_utils::retrieve_object_for_operation;

#[cfg(test)]
mod tests;

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

/// The Database implemented using `SQLite`
///
/// This class uses a connection should be cloned on each server thread
#[derive(Clone)]
/// When using JSON serialization, the Object is untagged
/// and looses its type information, so we have to keep
/// the `ObjectType`. See `Object` and `post_fix()` for details
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DBObject {
    pub(crate) object_type: ObjectType,
    pub(crate) object: Object,
}

pub fn state_from_string(s: &str) -> KResult<StateEnumeration> {
    match s {
        "PreActive" => Ok(StateEnumeration::PreActive),
        "Active" => Ok(StateEnumeration::Active),
        "Deactivated" => Ok(StateEnumeration::Deactivated),
        "Compromised" => Ok(StateEnumeration::Compromised),
        "Destroyed" => Ok(StateEnumeration::Destroyed),
        "Destroyed_Compromised" => Ok(StateEnumeration::Destroyed_Compromised),
        x => kms_bail!("invalid state in db: {}", x),
    }
}
