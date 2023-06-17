use std::path::PathBuf;

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_types::{
        Attributes, LinkedObjectIdentifier::TextString, StateEnumeration, UniqueIdentifier,
    },
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, IsWrapped, ObjectOperationTypes};
use lazy_static::lazy_static;
use rawsql::Loader;
use serde::{Deserialize, Serialize};

use crate::{kms_bail, result::KResult};

pub type KMSServer = crate::core::KMS;

pub(crate) mod cached_sqlcipher;
pub(crate) mod cached_sqlite_struct;
pub(crate) mod pgsql;
pub mod sqlite;

pub(crate) mod mysql;

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

#[async_trait]
pub trait Database {
    /// Return the filename of the database if supported
    fn filename(&self, group_id: u128) -> PathBuf;

    /// Insert the given Object in the database.
    ///
    /// A new UUID will be created if none is supplier.
    /// This method will fail if a `uid` is supplied
    /// and an object with the same id already exists
    async fn create(
        &self,
        uid: Option<String>,
        user: &str,
        object: &Object,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<UniqueIdentifier>;

    /// Insert the provided Objects in the database in a transaction
    ///
    /// A new UUID will be created if none is supplier.
    /// This method will fail if a `uid` is supplied
    /// and an object with the same id already exists
    async fn create_objects(
        &self,
        user: &str,
        objects: &[(Option<String>, Object)],
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<UniqueIdentifier>>;

    /// Retrieve an object from the database using `uid` and `user`.
    /// The `query_read_access` allows additional lookup in `read_access` table to see
    /// if `user` is matching `read_access` authorization
    async fn retrieve(
        &self,
        uid: &str,
        user: &str,
        query_read_access: ObjectOperationTypes,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Option<(Object, StateEnumeration)>>;

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// upsert (update or create if not exists)
    async fn upsert(
        &self,
        uid: &str,
        user: &str,
        object: &Object,
        state: StateEnumeration,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    async fn delete(
        &self,
        uid: &str,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    async fn list_access_rights_obtained(
        &self,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<
        Vec<(
            UniqueIdentifier,
            String,
            StateEnumeration,
            Vec<ObjectOperationTypes>,
            IsWrapped,
        )>,
    >;

    async fn list_accesses(
        &self,
        uid: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(String, Vec<ObjectOperationTypes>)>>;

    /// Insert a `userid` to give `operation_type` access right for the object identified
    /// by its `uid` and belonging to `owner`
    async fn insert_access(
        &self,
        uid: &str,
        userid: &str,
        operation_type: ObjectOperationTypes,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Delete a `userid` to remove read access right for the object identified
    /// by its `uid` and belonging to `owner`
    async fn delete_access(
        &self,
        uid: &str,
        userid: &str,
        operation_type: ObjectOperationTypes,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()>;

    /// Test if an object identified by its `uid` is currently owned by `owner`
    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<bool>;

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<(UniqueIdentifier, StateEnumeration, Attributes, IsWrapped)>>;
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

/// Handle different placeholders naming (bind parameter or
/// function) in SQL databases.
/// This trait contains default naming which are overridden
/// by implementation if needed
pub trait PlaceholderTrait {
    const JSON_FN_EACH_ELEMENT: &'static str = "json_each";
    const JSON_FN_EXTRACT_PATH: &'static str = "json_extract";
    const JSON_FN_EXTRACT_TEXT: &'static str = "json_extract";
    const JSON_NODE_ATTRS: &'static str = "'$.object.KeyBlock.KeyValue.Attributes'";
    const JSON_NODE_WRAPPING: &'static str = "'$.object.KeyBlock.KeyWrappingData'";
    const JSON_NODE_LINK: &'static str = "'$.object.KeyBlock.KeyValue.Attributes.Link'";
    const JSON_TEXT_LINK_OBJ_ID: &'static str = "'$.LinkedObjectIdentifier'";
    const JSON_TEXT_LINK_TYPE: &'static str = "'$.LinkType'";
    const TYPE_INTEGER: &'static str = "INTEGER";

    /// Handle different placeholders (`?`, `$1`) in SQL queries
    /// to bind value into a query
    #[must_use]
    fn binder(param_number: usize) -> String {
        format!("${param_number}")
    }

    /// In `PostgreSQL` and Sqlite, finding link attributes is different and
    /// needs an additional `FROM` component, which is later used as `value`
    /// when looping using `json_each`
    #[must_use]
    fn additional_rq_from() -> Option<String> {
        Some(format!(
            "{}({}(objects.object, {}))",
            Self::JSON_FN_EACH_ELEMENT,
            Self::JSON_FN_EXTRACT_PATH,
            Self::JSON_NODE_LINK
        ))
    }

    /// Build the query part that evaluates link, depending on the SQL engine.
    /// Searching and evaluating nodes can't be unified between MySQL/MariaDB and others
    #[must_use]
    fn link_evaluation(node_name: &str, node_value: &str) -> String {
        format!(
            "{}(value, {}) = '{}'",
            Self::JSON_FN_EXTRACT_TEXT,
            node_name,  // `P::JSON_TEXT_LINK_TYPE` or `P::JSON_TEXT_LINK_OBJ_ID`
            node_value  // `link.link_type` or `uid`
        )
    }

    /// Get node specifier depending on `key_name` (ie: `CryptographicAlgorithm`)
    #[must_use]
    fn extract_path_text(key_name: &str) -> String {
        format!("object -> 'object' -> 'KeyBlock' ->> '{key_name}'")
    }
}

pub enum MySqlPlaceholder {}
impl PlaceholderTrait for MySqlPlaceholder {
    const JSON_FN_EACH_ELEMENT: &'static str = "json_search";
    const JSON_TEXT_LINK_OBJ_ID: &'static str = "'$[*].LinkedObjectIdentifier'";
    const JSON_TEXT_LINK_TYPE: &'static str = "'$[*].LinkType'";
    const TYPE_INTEGER: &'static str = "SIGNED";

    fn binder(_param_number: usize) -> String {
        "?".to_string()
    }

    fn additional_rq_from() -> Option<String> {
        None
    }

    fn link_evaluation(node_name: &str, node_value: &str) -> String {
        // built evaluation is going to be like:
        // json_search(
        //      json_extract(objects.object, '$.object.KeyBlock.KeyValue.Attributes.Link'),
        //      'one',          -> need at most 1 match
        //      'ParentLink',   -> `node_value` (from either `link.link_type` or `uid`)
        //      NULL,
        //      '$[*].LinkType' -> `node_name` (from either `P::JSON_TEXT_LINK_TYPE` or `P::JSON_TEXT_LINK_OBJ_ID`)
        // )
        format!(
            "{}({}(objects.object, {}), 'one', '{}', NULL, {}) IS NOT NULL",
            Self::JSON_FN_EACH_ELEMENT,
            Self::JSON_FN_EXTRACT_PATH,
            Self::JSON_NODE_LINK,
            node_value,
            node_name,
        )
    }

    fn extract_path_text(key_name: &str) -> String {
        format!(
            "{}(object, '$.object.KeyBlock.{key_name}')",
            Self::JSON_FN_EXTRACT_TEXT
        )
    }
}
pub enum PgsqlPlaceholder {}
impl PlaceholderTrait for PgsqlPlaceholder {
    const JSON_FN_EACH_ELEMENT: &'static str = "json_array_elements";
    const JSON_FN_EXTRACT_PATH: &'static str = "json_extract_path";
    const JSON_FN_EXTRACT_TEXT: &'static str = "json_extract_path_text";
    const JSON_NODE_ATTRS: &'static str = "'object', 'KeyBlock', 'KeyValue', 'Attributes'";
    const JSON_NODE_LINK: &'static str = "'object', 'KeyBlock', 'KeyValue', 'Attributes', 'Link'";
    const JSON_NODE_WRAPPING: &'static str = "'object', 'KeyBlock', 'KeyWrappingData'";
    const JSON_TEXT_LINK_OBJ_ID: &'static str = "'LinkedObjectIdentifier'";
    const JSON_TEXT_LINK_TYPE: &'static str = "'LinkType'";
}
pub enum SqlitePlaceholder {}
impl PlaceholderTrait for SqlitePlaceholder {}

/// Builds a SQL query depending on `attributes` and `state` constraints,
/// to search for items in database.
/// Returns a tuple containing the stringified query and the values to bind with.
/// The different placeholder for variable binding is handled by trait specification.
pub fn query_from_attributes<P: PlaceholderTrait>(
    attributes: Option<&Attributes>,
    state: Option<StateEnumeration>,
    owner: &str,
) -> KResult<String> {
    let mut query = format!(
        "SELECT objects.id as id, objects.state as state, {}(objects.object, {}) as attrs, \
         {}(objects.object, {}) IS NOT NULL AS is_wrapped FROM objects",
        P::JSON_FN_EXTRACT_PATH,
        P::JSON_NODE_ATTRS,
        P::JSON_FN_EXTRACT_PATH,
        P::JSON_NODE_WRAPPING
    );
    if let Some(attributes) = attributes {
        if let Some(links) = &attributes.link {
            if !links.is_empty() {
                if let Some(additional_rq_from) = P::additional_rq_from() {
                    query = format!("{query}, {additional_rq_from}");
                }
            }
        }
    }

    query = format!("{query} WHERE owner = '{owner}'");

    if let Some(state) = state {
        query = format!("{query} AND state = '{state}'");
    }

    if let Some(attributes) = attributes {
        // CryptographicAlgorithm
        if let Some(cryptographic_algorithm) = attributes.cryptographic_algorithm {
            query = format!(
                "{query} AND {} = '{cryptographic_algorithm}'",
                P::extract_path_text("CryptographicAlgorithm")
            );
        };

        // CryptographicLength
        if let Some(cryptographic_length) = attributes.cryptographic_length {
            query = format!(
                "{query} AND CAST ({} AS {}) = {cryptographic_length}",
                P::extract_path_text("CryptographicLength"),
                P::TYPE_INTEGER
            );
        };

        // KeyFormatType
        if let Some(key_format_type) = attributes.key_format_type {
            query = format!(
                "{query} AND {} = '{key_format_type}'",
                P::extract_path_text("KeyFormatType")
            );
        };

        // Link
        if let Some(links) = &attributes.link {
            for link in links {
                // LinkType
                query = format!(
                    "{query} AND {}",
                    P::link_evaluation(P::JSON_TEXT_LINK_TYPE, &link.link_type.to_string())
                );

                // LinkedObjectIdentifier
                if let TextString(uid) = &link.linked_object_identifier {
                    query = format!(
                        "{query} AND {}",
                        P::link_evaluation(P::JSON_TEXT_LINK_OBJ_ID, uid)
                    );
                }
            }
        }
    }

    Ok(query)
}
