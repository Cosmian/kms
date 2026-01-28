use core::fmt::Write as _;

use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_types::{LinkedObjectIdentifier::TextString, NameType, UniqueIdentifier},
    },
};

/// Handle different placeholders naming (bind parameter or
/// function) in SQL databases.
/// This trait contains default naming overridden
/// by implementation if needed
pub(super) trait PlaceholderTrait {
    const NEEDS_INTEGER_CAST: bool = true;
    const JSON_FN_EACH_ELEMENT: &'static str = "json_each";
    const JSON_FN_EXTRACT_PATH: &'static str = "json_extract";
    const JSON_FN_EXTRACT_TEXT: &'static str = "json_extract";
    #[allow(dead_code)]
    const JSON_ARRAY_LENGTH: &'static str = "json_array_length";
    const JSON_NODE_LINK: &'static str = "'$.Link'";
    const JSON_TEXT_LINK_OBJ_ID: &'static str = "'$.LinkedObjectIdentifier'";
    const JSON_TEXT_LINK_TYPE: &'static str = "'$.LinkType'";
    const JSON_NODE_NAME: &'static str = "'$.Name'";
    const JSON_TEXT_NAME_VALUE: &'static str = "'$.NameValue'";
    const JSON_TEXT_NAME_TYPE: &'static str = "'$.NameType'";
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
    fn links_additional_rq_from() -> Option<String> {
        Some(format!(
            "{}({}(objects.attributes, {})) as links",
            Self::JSON_FN_EACH_ELEMENT,
            Self::JSON_FN_EXTRACT_PATH,
            Self::JSON_NODE_LINK
        ))
    }

    /// In `PostgreSQL` and Sqlite, finding name attributes is different and
    /// needs an additional `FROM` component, which is later used as `value`
    /// when looping using `json_each`
    #[must_use]
    fn names_additional_rq_from() -> Option<String> {
        Some(format!(
            "{}({}(objects.attributes, {})) as names",
            Self::JSON_FN_EACH_ELEMENT,
            Self::JSON_FN_EXTRACT_PATH,
            Self::JSON_NODE_NAME
        ))
    }

    /// Build the query part that evaluates link, depending on the SQL engine.
    /// Searching and evaluating nodes can't be unified between MySQL/MariaDB and others
    #[must_use]
    fn link_evaluation(node_name: &str, node_value: &str) -> String {
        format!(
            "{}(links.value, {}) = {}",
            Self::JSON_FN_EXTRACT_TEXT,
            node_name,  // `P::JSON_TEXT_LINK_TYPE` or `P::JSON_TEXT_LINK_OBJ_ID`
            node_value  // `link.link_type` or `uid`
        )
    }

    #[must_use]
    fn name_evaluation(node_name: &str, node_value: &str) -> String {
        format!(
            "{}(names.value, {}) = {}",
            Self::JSON_FN_EXTRACT_TEXT,
            node_name,  // `P::JSON_TEXT_NAME_TYPE` or `P::JSON_TEXT_NAME_VALUE`
            node_value  // `name.name_type` or `name.name_value`
        )
    }

    /// Format the JSON path to extract an attribute
    /// from the `objects.attributes` JSON field
    #[must_use]
    fn format_json_path(attribute_names: &[&str]) -> String {
        "$.".to_owned() + &*attribute_names.join(".")
    }

    #[must_use]
    fn extract_attribute_path(attribute_names: &[&str]) -> String {
        format!(
            "{}(objects.attributes, '{}')",
            Self::JSON_FN_EXTRACT_TEXT,
            Self::format_json_path(attribute_names)
        )
    }

    /// Get node specifier depending on `object_type` (ie: `PrivateKey` or `Certificate`)
    #[must_use]
    fn extract_object_type() -> String {
        Self::extract_attribute_path(&["ObjectType"])
    }
}

pub(super) enum MySqlPlaceholder {}
impl PlaceholderTrait for MySqlPlaceholder {
    const JSON_ARRAY_LENGTH: &'static str = "JSON_LENGTH";
    const JSON_FN_EACH_ELEMENT: &'static str = "json_search";
    const JSON_TEXT_LINK_OBJ_ID: &'static str = "'$[*].LinkedObjectIdentifier'";
    const JSON_TEXT_LINK_TYPE: &'static str = "'$[*].LinkType'";
    const JSON_TEXT_NAME_TYPE: &'static str = "'$[*].NameType'";
    const JSON_TEXT_NAME_VALUE: &'static str = "'$[*].NameValue'";
    const NEEDS_INTEGER_CAST: bool = false;
    const TYPE_INTEGER: &'static str = "UNSIGNED INTEGER";

    fn binder(_param_number: usize) -> String {
        "?".to_owned()
    }

    fn links_additional_rq_from() -> Option<String> {
        None
    }

    fn names_additional_rq_from() -> Option<String> {
        None
    }

    fn extract_attribute_path(attribute_names: &[&str]) -> String {
        // Use JSON_UNQUOTE(JSON_EXTRACT(...)) for broad MySQL/MariaDB compatibility
        format!(
            "JSON_UNQUOTE(JSON_EXTRACT(objects.attributes, '{}'))",
            Self::format_json_path(attribute_names)
        )
    }

    fn link_evaluation(node_name: &str, node_value: &str) -> String {
        // built evaluation is going to be like:
        // json_search(
        //      json_extract(objects.attributes, '$.Link'),
        //      'one',          -> need at most 1 match
        //      'ParentLink',   -> `node_value` (from either `link.link_type` or `uid`)
        //      NULL,
        //      '$[*].LinkType' -> `node_name` (from either `P::JSON_TEXT_LINK_TYPE` or `P::JSON_TEXT_LINK_OBJ_ID`)
        // )
        format!(
            "{}({}(objects.attributes, {}), 'one', {}, NULL, {}) IS NOT NULL",
            Self::JSON_FN_EACH_ELEMENT,
            Self::JSON_FN_EXTRACT_PATH,
            Self::JSON_NODE_LINK,
            node_value,
            node_name,
        )
    }

    fn name_evaluation(node_name: &str, node_value: &str) -> String {
        format!(
            "{}({}(objects.attributes, {}), 'one', {}, NULL, {}) IS NOT NULL",
            Self::JSON_FN_EACH_ELEMENT,
            Self::JSON_FN_EXTRACT_PATH,
            Self::JSON_NODE_NAME,
            node_value,
            node_name,
        )
    }
}

/// PostgreSQL-specific placeholder implementation.
///
/// Uses JSONB (binary JSON) instead of JSON for better performance:
/// - **Indexing**: JSONB supports GIN indexes for fast queries on JSON fields
/// - **Query performance**: Binary format allows direct access without reparsing
/// - **Operators**: Rich set of optimized operators (`->`, `->>`, `@>`, `?`, etc.)
/// - **Storage**: Normalized format removes duplicate keys automatically
///
/// While JSONB has slightly slower inserts (due to binary conversion), the query
/// performance improvement is substantial, especially for complex JSON operations
/// like those used in attribute searches and link/name evaluations.
pub(super) enum PgSqlPlaceholder {}
impl PlaceholderTrait for PgSqlPlaceholder {
    const JSON_ARRAY_LENGTH: &'static str = "jsonb_array_length";
    const JSON_FN_EACH_ELEMENT: &'static str = "jsonb_array_elements";
    const JSON_FN_EXTRACT_PATH: &'static str = "jsonb_extract_path";
    const JSON_FN_EXTRACT_TEXT: &'static str = "jsonb_extract_path_text";
    const JSON_NODE_LINK: &'static str = "'Link'";
    const JSON_NODE_NAME: &'static str = "'Name'";
    const JSON_TEXT_LINK_OBJ_ID: &'static str = "'LinkedObjectIdentifier'";
    const JSON_TEXT_LINK_TYPE: &'static str = "'LinkType'";
    const JSON_TEXT_NAME_TYPE: &'static str = "'NameType'";
    const JSON_TEXT_NAME_VALUE: &'static str = "'NameValue'";
    // We bind numeric parameters as Rust `i64` (see `LocateParam::I64`), so ensure
    // any explicit cast on the JSON-extracted value uses a compatible PostgreSQL type.
    const TYPE_INTEGER: &'static str = "BIGINT";

    // const JSON_NODE_WRAPPING: &'static str = "'object', 'KeyBlock', 'KeyWrappingData'";

    /// For `PostgreSQL`, `json_extract_path_text` expects each path element as a separate
    /// argument (e.g., `json_extract_path_text(json`, '`ApplicationSpecificInformation`', '`ApplicationData`')).
    /// Override `extract_attribute_path` to build a call with multiple quoted args instead
    /// of a single comma-joined string.
    fn extract_attribute_path(attribute_names: &[&str]) -> String {
        // Use -> and ->> operators for robust JSONB path extraction, casting to jsonb
        if attribute_names.is_empty() {
            return "(objects.attributes)::jsonb".to_owned();
        }
        let mut path = String::from("(objects.attributes)::jsonb");
        if let Some((last, heads)) = attribute_names.split_last() {
            for key in heads {
                let _ = write!(path, " -> '{key}'");
            }
            let _ = write!(path, " ->> '{last}'");
        }
        path
    }

    /// Get node specifier depending on `object_type` (ie: `PrivateKey` or `Certificate`)
    fn extract_object_type() -> String {
        "(objects.attributes)::jsonb ->> 'ObjectType'".to_owned()
    }
}

pub(super) enum SqlitePlaceholder {}
impl PlaceholderTrait for SqlitePlaceholder {}

// We build locate SQL dynamically across multiple DB engines (SQLite/Postgres/MySQL), but we must
// *not* interpolate user-controlled values directly into the SQL string.
//
// This small query builder keeps two things separate:
// - `sql`: the query text with engine-specific placeholders (`?` vs `$1`, `$2`, ...)
// - `params`: a typed list of values to bind later via the DB driver
//
// That separation is needed for:
// - Security: prevents SQL injection by always using bound parameters.
// - Correctness: preserves types (e.g., numeric values stay numeric) so casts like
//   `CAST(json_value AS BIGINT) = $n` behave consistently across engines.
// - Portability: allows placeholder numbering/formatting to vary by engine while keeping one
//   shared query-construction path.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum LocateParam {
    Text(String),
    I64(i64),
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct LocateQuery {
    pub(super) sql: String,
    pub(super) params: Vec<LocateParam>,
}

struct LocateQueryBuilder<P: PlaceholderTrait> {
    params: Vec<LocateParam>,
    _phantom: core::marker::PhantomData<P>,
}

impl<P: PlaceholderTrait> LocateQueryBuilder<P> {
    const fn new() -> Self {
        Self {
            params: Vec::new(),
            _phantom: core::marker::PhantomData,
        }
    }

    fn bind_text(&mut self, value: impl Into<String>) -> String {
        self.params.push(LocateParam::Text(value.into()));
        P::binder(self.params.len())
    }

    fn bind_i64(&mut self, value: i64) -> String {
        self.params.push(LocateParam::I64(value));
        P::binder(self.params.len())
    }

    fn finish(self, sql: String) -> LocateQuery {
        LocateQuery {
            sql,
            params: self.params,
        }
    }
}

/// Builds a SQL query depending on `attributes` and `state` constraints,
/// to search for items in database.
/// Returns a tuple containing the stringified query and the values to bind with.
/// The different placeholder for variable binding is handled by trait specification.
pub(super) fn query_from_attributes<P: PlaceholderTrait>(
    attributes: Option<&Attributes>,
    state: Option<State>,
    user: &str,
    user_must_be_owner: bool,
) -> LocateQuery {
    let mut qb = LocateQueryBuilder::<P>::new();
    let mut query =
        "SELECT DISTINCT objects.id as id, objects.state as state, objects.attributes as attrs \
                     FROM objects"
            .to_owned();

    if let Some(attributes) = attributes {
        // tags
        let tags = attributes.get_tags();
        let tags_len = tags.len();
        if tags_len > 0 {
            let tag_placeholders = tags
                .iter()
                .map(|t| qb.bind_text(t.clone()))
                .collect::<Vec<String>>()
                .join(", ");
            let tags_len_i64 = i64::try_from(tags_len).unwrap_or(0);
            let tags_len_placeholder = qb.bind_i64(tags_len_i64);
            query = format!(
                "{query} INNER JOIN (
    SELECT id
    FROM tags
    WHERE tag IN ({tag_placeholders})
    GROUP BY id
    HAVING COUNT(DISTINCT tag) = {tags_len_placeholder}
) AS matched_tags
ON objects.id = matched_tags.id"
            );
        }
    }

    if !user_must_be_owner {
        // select objects for which the user is the owner or has been granted an access right
        query = format!(
            "{query}\n LEFT JOIN read_access ON objects.id = read_access.id AND \
             read_access.userid = {}",
            qb.bind_text(user)
        );
    }

    if let Some(attributes) = attributes {
        // Links
        if let Some(links) = &attributes.link {
            if !links.is_empty() {
                if let Some(additional_rq_from) = P::links_additional_rq_from() {
                    query = format!("{query}, {additional_rq_from}");
                }
            }
        }
        if let Some(names) = &attributes.name {
            if !names.is_empty() {
                if let Some(additional_rq_from) = P::names_additional_rq_from() {
                    query = format!("{query}, {additional_rq_from}");
                }
            }
        }
    }

    if user_must_be_owner {
        // only select objects for which the user is the owner
        query = format!("{query} WHERE objects.owner = {}", qb.bind_text(user));
    } else {
        query = format!(
            "{query} WHERE (objects.owner = {} OR read_access.userid = {})",
            qb.bind_text(user),
            qb.bind_text(user)
        );
    }

    if let Some(state) = state {
        // Bind state as text to avoid injection and keep DB representation consistent.
        let state_s: &'static str = state.into();
        query = format!("{query} AND state = {}", qb.bind_text(state_s));
    }

    #[allow(clippy::collapsible_match)]
    if let Some(attributes) = attributes {
        // UniqueIdentifier
        if let Some(uid) = &attributes.unique_identifier {
            if let UniqueIdentifier::TextString(id) = uid {
                query = format!("{query} AND objects.id = {}", qb.bind_text(id.clone()));
            }
        }

        // ObjectGroup
        if let Some(object_group) = &attributes.object_group {
            query = format!(
                "{query} AND {} = {}",
                P::extract_attribute_path(&["ObjectGroup"]),
                qb.bind_text(object_group.clone())
            );
        }

        // ObjectGroupMember
        if let Some(object_group_member) = attributes.object_group_member {
            query = format!(
                "{query} AND {} = {}",
                P::extract_attribute_path(&["ObjectGroupMember"]),
                qb.bind_text(object_group_member.to_string())
            );
        }

        // CryptographicAlgorithm
        if let Some(cryptographic_algorithm) = attributes.cryptographic_algorithm {
            query = format!(
                "{query} AND {} = {}",
                P::extract_attribute_path(&["CryptographicAlgorithm"]),
                qb.bind_text(cryptographic_algorithm.to_string())
            );
        }

        // CryptographicLength
        if let Some(cryptographic_length) = attributes.cryptographic_length {
            let len_i64 = i64::from(cryptographic_length);
            if P::NEEDS_INTEGER_CAST {
                query = format!(
                    "{query} AND CAST ({} AS {}) = {}",
                    P::extract_attribute_path(&["CryptographicLength"]),
                    P::TYPE_INTEGER,
                    qb.bind_i64(len_i64)
                );
            } else {
                // For MySQL/MariaDB, rely on implicit conversion of unquoted value
                query = format!(
                    "{query} AND {} = {}",
                    P::extract_attribute_path(&["CryptographicLength"]),
                    qb.bind_i64(len_i64)
                );
            }
        }

        // KeyFormatType
        if let Some(key_format_type) = attributes.key_format_type {
            query = format!(
                "{query} AND {} = {}",
                P::extract_attribute_path(&["KeyFormatType"]),
                qb.bind_text(key_format_type.to_string())
            );
        }

        // ObjectType
        if let Some(object_type) = attributes.object_type {
            query = format!(
                "{query} AND {} = {}",
                P::extract_object_type(),
                qb.bind_text(object_type.to_string())
            );
        }

        // ApplicationSpecificInformation
        if let Some(app) = &attributes.application_specific_information {
            // ApplicationNamespace is required in the struct
            query = format!(
                "{query} AND {} = {}",
                P::extract_attribute_path(&[
                    "ApplicationSpecificInformation",
                    "ApplicationNamespace"
                ]),
                qb.bind_text(app.application_namespace.clone())
            );
            // ApplicationData is optional
            if let Some(data) = &app.application_data {
                query = format!(
                    "{query} AND {} = {}",
                    P::extract_attribute_path(&[
                        "ApplicationSpecificInformation",
                        "ApplicationData"
                    ]),
                    qb.bind_text(data.clone())
                );
            }
        }

        // Link
        if let Some(links) = &attributes.link {
            for link in links {
                // LinkType
                query = format!(
                    "{query} AND {}",
                    P::link_evaluation(
                        P::JSON_TEXT_LINK_TYPE,
                        &qb.bind_text(link.link_type.to_string())
                    )
                );

                // LinkedObjectIdentifier
                if let TextString(uid) = &link.linked_object_identifier {
                    query = format!(
                        "{query} AND {}",
                        P::link_evaluation(P::JSON_TEXT_LINK_OBJ_ID, &qb.bind_text(uid.clone()))
                    );
                }
            }
        }

        // Name
        if let Some(names) = &attributes.name {
            for name in names {
                // NameType
                query = format!(
                    "{query} AND {}",
                    P::name_evaluation(
                        P::JSON_TEXT_NAME_TYPE,
                        &qb.bind_text(match &name.name_type {
                            NameType::UninterpretedTextString => "UninterpretedTextString",
                            NameType::URI => "URI",
                        })
                    )
                );
                // NameValue
                query = format!(
                    "{query} AND {}",
                    P::name_evaluation(
                        P::JSON_TEXT_NAME_VALUE,
                        &qb.bind_text(name.name_value.clone())
                    )
                );
            }
        }
    }

    qb.finish(query)
}
