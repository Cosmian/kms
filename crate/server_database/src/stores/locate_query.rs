use cosmian_kmip::kmip::kmip_types::{
    Attributes, LinkedObjectIdentifier::TextString, StateEnumeration,
};

/// Handle different placeholders naming (bind parameter or
/// function) in SQL databases.
/// This trait contains default naming which are overridden
/// by implementation if needed
pub(crate) trait PlaceholderTrait {
    const JSON_FN_EACH_ELEMENT: &'static str = "json_each";
    const JSON_FN_EXTRACT_PATH: &'static str = "json_extract";
    const JSON_FN_EXTRACT_TEXT: &'static str = "json_extract";
    #[allow(dead_code)]
    const JSON_ARRAY_LENGTH: &'static str = "json_array_length";
    const JSON_NODE_WRAPPING: &'static str = "'$.object.KeyBlock.KeyWrappingData'";
    const JSON_NODE_LINK: &'static str = "'$.Link'";
    const JSON_TEXT_LINK_OBJ_ID: &'static str = "'$.LinkedObjectIdentifier'";
    const JSON_TEXT_LINK_TYPE: &'static str = "'$.LinkType'";
    const TYPE_INTEGER: &'static str = "INTEGER";

    /// Handle different placeholders (`?`, `$1`) in SQL queries
    /// to bind value into a query
    #[allow(dead_code)]
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
            "{}({}(objects.attributes, {}))",
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
    fn extract_text_from_key_block_path(key_name: &str) -> String {
        format!("object -> 'object' -> 'KeyBlock' ->> '{key_name}'")
    }

    /// Get node specifier depending on `object_type` (ie: `PrivateKey` or `Certificate`)
    #[must_use]
    fn extract_text_from_object_type_path() -> String {
        "object ->> 'object_type'".to_owned()
    }
}

pub(crate) enum MySqlPlaceholder {}
impl PlaceholderTrait for MySqlPlaceholder {
    const JSON_ARRAY_LENGTH: &'static str = "JSON_LENGTH";
    const JSON_FN_EACH_ELEMENT: &'static str = "json_search";
    const JSON_TEXT_LINK_OBJ_ID: &'static str = "'$[*].LinkedObjectIdentifier'";
    const JSON_TEXT_LINK_TYPE: &'static str = "'$[*].LinkType'";
    const TYPE_INTEGER: &'static str = "SIGNED";

    fn binder(_param_number: usize) -> String {
        "?".to_owned()
    }

    fn additional_rq_from() -> Option<String> {
        None
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
            "{}({}(objects.attributes, {}), 'one', '{}', NULL, {}) IS NOT NULL",
            Self::JSON_FN_EACH_ELEMENT,
            Self::JSON_FN_EXTRACT_PATH,
            Self::JSON_NODE_LINK,
            node_value,
            node_name,
        )
    }

    fn extract_text_from_key_block_path(key_name: &str) -> String {
        format!(
            "{}(object, '$.object.KeyBlock.{key_name}')",
            Self::JSON_FN_EXTRACT_TEXT
        )
    }

    fn extract_text_from_object_type_path() -> String {
        format!("{}(object, '$.object_type')", Self::JSON_FN_EXTRACT_TEXT)
    }
}
pub(crate) enum PgSqlPlaceholder {}
impl PlaceholderTrait for PgSqlPlaceholder {
    const JSON_ARRAY_LENGTH: &'static str = "json_array_length";
    const JSON_FN_EACH_ELEMENT: &'static str = "json_array_elements";
    const JSON_FN_EXTRACT_PATH: &'static str = "json_extract_path";
    const JSON_FN_EXTRACT_TEXT: &'static str = "json_extract_path_text";
    const JSON_NODE_LINK: &'static str = "'Link'";
    const JSON_NODE_WRAPPING: &'static str = "'object', 'KeyBlock', 'KeyWrappingData'";
    const JSON_TEXT_LINK_OBJ_ID: &'static str = "'LinkedObjectIdentifier'";
    const JSON_TEXT_LINK_TYPE: &'static str = "'LinkType'";
}
pub(crate) enum SqlitePlaceholder {}
impl PlaceholderTrait for SqlitePlaceholder {}

/// Builds a SQL query depending on `attributes` and `state` constraints,
/// to search for items in database.
/// Returns a tuple containing the stringified query and the values to bind with.
/// The different placeholder for variable binding is handled by trait specification.
// TODO  although this is a select query, it is complex and the occurrence is unlikely,
// TODO  protection against SQL Injection is not covered here
pub(crate) fn query_from_attributes<P: PlaceholderTrait>(
    attributes: Option<&Attributes>,
    state: Option<StateEnumeration>,
    user: &str,
    user_must_be_owner: bool,
) -> String {
    let mut query = format!(
        "SELECT objects.id as id, objects.state as state, objects.attributes as attrs, \
         {}(objects.object, {}) IS NOT NULL AS is_wrapped FROM objects",
        P::JSON_FN_EXTRACT_PATH,
        P::JSON_NODE_WRAPPING
    );

    if let Some(attributes) = attributes {
        // tags
        let tags = attributes.get_tags();
        let tags_len = tags.len();
        if tags_len > 0 {
            let tags_string = tags
                .iter()
                .map(|t| format!("'{t}'"))
                .collect::<Vec<String>>()
                .join(", ");
            query = format!(
                "{query} INNER JOIN (
    SELECT id
    FROM tags
    WHERE tag IN ({tags_string})
    GROUP BY id
    HAVING COUNT(DISTINCT tag) = {tags_len}
) AS matched_tags
ON objects.id = matched_tags.id"
            );
        }
    }

    if !user_must_be_owner {
        // select objects for which the user is the owner or has been granted an access right
        query = format!(
            "{query}\n LEFT JOIN read_access ON objects.id = read_access.id AND \
             read_access.userid = '{user}'"
        );
    }

    if let Some(attributes) = attributes {
        // Links
        if let Some(links) = &attributes.link {
            if !links.is_empty() {
                if let Some(additional_rq_from) = P::additional_rq_from() {
                    query = format!("{query}, {additional_rq_from}");
                }
            }
        }
    }

    if user_must_be_owner {
        // only select objects for which the user is the owner
        query = format!("{query} WHERE objects.owner = '{user}'",);
    } else {
        query =
            format!("{query} WHERE (objects.owner = '{user}' OR read_access.userid = '{user}')");
    }

    if let Some(state) = state {
        query = format!("{query} AND state = '{state}'");
    }

    if let Some(attributes) = attributes {
        // CryptographicAlgorithm
        if let Some(cryptographic_algorithm) = attributes.cryptographic_algorithm {
            query = format!(
                "{query} AND {} = '{cryptographic_algorithm}'",
                P::extract_text_from_key_block_path("CryptographicAlgorithm")
            );
        };

        // CryptographicLength
        if let Some(cryptographic_length) = attributes.cryptographic_length {
            query = format!(
                "{query} AND CAST ({} AS {}) = {cryptographic_length}",
                P::extract_text_from_key_block_path("CryptographicLength"),
                P::TYPE_INTEGER
            );
        };

        // KeyFormatType
        if let Some(key_format_type) = attributes.key_format_type {
            query = format!(
                "{query} AND {} = '{key_format_type}'",
                P::extract_text_from_key_block_path("KeyFormatType")
            );
        };

        // ObjectType
        if let Some(object_type) = attributes.object_type {
            query = format!(
                "{query} AND {} = '{object_type}'",
                P::extract_text_from_object_type_path()
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
    query
}
