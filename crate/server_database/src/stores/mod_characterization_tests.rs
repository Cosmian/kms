//! Characterization tests pinning that the embedded SQL bundles parse and expose the queries.

use super::{MYSQL_QUERIES, PGSQL_QUERIES, SQLITE_QUERIES};

#[test]
fn characterization_embedded_sql_bundles_parse_and_expose_queries() {
    for name in ["select-parameter", "has-row-objects"] {
        assert!(!PGSQL_QUERIES.get(name).unwrap().trim().is_empty());
        assert!(!MYSQL_QUERIES.get(name).unwrap().trim().is_empty());
    }
    assert!(
        !SQLITE_QUERIES
            .get("count-non-destroyed-keys")
            .unwrap()
            .trim()
            .is_empty()
    );
}

#[test]
fn characterization_embedded_sql_unknown_query_is_absent() {
    assert!(PGSQL_QUERIES.get("no-such-query").is_none());
    assert!(MYSQL_QUERIES.get("no-such-query").is_none());
    assert!(SQLITE_QUERIES.get("no-such-query").is_none());
}
