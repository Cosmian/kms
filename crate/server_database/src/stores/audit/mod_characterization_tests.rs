//! Characterization tests pinning that the embedded audit SQL bundle parses.

use super::AUDIT_QUERIES;

#[test]
fn characterization_audit_queries_parse_and_expose_queries() {
    for name in ["create-table-audit-events", "insert-audit-event"] {
        assert!(!AUDIT_QUERIES.get(name).unwrap().trim().is_empty());
    }
    assert!(AUDIT_QUERIES.get("no-such-query").is_none());
}
