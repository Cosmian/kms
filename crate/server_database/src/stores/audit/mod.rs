//! `PostgreSQL` audit backend: [`PgAuditSink`] (write path, used by the server's audit
//! writer task) and [`PgAuditReader`] (read-only path, used by `ckms audit export|verify`).
//!
//! Kept separate from `stores::sql`: the object store's `PgPool` speaks `ObjectsStore` /
//! `PermissionsStore`; this module speaks `cosmian_kms_interfaces::AuditSink`. Both reuse
//! the URL-parsing and retry helpers in `stores::sql::pgsql` — see `pgsql.rs`'s imports —
//! but never the object store's own schema-bootstrap code, since the two tables have
//! nothing in common and must not risk merge conflicts with each other's migrations.

mod pgsql;
mod row;

pub use pgsql::{PgAuditReader, PgAuditSink};

use std::sync::LazyLock;

use rawsql::Loader;

const AUDIT_FILE_QUERIES: &str = include_str!("audit.sql");

static AUDIT_QUERIES: LazyLock<Loader> = LazyLock::new(|| {
    // SAFETY: the SQL file is included at compile time and is valid.
    #[expect(clippy::expect_used)]
    Loader::get_queries_from(AUDIT_FILE_QUERIES).expect("Can't parse the audit SQL file")
});

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::AUDIT_QUERIES;

    /// The KMS must only ever append to `kms_audit_events` (or run pure schema-migration
    /// DDL). Any data-mutating verb (`UPDATE`/`DELETE`/`TRUNCATE`) reaching the runtime
    /// query set is a correctness bug that no amount of database-side hardening
    /// (append-only triggers, `REVOKE`) should be relied upon alone to catch.
    #[test]
    fn runtime_sql_bundle_never_mutates_or_deletes_rows() {
        for (name, sql) in AUDIT_QUERIES.iter() {
            let upper = sql.to_ascii_uppercase();
            assert!(
                !upper.contains("DELETE FROM"),
                "query '{name}' must never delete rows: {sql}"
            );
            // "UPDATE"/"TRUNCATE" appear legitimately in DDL ("BEFORE UPDATE ON ...",
            // "REVOKE UPDATE, ..., TRUNCATE ..."), so only reject a genuine statement
            // that starts with one of these verbs.
            let trimmed = upper.trim_start();
            assert!(
                !trimmed.starts_with("UPDATE ") && !trimmed.starts_with("TRUNCATE "),
                "query '{name}' must never be an UPDATE/TRUNCATE statement: {sql}"
            );
        }
    }

    #[test]
    fn all_queries_referenced_by_pgsql_rs_exist() {
        for name in [
            "create-table-audit-events",
            "add-column-audit-events-details",
            "create-index-audit-events-timestamp",
            "create-audit-append-only-guard",
            "create-audit-trigger-no-update",
            "create-audit-trigger-no-update-create",
            "create-audit-trigger-no-delete",
            "create-audit-trigger-no-delete-create",
            "create-audit-revoke-mutations",
            "select-audit-schema-columns",
            "select-audit-advisory-lock",
            "insert-audit-event",
            "select-audit-events-page",
            "select-audit-instances",
            "select-audit-event-row-hash",
        ] {
            assert!(
                AUDIT_QUERIES.get(name).is_some(),
                "query '{name}' referenced by pgsql.rs is missing from audit.sql"
            );
        }
    }
}
