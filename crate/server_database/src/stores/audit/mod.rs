//! `PostgreSQL` audit backend: [`PgAuditSink`] (write path, used by the server's audit writer
//! task) and [`PgAuditReader`] (read-only path, used by `ckms audit export|verify`).
//!
//! Kept separate from `stores::sql`: the object store's `PgPool` speaks `ObjectsStore` /
//! `PermissionsStore`; this module speaks `cosmian_kms_interfaces::AuditSink`. Both reuse the
//! pool/TLS/retry code in `stores::sql::{pg_pool, pg_retry}`.
//!
//! `kms_audit_events` schema (`audit.sql`)
//! =======================================
//! Primary key is the **composite** `(instance_id, id)`, not just `id`: `instance_id` identifies
//! the writing KMS instance, so each instance owns an independent hash chain restarting at
//! `id = 0`. This composite key is what makes a chain fork **impossible**, not just detected —
//! two writers sharing an `instance_id` collide on `INSERT` (`SQLSTATE 23505`) instead of
//! silently diverging. See `PgAuditSink::write_event_once` for how the resulting unique
//! violation is disambiguated from a lost-acknowledgement retry.
//!
//! `audit.sql` deliberately has **no `--` comments inside any multi-line query body**: the
//! `rawsql` loader joins a query's lines with spaces before handing it to `PostgreSQL`, so an
//! inline `--` would comment out everything after it, including the statement's closing `;`.
//! Put rationale here, in Rust doc comments, instead — see the `audit-postgres-backend`
//! instructions file for the incident this guards against.

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

    /// The KMS must only ever append to `kms_audit_events`. Any mutating verb reaching the
    /// runtime query set is a correctness bug that no amount of database-side hardening should
    /// be relied upon to catch.
    #[test]
    fn runtime_sql_bundle_is_append_only() {
        for (name, sql) in AUDIT_QUERIES.iter() {
            if name.starts_with("create-") {
                continue; // DDL: DROP TRIGGER / REVOKE are expected here.
            }
            let upper = sql.to_uppercase();
            for verb in ["UPDATE ", "DELETE ", "TRUNCATE ", "ALTER ", "DROP "] {
                assert!(
                    !upper.contains(verb),
                    "query `{name}` contains `{verb}`: {sql}"
                );
            }
            assert!(
                !upper.contains("ON CONFLICT"),
                "query `{name}` must not upsert"
            );
        }
    }

    /// The append-only guard function and its two triggers must not be truncated by the SQL
    /// loader's "ends at the first line ending in `;`" rule — each is written as a single
    /// physical line specifically to avoid that trap (see the `audit-postgres-backend`
    /// instructions file).
    #[test]
    fn ddl_queries_are_not_truncated() {
        let guard = AUDIT_QUERIES
            .get("create-audit-append-only-guard")
            .expect("query must exist");
        assert!(guard.contains("RAISE EXCEPTION"));
        assert!(guard.trim_end().ends_with("$BODY$;"));

        for name in [
            "create-audit-trigger-no-update-create",
            "create-audit-trigger-no-delete-create",
        ] {
            let sql = AUDIT_QUERIES.get(name).expect("query must exist");
            assert!(sql.contains("EXECUTE FUNCTION kms_audit_reject_mutation()"));
        }
    }

    /// The `rawsql` loader joins a query's lines with spaces before executing it, so an inline
    /// `--` comment inside a multi-line query body silently comments out everything after it —
    /// including the closing `;` — while leaving the file looking perfectly readable. This
    /// caused every DDL statement after the first inline comment to be dropped in an earlier
    /// draft of this file (a `CREATE TABLE` whose column list never reached the database).
    /// Rationale belongs in Rust doc comments instead; enforce that no query body ever contains
    /// a `--` again.
    #[test]
    fn no_query_contains_an_inline_sql_comment() {
        for (name, sql) in AUDIT_QUERIES.iter() {
            assert!(
                !sql.contains("--"),
                "query `{name}` contains an inline SQL comment: {sql}"
            );
        }
    }
}
