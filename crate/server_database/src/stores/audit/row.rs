//! `AuditEvent` <-> `tokio_postgres::Row` codec shared by `PgAuditSink` (write path, `resume()`
//! only) and `PgAuditReader` (read path), so the read and write representations cannot drift.

use cosmian_kms_access::audit::{AuditEvent, AuditResult};
use cosmian_kms_interfaces::{InterfaceError, InterfaceResult};
use tokio_postgres::Row;
use uuid::Uuid;

/// Rebuilds an `AuditEvent` from a row produced by any `select-audit-chain-head` /
/// `select-audit-events` query. Column order must match the `SELECT` list in `audit.sql`.
pub(super) fn event_from_row(row: &Row) -> InterfaceResult<AuditEvent> {
    let result_str: String = row.get("result");
    let result = AuditResult::from_canonical_str(&result_str).ok_or_else(|| {
        InterfaceError::Db(format!("audit: unparseable result column: {result_str}"))
    })?;

    let prev_hash: Vec<u8> = row.get("prev_hash");
    let row_hash: Vec<u8> = row.get("row_hash");
    let prev_hash: [u8; 32] = prev_hash
        .try_into()
        .map_err(|_e| InterfaceError::Db("audit: prev_hash column is not 32 bytes".to_owned()))?;
    let row_hash: [u8; 32] = row_hash
        .try_into()
        .map_err(|_e| InterfaceError::Db("audit: row_hash column is not 32 bytes".to_owned()))?;

    let duration_ms: i64 = row.get("duration_ms");
    let duration_ms = u64::try_from(duration_ms).unwrap_or(0);

    Ok(AuditEvent {
        id: row.get("id"),
        timestamp: row.get("timestamp"),
        operation: row.get("operation"),
        user: row.get("username"),
        object_uid: row.get("object_uid"),
        algorithm: row.get("algorithm"),
        client_ip: row.get("client_ip"),
        result,
        duration_ms,
        request_id: row.get::<_, Option<Uuid>>("request_id"),
        prev_hash,
        row_hash,
    })
}
