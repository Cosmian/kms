use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::hash::compute_row_hash;

/// The finalised, persisted audit event including its hash-chain fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonically increasing row counter.
    pub id: i64,
    /// Wall-clock timestamp of the KMIP operation (UTC).
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub operation: String,
    pub user: String,
    pub object_uid: Option<String>,
    pub algorithm: Option<String>,
    pub client_ip: Option<String>,
    pub result: AuditResult,
    pub duration_ms: u64,
    /// Shared across all `BatchItem` drafts produced from the same HTTP request.
    /// `None` only for synthetic events or test fixtures that predate this field.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub request_id: Option<Uuid>,
    /// Structured JSON payload for synthetic recovery rows (torn-write / reanchor sentinels).
    /// `None` for ordinary KMIP audit events. Always a JSON-object string when `Some` — see
    /// `canonical_bytes` for why this shape must never collide with `request_id`'s UUID shape.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub details: Option<String>,
    /// SHA-256 of the previous row (all-zeros for the first row).
    #[serde(with = "hex::serde")]
    pub prev_hash: [u8; 32],
    /// SHA-256 of the canonical byte representation of this row.
    #[serde(with = "hex::serde")]
    pub row_hash: [u8; 32],
}

/// Outcome of a KMIP operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditResult {
    /// The operation completed successfully.
    Success,
    /// The operation failed; the inner string contains the reason.
    Failure(String),
}

impl AuditResult {
    /// Returns a stable string representation used in the hash canonical form.
    #[must_use]
    pub fn as_canonical_str(&self) -> String {
        match self {
            Self::Success => "Success".to_owned(),
            Self::Failure(msg) => format!("Failure:{msg}"),
        }
    }

    /// Inverse of [`Self::as_canonical_str`], used to rebuild an event from a persisted
    /// column (e.g. a `PostgreSQL` row) instead of a JSONL line's own enum encoding.
    ///
    /// Returns `None` for anything that is neither `"Success"` nor `"Failure:…"`. Coercing
    /// an unparseable value to a default would change the row's canonical bytes and make a
    /// genuine row look tampered, so an unparseable value must be an error, not a fallback.
    #[must_use]
    pub fn from_canonical_str(s: &str) -> Option<Self> {
        match s {
            "Success" => Some(Self::Success),
            _ => s
                .strip_prefix("Failure:")
                .map(|m| Self::Failure(m.to_owned())),
        }
    }

    /// Returns `true` if the operation succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

/// The subset of audit data available at request time, before the hash chain
/// fields (`id`, `prev_hash`, `row_hash`) are assigned by the writer task.
#[derive(Debug, Clone)]
pub struct AuditEventDraft {
    pub timestamp: OffsetDateTime,
    pub operation: String,
    pub user: String,
    pub object_uid: Option<String>,
    pub algorithm: Option<String>,
    pub client_ip: Option<String>,
    pub result: AuditResult,
    pub duration_ms: u64,
    /// Shared across all `BatchItem` drafts from the same HTTP request.
    pub request_id: Option<Uuid>,
    /// Structured JSON payload for synthetic recovery rows. `None` for ordinary events.
    pub details: Option<String>,
}

/// Facts that are identical for every audit event produced from one HTTP request.
///
/// Split out from [`AuditEventDraft`] so the single-operation path and the per-`BatchItem`
/// fan-out share one constructor ([`AuditEventDraft::build`]): building the struct literal
/// separately at each call site is how a field added to one path silently goes missing
/// from the other.
#[derive(Debug, Clone)]
pub struct RequestAuditContext {
    pub timestamp: OffsetDateTime,
    pub user: String,
    pub client_ip: Option<String>,
    pub duration_ms: u64,
    /// Shared by every event fanned out from the same request, so a batch can be
    /// reassembled from the log.
    pub request_id: Option<Uuid>,
}

/// Facts specific to one KMIP operation — a whole single-op request, or one `BatchItem`.
#[derive(Debug, Clone, Default)]
pub struct OperationAuditContext {
    pub operation: String,
    pub object_uid: Option<String>,
    pub algorithm: Option<String>,
}

impl AuditEventDraft {
    /// Combines the per-request facts with one operation's facts and its outcome.
    ///
    /// `details` is always `None` here: it exists only for synthetic recovery rows
    /// (torn-write / reanchor sentinels) that the writer builds internally, never for
    /// ordinary request-driven events.
    #[must_use]
    pub fn build(
        req: &RequestAuditContext,
        op: OperationAuditContext,
        result: AuditResult,
    ) -> Self {
        Self {
            timestamp: req.timestamp,
            operation: op.operation,
            user: req.user.clone(),
            object_uid: op.object_uid,
            algorithm: op.algorithm,
            client_ip: req.client_ip.clone(),
            result,
            duration_ms: req.duration_ms,
            request_id: req.request_id,
            details: None,
        }
    }

    /// Assigns the hash-chain fields to turn this draft into a persistable [`AuditEvent`],
    /// computing `row_hash` over the canonical bytes (including `prev_hash`).
    ///
    /// Shared by every backend's writer so the same draft, `id`, and `prev_hash` always
    /// yield byte-identical canonical hashes regardless of which sink persists it — see
    /// `audit_now`'s microsecond truncation, which this depends on.
    #[must_use]
    pub fn finalize(self, id: i64, prev_hash: [u8; 32]) -> AuditEvent {
        let mut event = AuditEvent {
            id,
            timestamp: self.timestamp,
            operation: self.operation,
            user: self.user,
            object_uid: self.object_uid,
            algorithm: self.algorithm,
            client_ip: self.client_ip,
            result: self.result,
            duration_ms: self.duration_ms,
            request_id: self.request_id,
            details: self.details,
            prev_hash,
            row_hash: [0_u8; 32],
        };
        event.row_hash = compute_row_hash(&event);
        event
    }
}

/// Current UTC time truncated to **microsecond** resolution.
///
/// `PostgreSQL` `TIMESTAMPTZ` stores microseconds. Truncating at draft time — rather than
/// losing digits at the sink — keeps the canonical RFC 3339 string, and therefore
/// `row_hash`, byte-identical whichever backend persists the event. Without this a chain
/// written to `PostgreSQL` could not be re-verified from its own columns, and a
/// file-vs-database comparison of the same event would report false tampering.
#[must_use]
pub fn audit_now() -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond((now.nanosecond() / 1_000) * 1_000)
        .unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::{
        AuditEventDraft, AuditResult, OperationAuditContext, RequestAuditContext, audit_now,
    };
    use crate::audit::hash::verify_event;

    #[test]
    fn canonical_str_success() {
        assert_eq!(AuditResult::Success.as_canonical_str(), "Success");
    }

    #[test]
    fn canonical_str_failure() {
        assert_eq!(
            AuditResult::Failure("401 Unauthorized".to_owned()).as_canonical_str(),
            "Failure:401 Unauthorized"
        );
    }

    #[test]
    fn canonical_str_round_trip() {
        for result in [
            AuditResult::Success,
            AuditResult::Failure("401 Unauthorized".to_owned()),
            AuditResult::Failure(String::new()),
        ] {
            let s = result.as_canonical_str();
            assert_eq!(AuditResult::from_canonical_str(&s), Some(result));
        }
    }

    #[test]
    fn from_canonical_str_rejects_unparseable() {
        assert_eq!(AuditResult::from_canonical_str("garbage"), None);
        assert_eq!(AuditResult::from_canonical_str(""), None);
    }

    #[test]
    fn draft_creation() {
        let draft = AuditEventDraft {
            timestamp: OffsetDateTime::now_utc(),
            operation: "Encrypt".to_owned(),
            user: "alice@example.com".to_owned(),
            object_uid: Some("obj-1234".to_owned()),
            algorithm: Some("AES-256-GCM".to_owned()),
            client_ip: Some("127.0.0.1".to_owned()),
            result: AuditResult::Success,
            duration_ms: 5,
            request_id: None,
            details: None,
        };
        assert_eq!(draft.operation, "Encrypt");
    }

    #[test]
    fn build_combines_request_and_operation_context() {
        use uuid::Uuid;

        let req = RequestAuditContext {
            timestamp: OffsetDateTime::now_utc(),
            user: "alice@example.com".to_owned(),
            client_ip: Some("127.0.0.1".to_owned()),
            duration_ms: 5,
            request_id: Some(Uuid::new_v4()),
        };
        let op = OperationAuditContext {
            operation: "Encrypt".to_owned(),
            object_uid: Some("obj-1234".to_owned()),
            algorithm: Some("AES-256-GCM".to_owned()),
        };
        let draft = AuditEventDraft::build(&req, op, AuditResult::Success);

        assert_eq!(draft.timestamp, req.timestamp);
        assert_eq!(draft.user, req.user);
        assert_eq!(draft.client_ip, req.client_ip);
        assert_eq!(draft.duration_ms, req.duration_ms);
        assert_eq!(draft.request_id, req.request_id);
        assert_eq!(draft.operation, "Encrypt");
        assert_eq!(draft.object_uid.as_deref(), Some("obj-1234"));
        assert_eq!(draft.algorithm.as_deref(), Some("AES-256-GCM"));
        assert!(matches!(draft.result, AuditResult::Success));
        assert!(draft.details.is_none());
    }

    #[test]
    fn build_shares_request_context_across_batch_items() {
        let req = RequestAuditContext {
            timestamp: OffsetDateTime::now_utc(),
            user: "bob@example.com".to_owned(),
            client_ip: None,
            duration_ms: 12,
            request_id: None,
        };
        let first = AuditEventDraft::build(
            &req,
            OperationAuditContext {
                operation: "Encrypt".to_owned(),
                ..Default::default()
            },
            AuditResult::Success,
        );
        let second = AuditEventDraft::build(
            &req,
            OperationAuditContext {
                operation: "Decrypt".to_owned(),
                ..Default::default()
            },
            AuditResult::Failure("403 Forbidden".to_owned()),
        );

        assert_eq!(first.request_id, second.request_id);
        assert_eq!(first.timestamp, second.timestamp);
        assert_eq!(first.user, second.user);
        assert_ne!(first.operation, second.operation);
    }

    #[test]
    fn audit_now_truncates_to_microseconds() {
        let ts = audit_now();
        assert_eq!(ts.nanosecond() % 1_000, 0);
    }

    #[test]
    fn finalize_assigns_chain_fields_and_verifies() {
        let draft = AuditEventDraft {
            timestamp: audit_now(),
            operation: "Encrypt".to_owned(),
            user: "alice@example.com".to_owned(),
            object_uid: Some("obj-1234".to_owned()),
            algorithm: Some("AES-256-GCM".to_owned()),
            client_ip: Some("127.0.0.1".to_owned()),
            result: AuditResult::Success,
            duration_ms: 5,
            request_id: None,
            details: None,
        };
        let prev_hash = [0xAB_u8; 32];
        let event = draft.finalize(7, prev_hash);

        assert_eq!(event.id, 7);
        assert_eq!(event.prev_hash, prev_hash);
        assert_eq!(event.operation, "Encrypt");
        assert!(
            verify_event(&event),
            "finalize() must produce a self-consistent row_hash"
        );
    }

    #[test]
    fn finalize_is_deterministic_for_identical_input() {
        let draft = AuditEventDraft {
            timestamp: audit_now(),
            operation: "Decrypt".to_owned(),
            user: "bob@example.com".to_owned(),
            object_uid: None,
            algorithm: None,
            client_ip: None,
            result: AuditResult::Success,
            duration_ms: 1,
            request_id: None,
            details: None,
        };
        let a = draft.clone().finalize(0, [0_u8; 32]);
        let b = draft.finalize(0, [0_u8; 32]);
        assert_eq!(
            a.row_hash, b.row_hash,
            "same draft/id/prev_hash must yield the same canonical row_hash across backends"
        );
    }
}
