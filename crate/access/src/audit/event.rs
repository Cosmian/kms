use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

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

    /// Inverse of [`Self::as_canonical_str`], used to rebuild an event from database columns.
    ///
    /// Returns `None` for anything that is neither `"Success"` nor `"Failure:…"`. Coercing an
    /// unknown value to a default would change the row's canonical bytes and make a genuine row
    /// look tampered, so an unparseable value must be an error, not a fallback.
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
}

/// Facts that are identical for every audit event produced from one HTTP request.
///
/// Split out from [`AuditEventDraft`] so the single-operation path and the per-`BatchItem`
/// fan-out share one constructor ([`AuditEventDraft::build`]): building the struct literal
/// separately at each call site is how a field added to one path silently goes missing from
/// the other.
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
        }
    }
}

/// Current UTC time truncated to **microsecond** resolution.
///
/// `PostgreSQL` `TIMESTAMPTZ` stores microseconds. Truncating at draft time — rather than losing
/// digits at the sink — keeps the canonical RFC 3339 string, and therefore `row_hash`,
/// byte-identical whichever backend persists the event. Without this a chain written to
/// `PostgreSQL` could not be re-verified from its own columns, and a file-vs-database comparison
/// would report false tampering.
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
        };
        assert_eq!(draft.operation, "Encrypt");
    }

    #[test]
    fn canonical_result_round_trip() {
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
    fn from_canonical_str_rejects_unknown_value() {
        assert_eq!(AuditResult::from_canonical_str("garbage"), None);
        assert_eq!(AuditResult::from_canonical_str(""), None);
    }

    #[test]
    fn audit_now_is_microsecond_truncated() {
        let ts = audit_now();
        assert_eq!(
            ts.nanosecond() % 1_000,
            0,
            "audit_now() must be truncated to microsecond resolution"
        );
    }

    #[test]
    fn build_combines_request_and_operation_context() {
        let req = RequestAuditContext {
            timestamp: OffsetDateTime::now_utc(),
            user: "alice".to_owned(),
            client_ip: Some("127.0.0.1".to_owned()),
            duration_ms: 5,
            request_id: None,
        };
        let op = OperationAuditContext {
            operation: "Encrypt".to_owned(),
            object_uid: Some("obj-1".to_owned()),
            algorithm: Some("AES-256-GCM".to_owned()),
        };
        let draft = AuditEventDraft::build(&req, op, AuditResult::Success);
        assert_eq!(draft.operation, "Encrypt");
        assert_eq!(draft.user, "alice");
        assert_eq!(draft.object_uid.as_deref(), Some("obj-1"));
        assert_eq!(draft.algorithm.as_deref(), Some("AES-256-GCM"));
        assert_eq!(draft.client_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(draft.duration_ms, 5);
        assert!(matches!(draft.result, AuditResult::Success));
    }
}
