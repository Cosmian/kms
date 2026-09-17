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

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use super::{AuditEventDraft, AuditResult};

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
            details: None,
        };
        assert_eq!(draft.operation, "Encrypt");
    }
}
