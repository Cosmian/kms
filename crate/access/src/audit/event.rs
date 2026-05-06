use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// The finalised, persisted audit event including its hash-chain fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventFull {
    /// Monotonically increasing row counter.
    pub id: i64,
    /// Wall-clock timestamp of the KMIP operation (UTC).
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// KMIP operation name, e.g. "Encrypt", "Create", "Destroy".
    pub operation: String,
    /// Authenticated username / identity, e.g. "alice@example.com".
    pub user: String,
    /// KMIP Unique Identifier of the object involved, if any.
    pub object_uid: Option<String>,
    /// Cryptographic algorithm associated with the operation, if any.
    pub algorithm: Option<String>,
    /// Client IP address as seen by the server, if available.
    pub client_ip: Option<String>,
    /// Whether the operation succeeded or the reason it failed.
    pub result: AuditResult,
    /// Total server-side processing time in milliseconds.
    pub duration_ms: u64,
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
    /// Wall-clock timestamp of the KMIP operation (UTC).
    pub timestamp: OffsetDateTime,
    /// KMIP operation name.
    pub operation: String,
    /// Authenticated username / identity.
    pub user: String,
    /// KMIP Unique Identifier of the object involved, if any.
    pub object_uid: Option<String>,
    /// Cryptographic algorithm, if any.
    pub algorithm: Option<String>,
    /// Client IP address as seen by the server, if available.
    pub client_ip: Option<String>,
    /// Whether the operation succeeded or failed.
    pub result: AuditResult,
    /// Server-side processing time in milliseconds.
    pub duration_ms: u64,
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
        };
        assert_eq!(draft.operation, "Encrypt");
    }
}
