use std::fmt::Write as _;

use time::format_description::well_known::Rfc3339;

use super::event::{AuditEventFull, AuditResult};

// CEF v25 severity levels used by this implementation
const SEV_SUCCESS: u8 = 5;
const SEV_AUTH_FAILURE: u8 = 7; // 401 / 403
const SEV_OTHER_FAILURE: u8 = 6;

/// Serialises `event` as a single CEF v25 line (no trailing newline).
///
/// Format:
/// ```text
/// CEF:0|Cosmian|KMS|<version>|<operation>|<operation>|<severity>|<extension>
/// ```
///
/// Extension fields produced:
/// | Key        | Description                          |
/// |------------|--------------------------------------|
/// `rt`         | Event timestamp (epoch milliseconds) |
/// `suser`      | Authenticated user                   |
/// `src`        | Client IP (omitted if unknown)       |
/// `outcome`    | "Success" or "Failure"               |
/// `reason`     | Failure message (omitted on success) |
/// `act`        | KMIP operation name                  |
/// `cn1`        | Duration in milliseconds             |
/// `cn1Label`   | "durationMs"                         |
/// `cs1`        | Object UID (omitted if unknown)      |
/// `cs1Label`   | "objectUID" (omitted if cs1 absent)  |
/// `cs2`        | Algorithm (omitted if unknown)       |
/// `cs2Label`   | "algorithm" (omitted if cs2 absent)  |
#[must_use]
pub fn to_cef_line(event: &AuditEventFull, kms_version: &str) -> String {
    let severity = cef_severity(&event.result);

    // ── Header fields ────────────────────────────────────────────────────
    // CEF:Version|Device Vendor|Device Product|Device Version|
    //     Device Event Class ID|Name|Severity|
    let header = format!(
        "CEF:0|Cosmian|KMS|{ver}|{class}|{name}|{sev}|",
        ver = escape_header(kms_version),
        class = escape_header(&event.operation),
        name = escape_header(&event.operation),
        sev = severity,
    );

    // ── Extension key=value pairs ────────────────────────────────────────
    let rt_ms = event.timestamp.unix_timestamp() * 1000 + i64::from(event.timestamp.millisecond());

    let mut ext = format!(
        "rt={rt} suser={user}",
        rt = rt_ms,
        user = escape_ext_value(&event.user),
    );

    if let Some(ip) = &event.client_ip {
        let _ = write!(ext, " src={}", escape_ext_value(ip));
    }

    match &event.result {
        AuditResult::Success => {
            ext.push_str(" outcome=Success");
        }
        AuditResult::Failure(msg) => {
            ext.push_str(" outcome=Failure");
            let _ = write!(ext, " reason={}", escape_ext_value(msg));
        }
    }

    let _ = write!(
        ext,
        " act={act} cn1={dur} cn1Label=durationMs",
        act = escape_ext_value(&event.operation),
        dur = event.duration_ms,
    );

    if let Some(uid) = &event.object_uid {
        let _ = write!(ext, " cs1={} cs1Label=objectUID", escape_ext_value(uid));
    }

    if let Some(alg) = &event.algorithm {
        let _ = write!(ext, " cs2={} cs2Label=algorithm", escape_ext_value(alg));
    }

    // Append the event id for easy cross-referencing with the JSONL log
    let _ = write!(ext, " cs3={} cs3Label=auditId", event.id);

    // Append RFC3339 timestamp as a human-readable reference
    let ts_str = event
        .timestamp
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    let _ = write!(ext, " cs4={} cs4Label=timestamp", escape_ext_value(&ts_str));

    format!("{header}{ext}")
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn cef_severity(result: &AuditResult) -> u8 {
    match result {
        AuditResult::Success => SEV_SUCCESS,
        AuditResult::Failure(msg) => {
            if msg.contains("401")
                || msg.contains("403")
                || msg.contains("Unauthorized")
                || msg.contains("Forbidden")
            {
                SEV_AUTH_FAILURE
            } else {
                SEV_OTHER_FAILURE
            }
        }
    }
}

/// Escapes a value for use in the CEF pipe-delimited header.
/// Escapes `\` → `\\` then `|` → `\|`.
fn escape_header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}

/// Escapes a value for use in a CEF extension field value.
/// Per CEF v25 spec: `\` → `\\`, then `=` → `\=`, then newlines.
fn escape_ext_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::unseparated_literal_suffix)]
mod tests {
    use time::OffsetDateTime;

    use super::super::event::{AuditEventFull, AuditResult};
    use super::{escape_ext_value, escape_header, to_cef_line};
    use crate::audit::hash::compute_row_hash;

    fn make_event(result: AuditResult) -> AuditEventFull {
        let mut ev = AuditEventFull {
            id: 7,
            timestamp: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            operation: "Encrypt".to_owned(),
            user: "alice@example.com".to_owned(),
            object_uid: Some("obj-1234".to_owned()),
            algorithm: Some("AES-256-GCM".to_owned()),
            client_ip: Some("10.0.1.42".to_owned()),
            result,
            duration_ms: 12,
            prev_hash: [0u8; 32],
            row_hash: [0u8; 32],
        };
        ev.row_hash = compute_row_hash(&ev);
        ev
    }

    #[test]
    fn cef_line_starts_with_header() {
        let ev = make_event(AuditResult::Success);
        let line = to_cef_line(&ev, "5.0.0");
        assert!(line.starts_with("CEF:0|Cosmian|KMS|5.0.0|Encrypt|Encrypt|5|"));
    }

    #[test]
    fn cef_line_contains_rt() {
        let ev = make_event(AuditResult::Success);
        let line = to_cef_line(&ev, "5.0.0");
        // 1_700_000_000 * 1000 = 1700000000000
        assert!(line.contains("rt=1700000000000"));
    }

    #[test]
    fn cef_line_success_outcome() {
        let ev = make_event(AuditResult::Success);
        let line = to_cef_line(&ev, "5.0.0");
        assert!(line.contains("outcome=Success"));
        assert!(!line.contains("reason="));
    }

    #[test]
    fn cef_line_failure_outcome() {
        let ev = make_event(AuditResult::Failure("401 Unauthorized".to_owned()));
        let line = to_cef_line(&ev, "5.0.0");
        assert!(line.contains("outcome=Failure"));
        assert!(line.contains("reason=401 Unauthorized"));
    }

    #[test]
    fn cef_failure_401_severity_7() {
        let ev = make_event(AuditResult::Failure("401 Unauthorized".to_owned()));
        let line = to_cef_line(&ev, "5.0.0");
        // header has |7| for auth failures
        assert!(line.contains("|7|"));
    }

    #[test]
    fn cef_other_failure_severity_6() {
        let ev = make_event(AuditResult::Failure("Internal error".to_owned()));
        let line = to_cef_line(&ev, "5.0.0");
        assert!(line.contains("|6|"));
    }

    #[test]
    fn cef_line_has_object_uid() {
        let ev = make_event(AuditResult::Success);
        let line = to_cef_line(&ev, "5.0.0");
        assert!(line.contains("cs1=obj-1234"));
        assert!(line.contains("cs1Label=objectUID"));
    }

    #[test]
    fn cef_line_no_object_uid_when_absent() {
        let mut ev = make_event(AuditResult::Success);
        ev.object_uid = None;
        let line = to_cef_line(&ev, "5.0.0");
        assert!(!line.contains("cs1="));
    }

    #[test]
    fn escape_header_pipe() {
        assert_eq!(escape_header("foo|bar"), "foo\\|bar");
    }

    #[test]
    fn escape_ext_value_equals() {
        assert_eq!(escape_ext_value("key=val"), "key\\=val");
    }

    #[test]
    fn escape_ext_value_backslash() {
        assert_eq!(escape_ext_value("a\\b"), "a\\\\b");
    }
}
