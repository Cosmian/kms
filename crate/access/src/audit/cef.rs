// This file is implemented according to the following spec:
// https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.2/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf
use std::fmt::Write as _;

use time::format_description::well_known::Rfc3339;

use super::event::{AuditEvent, AuditResult};

// CEF severity levels used by this implementation (CEF spec 0.1, header CEF:0)
const SEV_SUCCESS: u8 = 5;
const SEV_AUTH_FAILURE: u8 = 7; // 401 / 403
const SEV_OTHER_FAILURE: u8 = 6;

// Note: no current Rust library currently seems to exist for CEF, hence this implementation is hand-rolled. Tests are pretty heavy.

/// Serialises `event` as a single CEF line (spec 0.1, `CEF:0` header, no trailing newline).
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
pub fn to_cef_line(event: &AuditEvent, kms_version: &str) -> String {
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

    // Extension key=value pairs
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

    if let Some(rid) = &event.request_id {
        let _ = write!(ext, " cs5={} cs5Label=requestId", rid.hyphenated());
    }

    format!("{header}{ext}")
}

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
/// Escapes `\` → `\\`, `|` → `\|`, then newlines — a raw `\n`/`\r` in the
/// operation name would otherwise let an attacker inject a second, forged
/// CEF record into the SIEM stream.
fn escape_header(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Escapes a value for use in a CEF extension field value.
/// Per CEF spec 0.1: `\` → `\\`, then `=` → `\=`, then newlines.
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

    use super::super::event::{AuditEvent, AuditResult};
    use super::{escape_ext_value, escape_header, to_cef_line};
    use crate::audit::hash::compute_row_hash;

    fn make_event(result: AuditResult) -> AuditEvent {
        let mut ev = AuditEvent {
            id: 7,
            timestamp: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            operation: "Encrypt".to_owned(),
            user: "alice@example.com".to_owned(),
            object_uid: Some("obj-1234".to_owned()),
            algorithm: Some("AES-256-GCM".to_owned()),
            client_ip: Some("10.0.1.42".to_owned()),
            result,
            duration_ms: 12,
            request_id: None,
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

    #[test]
    fn cef_line_includes_request_id() {
        use uuid::Uuid;
        let mut ev = make_event(AuditResult::Success);
        let rid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        ev.request_id = Some(rid);
        ev.row_hash = compute_row_hash(&ev);
        let line = to_cef_line(&ev, "5.0.0");
        assert!(
            line.contains("cs5=550e8400-e29b-41d4-a716-446655440000"),
            "expected cs5 in: {line}"
        );
        assert!(
            line.contains("cs5Label=requestId"),
            "expected cs5Label in: {line}"
        );
    }

    #[test]
    fn cef_line_omits_request_id_when_none() {
        let ev = make_event(AuditResult::Success);
        assert!(ev.request_id.is_none());
        let line = to_cef_line(&ev, "5.0.0");
        assert!(
            !line.contains("cs5"),
            "cs5 must be absent when request_id is None: {line}"
        );
    }

    // ── Injection hardening ─────────────────────────────────────────────

    #[test]
    fn escape_ext_value_newline_and_cr() {
        assert_eq!(escape_ext_value("a\nb\rc"), "a\\nb\\rc");
    }

    #[test]
    fn escape_ext_value_pipe_is_not_escaped() {
        // `|` only delimits the CEF header, not extension key=value pairs.
        assert_eq!(escape_ext_value("a|b"), "a|b");
    }

    #[test]
    fn escape_header_newline_and_cr() {
        assert_eq!(escape_header("a\nb\rc"), "a\\nb\\rc");
    }

    #[test]
    fn cef_line_user_with_forged_record_stays_single_line() {
        // A malicious `user` embedding a newline + fake CEF header must not be
        // able to inject a second record into the SIEM stream.
        let mut ev = make_event(AuditResult::Success);
        ev.user = "evil\nCEF:0|Attacker|Forged|1.0|Fake|Fake|10|".to_owned();
        ev.row_hash = compute_row_hash(&ev);
        let line = to_cef_line(&ev, "5.0.0");

        assert!(
            !line.contains('\n'),
            "CEF line must not contain a raw newline: {line}"
        );
        assert!(
            !line.contains('\r'),
            "CEF line must not contain a raw CR: {line}"
        );
        // The forged header text must stay embedded inside the escaped `suser`
        // value, not break out into what a line-oriented parser would treat
        // as a second record.
        assert!(
            line.contains("suser=evil\\nCEF:0|Attacker"),
            "expected escaped user: {line}"
        );
    }

    #[test]
    fn cef_line_object_uid_with_equals_and_pipe_stays_single_field() {
        let mut ev = make_event(AuditResult::Success);
        ev.object_uid = Some("uid=1|extra=field".to_owned());
        ev.row_hash = compute_row_hash(&ev);
        let line = to_cef_line(&ev, "5.0.0");

        assert!(
            line.contains("cs1=uid\\=1|extra\\=field cs1Label=objectUID"),
            "expected escaped '=' in cs1 value: {line}"
        );
    }

    #[test]
    fn cef_line_operation_with_pipe_does_not_break_header_fields() {
        let mut ev = make_event(AuditResult::Success);
        ev.operation = "Fake|Injected|99".to_owned();
        ev.row_hash = compute_row_hash(&ev);
        let line = to_cef_line(&ev, "5.0.0");

        // The embedded `|` must be escaped (`\|`), not left as a raw field
        // separator — otherwise it would shift the severity/extension fields.
        let expected_header =
            "CEF:0|Cosmian|KMS|5.0.0|Fake\\|Injected\\|99|Fake\\|Injected\\|99|5|";
        assert!(
            line.starts_with(expected_header),
            "expected escaped pipes in header, got: {line}"
        );
        assert!(
            line[expected_header.len()..].starts_with("rt="),
            "severity/extension fields must not shift: {line}"
        );
    }
}
