// This file is implemented according to the following spec:
// https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.2/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf
use std::fmt::Write as _;

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
/// Extension fields produced (all keys verified against CEF v27 spec):
/// | Key               | CEF full name              | Description                          |
/// |-------------------|----------------------------|--------------------------------------|
/// `rt`                | deviceReceiptTime          | Event timestamp (epoch milliseconds) |
/// `suser`             | sourceUserName             | Authenticated user                   |
/// `src`               | sourceAddress              | Client IP (omitted if unknown)       |
/// `outcome`           | eventOutcome               | "Success" or "Failure"               |
/// `reason`            | reason                     | Failure message (omitted on success) |
/// `act`               | deviceAction               | KMIP operation name                  |
/// `cn1`               | deviceCustomNumber1        | Duration in milliseconds             |
/// `cn1Label`          | deviceCustomNumber1Label   | "durationMs"                         |
/// `cs1`               | deviceCustomString1        | Object UID (omitted if unknown)      |
/// `cs1Label`          | deviceCustomString1Label   | "objectUID" (omitted if cs1 absent)  |
/// `cs2`               | deviceCustomString2        | Algorithm (omitted if unknown)       |
/// `cs2Label`          | deviceCustomString2Label   | "algorithm" (omitted if cs2 absent)  |
/// `externalId`        | externalId                 | Audit record ID (JSONL row index)    |
/// `devicePayloadId`   | devicePayloadId            | Request correlation ID (omitted if none) |
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

    // Audit record ID → standard CEF `externalId` (unique ID from originating device)
    let _ = write!(ext, " externalId={}", event.id);

    // Request correlation ID → standard CEF `devicePayloadId`
    if let Some(rid) = &event.request_id {
        let _ = write!(ext, " devicePayloadId={}", rid.hyphenated());
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
#[allow(
    clippy::unwrap_used,
    clippy::unseparated_literal_suffix,
    clippy::expect_used
)]
mod tests {
    use time::OffsetDateTime;

    use super::{
        super::event::{AuditEvent, AuditResult},
        cef_severity, escape_ext_value, escape_header, to_cef_line,
    };
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
            details: None,
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
    fn cef_line_includes_external_id() {
        let ev = make_event(AuditResult::Success);
        let line = to_cef_line(&ev, "5.0.0");
        assert!(
            line.contains("externalId=7"),
            "expected externalId in: {line}"
        );
    }

    #[test]
    fn cef_line_includes_request_id_as_device_payload_id() {
        use uuid::Uuid;
        let mut ev = make_event(AuditResult::Success);
        let rid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        ev.request_id = Some(rid);
        ev.row_hash = compute_row_hash(&ev);
        let line = to_cef_line(&ev, "5.0.0");
        assert!(
            line.contains("devicePayloadId=550e8400-e29b-41d4-a716-446655440000"),
            "expected devicePayloadId in: {line}"
        );
    }

    #[test]
    fn cef_line_omits_device_payload_id_when_no_request_id() {
        let ev = make_event(AuditResult::Success);
        assert!(ev.request_id.is_none());
        let line = to_cef_line(&ev, "5.0.0");
        assert!(
            !line.contains("devicePayloadId"),
            "devicePayloadId must be absent when request_id is None: {line}"
        );
    }

    #[test]
    fn cef_line_uses_only_standard_cef_keys() {
        // Verify no non-standard custom labels (cs3Label, cs4Label, cs5Label)
        // are emitted — all extension keys must be from the CEF v27 dictionary.
        let ev = make_event(AuditResult::Success);
        let line = to_cef_line(&ev, "5.0.0");
        assert!(
            !line.contains("cs3Label="),
            "cs3Label is not a standard CEF key: {line}"
        );
        assert!(
            !line.contains("cs4Label="),
            "cs4Label is not a standard CEF key: {line}"
        );
        assert!(
            !line.contains("cs5Label="),
            "cs5Label is not a standard CEF key: {line}"
        );
        assert!(
            !line.contains("auditId"),
            "auditId is not a standard CEF key: {line}"
        );
        assert!(
            !line.contains("cs4="),
            "redundant timestamp field must be removed: {line}"
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

    // ── CEF v27 structural compliance ─────────────────────────────────────

    #[test]
    fn cef_header_fields_within_v27_length_limits() {
        let ev = make_event(AuditResult::Success);
        let line = to_cef_line(&ev, "5.0.0");

        // Parse header: CEF:0|vendor|product|version|classId|name|severity
        let header_part = &line[..line.find("|rt=").expect("must have |rt=")];
        let fields: Vec<&str> = header_part.split('|').collect();
        assert_eq!(
            fields.len(),
            7,
            "header must have exactly 7 pipe-delimited fields"
        );

        // Map header positions to CEF field names and their max lengths
        let header_checks: &[(&str, usize)] = &[
            ("deviceVendor", 63),
            ("deviceProduct", 63),
            ("deviceVersion", 31),
            ("deviceEventClassId", 1023),
            ("name", 512),
        ];

        for (i, &(field_name, max_len)) in header_checks.iter().enumerate() {
            let value = fields.get(i + 1).copied().unwrap_or_default();
            assert!(
                value.len() <= max_len,
                "{field_name} length {} exceeds CEF v27 limit {max_len}: {value:?}",
                value.len()
            );
        }
    }

    #[test]
    fn cef_severity_always_in_valid_range() {
        // Success → 5, auth failure → 7, other failure → 6. All within 0–10.
        for (result, expected) in [
            (AuditResult::Success, 5),
            (AuditResult::Failure("401 Unauthorized".to_owned()), 7),
            (AuditResult::Failure("403 Forbidden".to_owned()), 7),
            (AuditResult::Failure("Internal error".to_owned()), 6),
        ] {
            let ev = make_event(result);
            let sev = cef_severity(&ev.result);
            assert_eq!(sev, expected, "unexpected severity for {:?}", ev.result);
            assert!(
                (0..=10).contains(&sev),
                "severity {sev} outside CEF v27 range 0–10"
            );
        }
    }

    #[test]
    fn cef_extension_keys_all_in_v27_dictionary() {
        // Every extension key we emit must exist in the CEF v27 standard dictionary.
        // This is a static assertion: parse the extension part of a CEF line and
        // verify each key.
        let ev = make_event(AuditResult::Success);
        let line = to_cef_line(&ev, "5.0.0");

        let ext_start = line.find("|rt=").expect("must have |rt=") + 1;
        let ext = &line[ext_start..];

        // CEF v27 standard keys we use (subset of the full dictionary)
        let standard_keys: std::collections::HashSet<&str> = [
            "rt",
            "suser",
            "src",
            "outcome",
            "reason",
            "act",
            "cn1",
            "cn1Label",
            "cs1",
            "cs1Label",
            "cs2",
            "cs2Label",
            "externalId",
            "devicePayloadId",
        ]
        .into_iter()
        .collect();

        for pair in ext.split_whitespace() {
            if let Some(key) = pair.split('=').next() {
                assert!(
                    standard_keys.contains(key),
                    "extension key {key:?} is not in the CEF v27 dictionary"
                );
            }
        }
    }

    #[test]
    fn escape_header_round_trip() {
        // escape_header must be invertible: unescaping the output recovers the input.
        let inputs = [
            "simple",
            "with|pipe",
            r"with\backslash",
            "with\nnewline",
            "with\rcarriage",
            "all|together\nand\\more",
        ];
        for input in inputs {
            let escaped = escape_header(input);
            // Unescape: reverse the order of replacements
            let unescaped = escaped
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\|", "|")
                .replace("\\\\", "\\");
            assert_eq!(
                unescaped, input,
                "header escape round-trip failed for {input:?}"
            );
        }
    }

    #[test]
    fn escape_ext_value_round_trip() {
        let inputs = [
            "simple",
            "with=equals",
            r"with\backslash",
            "with\nnewline",
            "with\rcarriage",
            "all=together\nand\\more",
        ];
        for input in inputs {
            let escaped = escape_ext_value(input);
            let unescaped = escaped
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\=", "=")
                .replace("\\\\", "\\");
            assert_eq!(
                unescaped, input,
                "ext escape round-trip failed for {input:?}"
            );
        }
    }
}
