//! Characterization tests: exact CEF lines and escaping helpers.

use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    super::event::{AuditEvent, AuditResult},
    cef_severity, escape_ext_value, escape_header, to_cef_line, to_cef_line_with_source,
};

fn event(result: AuditResult) -> AuditEvent {
    AuditEvent {
        id: 42,
        timestamp: OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_456_789).unwrap(),
        operation: "Encrypt|Op".to_owned(),
        user: "al=ice\\x".to_owned(),
        object_uid: Some("obj=1\n2".to_owned()),
        algorithm: Some("AES-256-GCM".to_owned()),
        client_ip: Some("10.0.1.42".to_owned()),
        result,
        duration_ms: 12,
        request_id: Some(Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef)),
        details: Some("{\"reason\":\"a=b\"}".to_owned()),
        prev_hash: [0_u8; 32],
        row_hash: [0_u8; 32],
    }
}

fn minimal_event(result: AuditResult) -> AuditEvent {
    AuditEvent {
        id: 0,
        timestamp: OffsetDateTime::from_unix_timestamp(0).unwrap(),
        operation: "Create".to_owned(),
        user: "bob".to_owned(),
        object_uid: None,
        algorithm: None,
        client_ip: None,
        result,
        duration_ms: 0,
        request_id: None,
        details: None,
        prev_hash: [0_u8; 32],
        row_hash: [0_u8; 32],
    }
}

#[test]
fn characterization_to_cef_line_full_success() {
    assert_eq!(
        to_cef_line(&event(AuditResult::Success), "5.1.0|x"),
        r#"CEF:0|Cosmian|KMS|5.1.0\|x|Encrypt\|Op|Encrypt\|Op|5|rt=1700000000123 suser=al\=ice\\x src=10.0.1.42 outcome=Success act=Encrypt|Op cn1=12 cn1Label=durationMs cs1=obj\=1\n2 cs1Label=objectUID cs2=AES-256-GCM cs2Label=algorithm cs3={"reason":"a\=b"} cs3Label=details externalId=42 devicePayloadId=01234567-89ab-cdef-0123-456789abcdef"#
    );
}

#[test]
fn characterization_to_cef_line_full_failure() {
    assert_eq!(
        to_cef_line(
            &event(AuditResult::Failure("403 Forbidden=x".to_owned())),
            "5.1.0"
        ),
        r#"CEF:0|Cosmian|KMS|5.1.0|Encrypt\|Op|Encrypt\|Op|7|rt=1700000000123 suser=al\=ice\\x src=10.0.1.42 outcome=Failure reason=403 Forbidden\=x act=Encrypt|Op cn1=12 cn1Label=durationMs cs1=obj\=1\n2 cs1Label=objectUID cs2=AES-256-GCM cs2Label=algorithm cs3={"reason":"a\=b"} cs3Label=details externalId=42 devicePayloadId=01234567-89ab-cdef-0123-456789abcdef"#
    );
}

#[test]
fn characterization_to_cef_line_minimal_event() {
    assert_eq!(
        to_cef_line(&minimal_event(AuditResult::Success), "1"),
        "CEF:0|Cosmian|KMS|1|Create|Create|5|rt=0 suser=bob outcome=Success act=Create cn1=0 cn1Label=durationMs externalId=0"
    );
}

#[test]
fn characterization_to_cef_line_with_source_full() {
    assert_eq!(
        to_cef_line_with_source(&event(AuditResult::Success), "5.1.0", Some(("inst=1", 3))),
        r#"CEF:0|Cosmian|KMS|5.1.0|Encrypt\|Op|Encrypt\|Op|5|rt=1700000000123 suser=al\=ice\\x src=10.0.1.42 outcome=Success act=Encrypt|Op cn1=12 cn1Label=durationMs cs1=obj\=1\n2 cs1Label=objectUID cs2=AES-256-GCM cs2Label=algorithm cs3={"reason":"a\=b"} cs3Label=details deviceExternalId=inst\=1 cn2=3 cn2Label=chainGeneration externalId=3:42 devicePayloadId=01234567-89ab-cdef-0123-456789abcdef"#
    );
}

#[test]
fn characterization_to_cef_line_with_source_minimal() {
    assert_eq!(
        to_cef_line_with_source(&minimal_event(AuditResult::Success), "1", Some(("i", -1))),
        "CEF:0|Cosmian|KMS|1|Create|Create|5|rt=0 suser=bob outcome=Success act=Create cn1=0 cn1Label=durationMs deviceExternalId=i cn2=-1 cn2Label=chainGeneration externalId=-1:0"
    );
    assert_eq!(
        to_cef_line_with_source(&minimal_event(AuditResult::Success), "1", None),
        to_cef_line(&minimal_event(AuditResult::Success), "1")
    );
}

#[test]
fn characterization_cef_severity_table() {
    assert_eq!(cef_severity(&AuditResult::Success), 5);
    for msg in [
        "401",
        "HTTP 403",
        "Unauthorized",
        "Forbidden",
        "x Forbidden y",
    ] {
        assert_eq!(
            cef_severity(&AuditResult::Failure(msg.to_owned())),
            7,
            "{msg}"
        );
    }
    for msg in ["", "500", "forbidden", "unauthorized", "boom"] {
        assert_eq!(
            cef_severity(&AuditResult::Failure(msg.to_owned())),
            6,
            "{msg}"
        );
    }
}

#[test]
fn characterization_escape_header_table() {
    assert_eq!(escape_header(""), "");
    assert_eq!(escape_header("plain"), "plain");
    assert_eq!(escape_header("a\\b|c=d\ne\rf"), "a\\\\b\\|c=d\\ne\\rf");
}

#[test]
fn characterization_escape_ext_value_table() {
    assert_eq!(escape_ext_value(""), "");
    assert_eq!(escape_ext_value("plain|pipe"), "plain|pipe");
    assert_eq!(escape_ext_value("a\\b|c=d\ne\rf"), "a\\\\b|c\\=d\\ne\\rf");
}
