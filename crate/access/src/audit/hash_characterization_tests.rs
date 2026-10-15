//! Characterization tests: canonical byte layout and SHA-256 row hashes of fixed events.

use time::OffsetDateTime;
use uuid::Uuid;

use super::{canonical_bytes, compute_row_hash, verify_chain_link, verify_event};
use crate::audit::event::{AuditEvent, AuditResult};

fn base_event() -> AuditEvent {
    AuditEvent {
        id: 258,
        timestamp: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        operation: "Encrypt".to_owned(),
        user: "alice".to_owned(),
        object_uid: Some("uid-1".to_owned()),
        algorithm: Some("AES".to_owned()),
        client_ip: Some("10.0.0.1".to_owned()),
        result: AuditResult::Failure("401 no".to_owned()),
        duration_ms: 513,
        request_id: None,
        details: None,
        prev_hash: [0xAB_u8; 32],
        row_hash: [0_u8; 32],
    }
}

#[test]
fn characterization_canonical_bytes_base_layout() {
    let bytes = canonical_bytes(&base_event());
    assert_eq!(
        hex::encode(bytes),
        "abababababababababababababababababababababababababababababababab0000000000000102323032332d31312d31345432323a31333a32305a00456e637279707400616c696365007569642d31004145530031302e302e302e31004661696c7572653a343031206e6f000000000000000201"
    );
}

#[test]
fn characterization_canonical_bytes_empty_optionals() {
    let mut ev = base_event();
    ev.object_uid = None;
    ev.algorithm = None;
    ev.client_ip = None;
    ev.result = AuditResult::Success;
    ev.id = -1;
    ev.duration_ms = u64::MAX;
    assert_eq!(
        hex::encode(canonical_bytes(&ev)),
        "ababababababababababababababababababababababababababababababababffffffffffffffff323032332d31312d31345432323a31333a32305a00456e637279707400616c696365000000005375636365737300ffffffffffffffff"
    );
}

#[test]
fn characterization_canonical_bytes_request_id_and_details() {
    let mut ev = base_event();
    ev.request_id = Some(Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef));
    assert_eq!(
        hex::encode(canonical_bytes(&ev)),
        "abababababababababababababababababababababababababababababababab0000000000000102323032332d31312d31345432323a31333a32305a00456e637279707400616c696365007569642d31004145530031302e302e302e31004661696c7572653a343031206e6f0000000000000002010030313233343536372d383961622d636465662d303132332d343536373839616263646566"
    );
    ev.details = Some("{\"k\":1}".to_owned());
    assert_eq!(
        hex::encode(canonical_bytes(&ev)),
        "abababababababababababababababababababababababababababababababab0000000000000102323032332d31312d31345432323a31333a32305a00456e637279707400616c696365007569642d31004145530031302e302e302e31004661696c7572653a343031206e6f0000000000000002010030313233343536372d383961622d636465662d303132332d343536373839616263646566007b226b223a317d"
    );
    ev.request_id = None;
    assert_eq!(
        hex::encode(canonical_bytes(&ev)),
        "abababababababababababababababababababababababababababababababab0000000000000102323032332d31312d31345432323a31333a32305a00456e637279707400616c696365007569642d31004145530031302e302e302e31004661696c7572653a343031206e6f000000000000000201007b226b223a317d"
    );
}

#[test]
fn characterization_compute_row_hash_fixed_events() {
    let mut ev = base_event();
    assert_eq!(
        hex::encode(compute_row_hash(&ev)),
        "aa6dddc73fc5999cb8243375807578bf4193b144844b06ac3c41f036687ef399"
    );
    ev.request_id = Some(Uuid::from_u128(1));
    ev.details = Some("{}".to_owned());
    assert_eq!(
        hex::encode(compute_row_hash(&ev)),
        "f8581386847a2b2ec6cf28c169ca3c3d2b814ff6b03dd55a11b7c6224aa16b9b"
    );
}

#[test]
fn characterization_verify_event_and_chain_with_fixed_hashes() {
    let mut first = base_event();
    first.id = 0;
    first.prev_hash = [0_u8; 32];
    first.row_hash = compute_row_hash(&first);
    assert!(verify_event(&first));
    assert!(verify_chain_link(&first, None));

    let mut second = base_event();
    second.id = 1;
    second.prev_hash = first.row_hash;
    second.row_hash = compute_row_hash(&second);
    assert!(verify_event(&second));
    assert!(verify_chain_link(&second, Some(&first)));
    assert!(!verify_chain_link(&second, None));
    assert!(!verify_chain_link(&first, Some(&second)));

    second.user = "mallory".to_owned();
    assert!(!verify_event(&second));
}
