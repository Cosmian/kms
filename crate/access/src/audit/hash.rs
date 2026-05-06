use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;

use super::event::AuditEventFull;

/// Builds the deterministic, NUL-delimited binary representation of `event`
/// that is fed into the SHA-256 digest.
///
/// Layout (concatenation without length prefixes):
/// ```text
/// prev_hash (32 bytes, raw)
/// || id     (8 bytes, big-endian i64)
/// || timestamp in RFC 3339 / ISO 8601 (UTF-8 bytes)
/// || NUL (0x00)
/// || operation (UTF-8)
/// || NUL
/// || user (UTF-8)
/// || NUL
/// || object_uid or "" (UTF-8)
/// || NUL
/// || algorithm or "" (UTF-8)
/// || NUL
/// || client_ip or "" (UTF-8)
/// || NUL
/// || result canonical string (UTF-8, e.g. "Success" / "Failure:401 …")
/// || NUL
/// || duration_ms (8 bytes, big-endian u64)
/// ```
pub(crate) fn canonical_bytes(event: &AuditEventFull) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    buf.extend_from_slice(&event.prev_hash);
    buf.extend_from_slice(&event.id.to_be_bytes());

    let ts = event
        .timestamp
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    buf.extend_from_slice(ts.as_bytes());
    buf.push(0x00);

    buf.extend_from_slice(event.operation.as_bytes());
    buf.push(0x00);

    buf.extend_from_slice(event.user.as_bytes());
    buf.push(0x00);

    buf.extend_from_slice(event.object_uid.as_deref().unwrap_or("").as_bytes());
    buf.push(0x00);

    buf.extend_from_slice(event.algorithm.as_deref().unwrap_or("").as_bytes());
    buf.push(0x00);

    buf.extend_from_slice(event.client_ip.as_deref().unwrap_or("").as_bytes());
    buf.push(0x00);

    buf.extend_from_slice(event.result.as_canonical_str().as_bytes());
    buf.push(0x00);

    buf.extend_from_slice(&event.duration_ms.to_be_bytes());

    buf
}

/// Computes the SHA-256 digest over the canonical byte form of `event`.
/// The returned hash should be stored as `event.row_hash`.
#[must_use]
pub fn compute_row_hash(event: &AuditEventFull) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical_bytes(event));
    hasher.finalize().into()
}

/// Returns `true` when `event.row_hash` matches the SHA-256 of its own
/// canonical bytes.
#[must_use]
pub fn verify_event(event: &AuditEventFull) -> bool {
    let expected = compute_row_hash(event);
    expected == event.row_hash
}

/// Verifies that the hash-chain link from `prev` to `current` is intact.
///
/// * If `prev` is `None` the row must be the first row
///   (`current.prev_hash == [0u8; 32]` AND `current.id == 0`).
/// * Otherwise `current.prev_hash` must equal `prev.row_hash`.
///
/// Note: this function does **not** call [`verify_event`]; call that
/// separately to check the row's own integrity.
#[must_use]
pub fn verify_chain_link(current: &AuditEventFull, prev: Option<&AuditEventFull>) -> bool {
    prev.map_or_else(
        || current.id == 0 && current.prev_hash == [0_u8; 32],
        |p| current.prev_hash == p.row_hash,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::unseparated_literal_suffix)]
mod tests {
    use time::OffsetDateTime;

    use super::super::event::{AuditEventFull, AuditResult};
    use super::{canonical_bytes, compute_row_hash, verify_chain_link, verify_event};

    fn make_event(id: i64, prev_hash: [u8; 32], result: AuditResult) -> AuditEventFull {
        let mut ev = AuditEventFull {
            id,
            timestamp: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            operation: "Encrypt".to_owned(),
            user: "alice@example.com".to_owned(),
            object_uid: Some("obj-1234".to_owned()),
            algorithm: Some("AES-256-GCM".to_owned()),
            client_ip: Some("127.0.0.1".to_owned()),
            result,
            duration_ms: 10,
            prev_hash,
            row_hash: [0u8; 32],
        };
        ev.row_hash = compute_row_hash(&ev);
        ev
    }

    #[test]
    fn canonical_bytes_deterministic() {
        let ev = make_event(0, [0u8; 32], AuditResult::Success);
        let b1 = canonical_bytes(&ev);
        let b2 = canonical_bytes(&ev);
        assert_eq!(b1, b2);
    }

    #[test]
    fn canonical_bytes_differ_on_operation() {
        let ev1 = make_event(0, [0u8; 32], AuditResult::Success);
        let mut ev2 = ev1.clone();
        ev2.operation = "Decrypt".to_owned();
        assert_ne!(canonical_bytes(&ev1), canonical_bytes(&ev2));
    }

    #[test]
    fn verify_event_ok() {
        let ev = make_event(0, [0u8; 32], AuditResult::Success);
        assert!(verify_event(&ev));
    }

    #[test]
    fn verify_event_detects_tampering() {
        let mut ev = make_event(0, [0u8; 32], AuditResult::Success);
        ev.operation = "Destroy".to_owned(); // tamper after hash was set
        assert!(!verify_event(&ev));
    }

    #[test]
    fn chain_first_row() {
        let ev = make_event(0, [0u8; 32], AuditResult::Success);
        assert!(verify_chain_link(&ev, None));
    }

    #[test]
    fn chain_first_row_wrong_id() {
        let ev = make_event(1, [0u8; 32], AuditResult::Success);
        assert!(!verify_chain_link(&ev, None));
    }

    #[test]
    fn chain_link_valid() {
        let row0 = make_event(0, [0u8; 32], AuditResult::Success);
        let row1 = make_event(1, row0.row_hash, AuditResult::Failure("403".to_owned()));
        assert!(verify_chain_link(&row1, Some(&row0)));
    }

    #[test]
    fn chain_link_broken() {
        let row0 = make_event(0, [0u8; 32], AuditResult::Success);
        let mut row1 = make_event(1, row0.row_hash, AuditResult::Success);
        row1.prev_hash = [0u8; 32]; // break the link
        assert!(!verify_chain_link(&row1, Some(&row0)));
    }
}
