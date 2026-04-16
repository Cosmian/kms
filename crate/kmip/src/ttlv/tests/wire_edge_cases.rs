//! Edge-case and adversarial tests for the binary TTLV (wire) deserializer.
//!
//! Coverage areas:
//!   W1-W5   : Truncated / empty payloads
//!   W6-W8   : Invalid header fields
//!   W9-W11  : Structure length / child overflow (regression for remaining -= underflow)
//!   W12-W14 : Depth limit enforcement
//!   W15-W18 : Scalar type length checks
//!   W19-W21 : `BigInteger` / `ByteString` / `TextString` malformed values
//!   W22-W24 : `DateTime` / `Interval` / `DateTimeExtended` edge values
//!   W25     : Round-trip: maximum valid depth (64 levels)

use crate::ttlv::{KmipFlavor, TTLV, TTLVBytesDeserializer, TTLVBytesSerializer};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal valid Integer item encoded in TTLV binary format.
///
/// Layout: [tag 3B][type 1B][length 4B][value 4B][padding 4B] = 16 bytes total.
///
/// Uses tag `0x42_000D` (`BatchCount`), type 0x02 (Integer), length=4, value=1.
fn integer_item() -> Vec<u8> {
    vec![
        0x42, 0x00, 0x0D, // tag: BatchCount
        0x02, // type: Integer
        0x00, 0x00, 0x00, 0x04, // length: 4
        0x00, 0x00, 0x00, 0x01, // value: 1
        0x00, 0x00, 0x00, 0x00, // padding: 4 zero bytes
    ]
}

/// Build a TTLV Structure header (8 bytes) claiming the given `content_len`.
fn structure_header(tag: [u8; 3], content_len: u32) -> Vec<u8> {
    let mut h = vec![tag[0], tag[1], tag[2], 0x01]; // type = Structure
    h.extend_from_slice(&content_len.to_be_bytes());
    h
}

/// Build a complete well-formed Structure containing one Integer child.
///
/// The structure uses tag `0x42_007B` (`RequestMessage`), enclosing one `BatchCount` Integer.
#[allow(dead_code)]
fn valid_structure_with_integer() -> Vec<u8> {
    let child = integer_item(); // 16 bytes
    let mut buf = structure_header([0x42, 0x00, 0x7B], child.len() as u32);
    buf.extend_from_slice(&child);
    buf
}

/// Build `depth` nested Structures (tag `0x42_007B`), each wrapping the next.
/// The innermost Structure contains a single `BatchCount` Integer leaf.
///
/// This mirrors how `build_nested_structure` works in the deserializer test:
/// `depth` wrapper levels mean the leaf is parsed at `depth`, so
/// `nested_structures(MAX_TTLV_DEPTH)` is the last that succeeds.
fn nested_structures(depth: usize) -> Vec<u8> {
    // Innermost: an empty Structure (leaf equivalent, length=0)
    let leaf = integer_item(); // 16 bytes; the leaf is an Integer inside no extra wrapper

    // Start from the inside: one empty structure containing the Integer leaf.
    let inner_content = leaf;
    let mut inner: Vec<u8> = structure_header([0x42, 0x00, 0x7B], inner_content.len() as u32);
    inner.extend_from_slice(&inner_content);

    // Wrap `depth - 1` more times (total: `depth` Structure headers are present)
    for _ in 1..depth {
        let content_len = inner.len() as u32;
        let mut outer = structure_header([0x42, 0x00, 0x7B], content_len);
        outer.extend_from_slice(&inner);
        inner = outer;
    }
    inner
}

// ---------------------------------------------------------------------------
// W1: Empty input → error (cannot read even 8-byte header)
// ---------------------------------------------------------------------------
#[test]
fn w01_empty_input() {
    let result = TTLV::from_bytes(&[], KmipFlavor::Kmip1);
    assert!(result.is_err(), "empty input must fail");
}

// ---------------------------------------------------------------------------
// W2: Truncated at 4 bytes (partial header)
// ---------------------------------------------------------------------------
#[test]
fn w02_truncated_four_bytes() {
    // Only 4 bytes: tag(3) + type(1), missing length(4) and value
    let data = [0x42, 0x00, 0x7B, 0x02];
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(result.is_err(), "partial header must fail");
}

// ---------------------------------------------------------------------------
// W3: Truncated at 7 bytes (tag + type + 3 of 4 length bytes)
// ---------------------------------------------------------------------------
#[test]
fn w03_truncated_seven_bytes() {
    let data = [0x42, 0x00, 0x7B, 0x02, 0x00, 0x00, 0x00];
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(result.is_err(), "7-byte partial header must fail");
}

// ---------------------------------------------------------------------------
// W4: Valid 8-byte header for Integer, but value bytes are missing
// ---------------------------------------------------------------------------
#[test]
fn w04_header_only_no_value() {
    // Integer header: tag, type=0x02(Integer), length=4; value is absent
    let data = [0x42, 0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x04];
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(result.is_err(), "missing Integer value must fail");
}

// ---------------------------------------------------------------------------
// W5: Invalid type byte 0xFF
// ---------------------------------------------------------------------------
#[test]
fn w05_invalid_type_byte() {
    let data = [
        0x42, 0x00, 0x7B, // tag
        0xFF, // invalid type
        0x00, 0x00, 0x00, 0x08, // length
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(result.is_err(), "invalid type 0xFF must fail");
}

// ---------------------------------------------------------------------------
// W6: Invalid tag prefix (0x00 instead of 0x42)
// ---------------------------------------------------------------------------
#[test]
fn w06_invalid_tag_prefix() {
    let data = [
        0x00, 0x00, 0x7B, // tag: invalid (not in 0x42xxxx range)
        0x02, // type: Integer
        0x00, 0x00, 0x00, 0x04, // length: 4
        0x00, 0x00, 0x00, 0x01, // value
        0x00, 0x00, 0x00, 0x00, // padding
    ];
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(result.is_err(), "tag with invalid prefix must fail");
}

// ---------------------------------------------------------------------------
// W7: Type byte 0x00 (zero, before first valid type 0x01=Structure)
// ---------------------------------------------------------------------------
#[test]
fn w07_type_byte_zero() {
    let data = [
        0x42, 0x00, 0x7B, 0x00, // type=0x00 invalid
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(result.is_err(), "type byte 0x00 must fail");
}

// ---------------------------------------------------------------------------
// W8: Type byte 0x0C (above DateTimeExtended=0x0B, the highest valid type)
// ---------------------------------------------------------------------------
#[test]
fn w08_type_byte_above_max() {
    let data = [
        0x42, 0x00, 0x7B, 0x0C, // 0x0C does not map to any TtlvType
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(result.is_err(), "type byte 0x0C must fail");
}

// ---------------------------------------------------------------------------
// W9: Structure with correct parent length, but child data is truncated
// ---------------------------------------------------------------------------
#[test]
fn w09_structure_child_truncated() {
    // Parent claims length=16 (room for one Integer), but only child header present (8 bytes)
    let mut data = structure_header([0x42, 0x00, 0x7B], 16);
    // Only 8 bytes of child header, value/padding missing
    data.extend_from_slice(&[0x42, 0x00, 0x0D, 0x02, 0x00, 0x00, 0x00, 0x04]);
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(
        result.is_err(),
        "truncated child inside structure must fail"
    );
}

// ---------------------------------------------------------------------------
// W10: Child item_length exceeds remaining parent bytes — overflow regression
//
// Parent claims length=8; the Integer child has item_length=16 (8 hdr + 8 value).
// Before the fix `remaining -= item_length` would panic (debug) or wrap (release).
// After the fix it must return a clean error.
// ---------------------------------------------------------------------------
#[test]
fn w10_child_exceeds_parent_remaining() {
    // Parent Structure: tag=0x42007B, type=0x01, length=8 (too small for one Integer)
    let mut data = structure_header([0x42, 0x00, 0x7B], 8);
    // One full Integer child (16 bytes): tag=0x42000D, type=Integer, len=4, value+pad=8
    data.extend_from_slice(&integer_item());
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(
        result.is_err(),
        "child length exceeding parent remaining must fail, not wrap"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("exceeds remaining") || msg.contains("malformed"),
        "error should mention malformed structure, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// W11: Structure length=0 with one child present — child should be parsed
//       because remaining=0 immediately → loop exits and child bytes are ignored;
//       then the outer stream still has extra bytes.  The call itself succeeds
//       (one Structure is returned) but child is simply not read inside.
//       Mostly a documentation/regression test for the parsing boundary.
// ---------------------------------------------------------------------------
#[test]
fn w11_structure_length_zero_with_extra_bytes() {
    // Empty structure (length=0), followed by trailing Integer bytes
    let mut data = structure_header([0x42, 0x00, 0x7B], 0);
    data.extend_from_slice(&integer_item()); // 16 trailing bytes not part of structure
    // from_bytes reads ONE item, so the structure with length=0 should parse fine
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(
        result.is_ok(),
        "empty structure (length=0) should parse successfully"
    );
}

// ---------------------------------------------------------------------------
// W12: Depth limit — exactly at limit (64 levels) must succeed
// ---------------------------------------------------------------------------
#[test]
fn w12_depth_exactly_at_limit() {
    use crate::ttlv::MAX_TTLV_DEPTH;
    let depth = MAX_TTLV_DEPTH as usize;
    let data = nested_structures(depth);
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(
        result.is_ok(),
        "depth={depth} must succeed (at limit), got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// W13: Depth limit — one level over limit (65 levels) must fail
// ---------------------------------------------------------------------------
#[test]
fn w13_depth_one_over_limit() {
    use crate::ttlv::MAX_TTLV_DEPTH;
    let depth = (MAX_TTLV_DEPTH + 1) as usize;
    let data = nested_structures(depth);
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(
        result.is_err(),
        "depth={depth} must fail (over limit), but succeeded"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("depth") || msg.contains("maximum"),
        "error should mention depth limit, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// W14: Extreme depth (1000 levels) — must fail gracefully (no stack overflow)
// ---------------------------------------------------------------------------
#[test]
fn w14_extreme_depth_no_stack_overflow() {
    let data = nested_structures(1000);
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(
        result.is_err(),
        "depth=1000 must fail, not overflow the call stack"
    );
}

// ---------------------------------------------------------------------------
// W15: Integer with wrong length declared (not 4) — parser reads 4 bytes anyway,
//       but the extra bytes will be left in the stream; the caller does not check
//       alignment for single-item reads, so this is an informational test.
//       We verify the parser does not panic (returns a value or error).
// ---------------------------------------------------------------------------
#[test]
fn w15_integer_declared_length_zero() {
    // Integer is always 4+4=8 bytes, independent of the declared length field.
    // Length=0 is technically invalid per KMIP spec but we test parser robustness.
    let data = [
        0x42, 0x00, 0x0D, // tag: BatchCount
        0x02, // type: Integer
        0x00, 0x00, 0x00, 0x00, // length: 0 (wrong per spec, Integer must be 4)
        0x00, 0x00, 0x00, 0x01, // value bytes (will be read as padding by Integer branch)
        0x00, 0x00, 0x00, 0x00,
    ];
    // Either succeeds or fails cleanly — must never panic
    let _result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
}

// ---------------------------------------------------------------------------
// W16: TextString with claimed length larger than available data
// ---------------------------------------------------------------------------
#[test]
fn w16_textstring_truncated_value() {
    let data = [
        0x42, 0x00, 0x0A, // tag: AttributeName
        0x07, // type: TextString
        0x00, 0x00, 0x00, 0x10, // length: 16 bytes
        b'h', b'e', b'l', b'l', b'o', // only 5 bytes available
    ];
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(result.is_err(), "truncated TextString must fail");
}

// ---------------------------------------------------------------------------
// W17: ByteString with claimed length larger than available data
// ---------------------------------------------------------------------------
#[test]
fn w17_bytestring_truncated_value() {
    let data = [
        0x42, 0x00, 0x1E, // tag: CertificateValue
        0x08, // type: ByteString
        0x00, 0x00, 0x00, 0x20, // length: 32
        0xDE, 0xAD, 0xBE, 0xEF, // only 4 bytes available
    ];
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(result.is_err(), "truncated ByteString must fail");
}

// ---------------------------------------------------------------------------
// W18: TextString with valid UTF-8 length and content (happy path regression)
// ---------------------------------------------------------------------------
#[test]
fn w18_textstring_valid_utf8() {
    // "hello" = 5 bytes. Padding to 8-byte boundary = 3 extra bytes.
    let data = [
        0x42, 0x00, 0x0A, // tag: AttributeName
        0x07, // type: TextString
        0x00, 0x00, 0x00, 0x05, // length: 5
        b'h', b'e', b'l', b'l', b'o', // value
        0x00, 0x00, 0x00, // padding: 3 bytes (5 % 8 = 5; pad to next 8 = 3)
    ];
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(result.is_ok(), "valid TextString must succeed: {result:?}");
    if let Ok(ttlv) = result {
        use crate::ttlv::TTLValue;
        assert_eq!(ttlv.value, TTLValue::TextString("hello".to_owned()));
    }
}

// ---------------------------------------------------------------------------
// W19: TextString with invalid UTF-8 bytes must fail cleanly
// ---------------------------------------------------------------------------
#[test]
fn w19_textstring_invalid_utf8() {
    // 0xFF is not valid UTF-8
    let data = [
        0x42, 0x00, 0x0A, // tag: AttributeName
        0x07, // type: TextString
        0x00, 0x00, 0x00, 0x01, // length: 1
        0xFF, // invalid UTF-8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 7 padding bytes (1 % 8 = 1; pad=7)
    ];
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(result.is_err(), "invalid UTF-8 in TextString must fail");
}

// ---------------------------------------------------------------------------
// W20: TextString length=0 (empty string) must succeed
// ---------------------------------------------------------------------------
#[test]
fn w20_textstring_empty() {
    let data = [
        0x42, 0x00, 0x0A, // tag: AttributeName
        0x07, // type: TextString
        0x00, 0x00, 0x00, 0x00, // length: 0 → no value, no padding needed
    ];
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(result.is_ok(), "empty TextString must succeed: {result:?}");
}

// ---------------------------------------------------------------------------
// W21: ByteString length=0 (empty bytes) must succeed
// ---------------------------------------------------------------------------
#[test]
fn w21_bytestring_empty() {
    let data = [
        0x42, 0x00, 0x1E, // tag: CertificateValue
        0x08, // type: ByteString
        0x00, 0x00, 0x00, 0x00, // length: 0 → no value, no padding needed
    ];
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(result.is_ok(), "empty ByteString must succeed: {result:?}");
}

// ---------------------------------------------------------------------------
// W22: DateTime with max valid Unix timestamp (i64::MAX) must succeed
// ---------------------------------------------------------------------------
#[test]
fn w22_datetime_max_timestamp() {
    let ts: i64 = i64::MAX;
    let mut data = vec![
        0x42, 0x00, 0x20, // tag: CompromiseDate
        0x09, // type: DateTime
        0x00, 0x00, 0x00, 0x08, // length: 8
    ];
    data.extend_from_slice(&ts.to_be_bytes());
    // i64::MAX is outside valid time::OffsetDateTime range — parser may succeed or fail;
    // what matters is it must not panic.
    let _result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
}

// ---------------------------------------------------------------------------
// W23: DateTime with negative timestamp (Unix epoch before 1970) must succeed
// ---------------------------------------------------------------------------
#[test]
fn w23_datetime_negative_timestamp() {
    let ts: i64 = -1_i64;
    let mut data = vec![
        0x42, 0x00, 0x20, // tag: CompromiseDate
        0x09, // type: DateTime
        0x00, 0x00, 0x00, 0x08, // length: 8
    ];
    data.extend_from_slice(&ts.to_be_bytes());
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(
        result.is_ok(),
        "negative timestamp (1 sec before epoch) must succeed: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// W24: LongInteger with min value (i64::MIN) — round-trip correctness
// ---------------------------------------------------------------------------
#[test]
fn w24_longinteger_min_value() {
    let mut data = vec![
        0x42, 0x00, 0x0D, // tag: BatchCount (reuse for convenience)
        0x03, // type: LongInteger
        0x00, 0x00, 0x00, 0x08, // length: 8
    ];
    data.extend_from_slice(&i64::MIN.to_be_bytes());
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(
        result.is_ok(),
        "LongInteger i64::MIN must succeed: {result:?}"
    );
    if let Ok(ttlv) = result {
        use crate::ttlv::TTLValue;
        assert_eq!(ttlv.value, TTLValue::LongInteger(i64::MIN));
    }
}

// ---------------------------------------------------------------------------
// W26: ByteString with oversized length header → field-length guard rejects
// ---------------------------------------------------------------------------
/// A crafted TTLV packet whose `ByteString` length field claims 128 MiB of data
/// while the actual payload is only a handful of bytes.
/// Before the guard was added the deserializer would allocate 128 MiB of zeroed memory
/// on every such request (`DoS` vector).  After the fix it must return an error immediately.
#[test]
fn w26_bytestring_oversized_length_rejected() {
    use crate::ttlv::wire::MAX_TTLV_FIELD_BYTES;
    // Claim a field that is 2× the allowed maximum.
    let claimed_len: u32 = u32::try_from(MAX_TTLV_FIELD_BYTES * 2).unwrap_or(u32::MAX);
    let mut data = vec![
        0x42, 0x00, 0x08, // tag: Attribute (ByteString in tests)
        0x08, // type: ByteString
    ];
    data.extend_from_slice(&claimed_len.to_be_bytes());
    // Only write 16 bytes of actual payload (not the claimed length).
    data.extend_from_slice(&[0xAA_u8; 16]);
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(
        result.is_err(),
        "ByteString with oversized claimed length must be rejected, got Ok"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("exceeds maximum") || msg.contains("MAX"),
        "error message must mention the length guard, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// W27: TextString with oversized length header → field-length guard rejects
// ---------------------------------------------------------------------------
#[test]
fn w27_textstring_oversized_length_rejected() {
    use crate::ttlv::wire::MAX_TTLV_FIELD_BYTES;
    let claimed_len: u32 = u32::try_from(MAX_TTLV_FIELD_BYTES + 1).unwrap_or(u32::MAX);
    let mut data = vec![
        0x42, 0x00, 0x55, // tag: Name (TextString)
        0x07, // type: TextString
    ];
    data.extend_from_slice(&claimed_len.to_be_bytes());
    data.extend_from_slice(b"short payload");
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(
        result.is_err(),
        "TextString with oversized claimed length must be rejected"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("exceeds maximum") || msg.contains("MAX"),
        "error message must mention the length guard, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// W28: BigInteger with oversized length header → field-length guard rejects
// ---------------------------------------------------------------------------
#[test]
fn w28_biginteger_oversized_length_rejected() {
    use crate::ttlv::wire::MAX_TTLV_FIELD_BYTES;
    let claimed_len: u32 = u32::try_from(MAX_TTLV_FIELD_BYTES + 1).unwrap_or(u32::MAX);
    let mut data = vec![
        0x42, 0x00, 0x0A, // tag: BigInteger
        0x04, // type: BigInteger
    ];
    data.extend_from_slice(&claimed_len.to_be_bytes());
    data.extend_from_slice(&[0xFF_u8; 8]);
    let result = TTLV::from_bytes(&data, KmipFlavor::Kmip1);
    assert!(
        result.is_err(),
        "BigInteger with oversized claimed length must be rejected"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("exceeds maximum") || msg.contains("MAX"),
        "error message must mention the length guard, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// W25: Round-trip — serialize a valid structure then deserialize it back
// ---------------------------------------------------------------------------
#[test]
fn w25_round_trip_structure() {
    use crate::{
        kmip_1_4,
        ttlv::{TTLV, TTLValue},
    };
    let ttlv = TTLV {
        tag: "RequestMessage".to_owned(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "BatchCount".to_owned(),
            value: TTLValue::Integer(1),
        }]),
    };
    let mut buf = Vec::new();
    TTLVBytesSerializer::new(&mut buf)
        .write_ttlv::<kmip_1_4::kmip_types::Tag>(&ttlv)
        .expect("serialization must succeed");

    let (ttlv_back, len) = TTLVBytesDeserializer::new(buf.as_slice())
        .read_ttlv::<kmip_1_4::kmip_types::Tag>()
        .expect("deserialization must succeed");
    assert_eq!(len, buf.len(), "consumed length must match serialized size");
    assert_eq!(ttlv_back, ttlv, "round-trip must preserve structure");
}
