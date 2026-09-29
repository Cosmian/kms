//! Edge-case and adversarial tests for the TTLV XML deserializer.
//!
//! Coverage areas:
//!   X1-X4   : Malformed / empty XML
//!   X5-X7   : Unknown / bad attributes
//!   X8-X10  : Depth limit enforcement (`MAX_XML_STACK_DEPTH` = 64)
//!   X11-X13 : Scalar leaf types (`Integer`, `TextString`, `Boolean`)
//!   X14-X16 : XXE and entity checks (regression: quick-xml must not expand)
//!   X17     : Well-formed deeply-nested Structure at limit
//!   X18     : Round-trip: XML serialize → XML deserialize

use crate::ttlv::{TTLV, TTLValue, xml::TTLVXMLDeserializer};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build XML for `depth` nested `<RequestMessage type="Structure">` elements.
fn nested_xml(depth: usize) -> String {
    let open: String = (0..depth)
        .map(|_| r#"<RequestMessage type="Structure">"#)
        .collect::<Vec<_>>()
        .join("\n");
    let close: String = (0..depth)
        .map(|_| "</RequestMessage>")
        .collect::<Vec<_>>()
        .join("\n");
    format!("{open}\n{close}")
}

// ---------------------------------------------------------------------------
// X1: Empty string → error
// ---------------------------------------------------------------------------
#[test]
fn x01_empty_string() {
    let result = TTLVXMLDeserializer::from_xml("");
    assert!(result.is_err(), "empty XML must fail");
}

// ---------------------------------------------------------------------------
// X2: Random garbage bytes, not XML at all
// ---------------------------------------------------------------------------
#[test]
fn x02_garbage_input() {
    // Use valid low-ASCII control bytes; \xFF/\x80 are rejected by Rust string literals.
    let result = TTLVXMLDeserializer::from_xml("\x00\x01\x02\x03 not xml");
    // Should fail with a parse error, not panic
    assert!(result.is_err(), "garbage input must fail");
}

// ---------------------------------------------------------------------------
// X3: Well-formed XML but no KMIP element — stack ends empty
// ---------------------------------------------------------------------------
#[test]
fn x03_no_root_element() {
    // valid XML comment, but no actual element
    let result = TTLVXMLDeserializer::from_xml("<!-- no content -->");
    assert!(result.is_err(), "XML with no root element must fail");
}

// ---------------------------------------------------------------------------
// X4: Unclosed tag (malformed XML)
// ---------------------------------------------------------------------------
#[test]
fn x04_unclosed_tag() {
    let result = TTLVXMLDeserializer::from_xml(r#"<RequestMessage type="Structure">"#);
    assert!(result.is_err(), "unclosed tag must fail");
}

// ---------------------------------------------------------------------------
// X5: Leaf element with unknown type attribute
// ---------------------------------------------------------------------------
#[test]
fn x05_unknown_leaf_type() {
    let xml = r#"<RequestMessage type="Structure"><BatchCount type="UnknownType" value="1"/></RequestMessage>"#;
    let result = TTLVXMLDeserializer::from_xml(xml);
    // Unrecognised type should produce an error, not silently produce garbage
    assert!(result.is_err(), "unknown type attribute on leaf must fail");
}

// ---------------------------------------------------------------------------
// X6: Integer leaf – non-numeric value
// ---------------------------------------------------------------------------
#[test]
fn x06_integer_non_numeric_value() {
    let xml = r#"<RequestMessage type="Structure"><BatchCount type="Integer" value="not_a_number"/></RequestMessage>"#;
    let result = TTLVXMLDeserializer::from_xml(xml);
    assert!(result.is_err(), "non-numeric Integer value must fail");
}

// ---------------------------------------------------------------------------
// X7: Boolean leaf – invalid value string
// ---------------------------------------------------------------------------
#[test]
fn x07_boolean_invalid_value() {
    let xml = r#"<RequestMessage type="Structure"><SomeFlag type="Boolean" value="maybe"/></RequestMessage>"#;
    let result = TTLVXMLDeserializer::from_xml(xml);
    assert!(result.is_err(), "invalid Boolean value must fail");
}

// ---------------------------------------------------------------------------
// X8: Depth exactly at limit (64 levels) — must succeed
// ---------------------------------------------------------------------------
#[test]
fn x08_depth_exactly_at_limit() {
    // MAX_XML_STACK_DEPTH = 64; the stack counts start-element pushes.
    // A document with 64 opening tags that are pushed to the stack is allowed.
    let xml = nested_xml(64);
    let result = TTLVXMLDeserializer::from_xml(&xml);
    assert!(
        result.is_ok(),
        "depth=64 must succeed (at limit), got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// X9: Depth one over limit (65 levels) — must fail with depth error
// ---------------------------------------------------------------------------
#[test]
fn x09_depth_one_over_limit() {
    let xml = nested_xml(65);
    let result = TTLVXMLDeserializer::from_xml(&xml);
    assert!(
        result.is_err(),
        "depth=65 must fail (one over MAX_XML_STACK_DEPTH)"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("depth") || msg.contains("maximum"),
        "error should mention depth limit, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// X10: Extreme depth (10 000 levels) — must fail gracefully, no stack overflow
// ---------------------------------------------------------------------------
#[test]
fn x10_extreme_depth_no_stack_overflow() {
    let xml = nested_xml(10_000);
    let result = TTLVXMLDeserializer::from_xml(&xml);
    assert!(
        result.is_err(),
        "depth=10000 must fail, not overflow the call stack"
    );
}

// ---------------------------------------------------------------------------
// X11: Valid Integer leaf in a structure
// ---------------------------------------------------------------------------
#[test]
fn x11_valid_integer_leaf() {
    let xml = r#"<RequestMessage type="Structure"><BatchCount type="Integer" value="42"/></RequestMessage>"#;
    let result = TTLVXMLDeserializer::from_xml(xml);
    assert!(
        result.is_ok(),
        "valid Integer leaf must succeed: {result:?}"
    );
    let ttlv = result.unwrap();
    match &ttlv.value {
        TTLValue::Structure(children) => {
            assert_eq!(children.len(), 1);
            assert_eq!(children[0].tag, "BatchCount");
            assert_eq!(children[0].value, TTLValue::Integer(42));
        }
        _ => panic!("expected Structure, got {:?}", ttlv.value),
    }
}

// ---------------------------------------------------------------------------
// X12: Valid TextString leaf
// ---------------------------------------------------------------------------
#[test]
fn x12_valid_textstring_leaf() {
    let xml = r#"<RequestMessage type="Structure"><AttributeName type="TextString" value="hello"/></RequestMessage>"#;
    let result = TTLVXMLDeserializer::from_xml(xml);
    assert!(
        result.is_ok(),
        "valid TextString leaf must succeed: {result:?}"
    );
    let ttlv = result.unwrap();
    match &ttlv.value {
        TTLValue::Structure(children) => {
            assert_eq!(children[0].value, TTLValue::TextString("hello".to_owned()));
        }
        _ => panic!("expected Structure, got {:?}", ttlv.value),
    }
}

// ---------------------------------------------------------------------------
// X13: Valid Boolean leaf — true
// ---------------------------------------------------------------------------
#[test]
fn x13_valid_boolean_true() {
    let xml = r#"<RequestMessage type="Structure"><SomeFlag type="Boolean" value="true"/></RequestMessage>"#;
    let result = TTLVXMLDeserializer::from_xml(xml);
    assert!(
        result.is_ok(),
        "valid Boolean true must succeed: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// X14: XXE — entity declaration must NOT be expanded; parser returns error or
//       treats the entity literally (regression: quick-xml must not call out-of-band)
// ---------------------------------------------------------------------------
#[test]
fn x14_xxe_entity_not_expanded() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<RequestMessage type="Structure">
  <AttributeName type="TextString" value="&xxe;"/>
</RequestMessage>"#;
    // quick-xml does not expand external entities; it may return an error or
    // treat the text literally. No filesystem access must occur.
    let result = TTLVXMLDeserializer::from_xml(xml);
    // The key assertion: if it succeeds, the value must NOT contain /etc/passwd content
    if let Ok(ttlv) = result {
        fn contains_passwd(t: &TTLV) -> bool {
            match &t.value {
                TTLValue::TextString(s) => s.contains("root:") || s.contains("/bin/"),
                TTLValue::Structure(children) => children.iter().any(contains_passwd),
                _ => false,
            }
        }
        assert!(
            !contains_passwd(&ttlv),
            "XXE entity expansion must not read /etc/passwd"
        );
    }
}

// ---------------------------------------------------------------------------
// X15: XML bomb (billion laughs) — exponential entity expansion must not OOM
//
// quick-xml does not perform entity substitution at all so this should finish
// quickly. This test is a regression guard for parser upgrades.
// ---------------------------------------------------------------------------
#[test]
fn x15_xml_bomb_billion_laughs() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<RequestMessage type="Structure"><AttributeName type="TextString" value="&lol9;"/></RequestMessage>"#;
    // Must return quickly (either error or value with unexpanded entities) — not hang
    let _result = TTLVXMLDeserializer::from_xml(xml);
}

// ---------------------------------------------------------------------------
// X16: Attribute with no type — ALLOW_IMPLICIT_STRUCTURE means Structure assumed
// ---------------------------------------------------------------------------
#[test]
fn x16_implicit_structure_type() {
    // No type attribute → treated as Structure (legacy interop behaviour)
    let xml = r#"<RequestMessage><BatchCount type="Integer" value="1"/></RequestMessage>"#;
    let result = TTLVXMLDeserializer::from_xml(xml);
    assert!(
        result.is_ok(),
        "implicit Structure type must succeed (ALLOW_IMPLICIT_STRUCTURE): {result:?}"
    );
}

// ---------------------------------------------------------------------------
// X17: Deeply-nested structure at exact limit, with Integer leaf at bottom
// ---------------------------------------------------------------------------
#[test]
fn x17_deep_structure_with_leaf() {
    // Build 63 nesting levels; the leaf is one BatchCount Integer at the deepest level.
    // Stack depth during: open_1 push, open_2 push… open_63 push, leaf processed → 63 items on stack → OK.
    let depth = 63_usize;
    let open: String = (0..depth)
        .map(|_| r#"<RequestMessage type="Structure">"#)
        .collect::<Vec<_>>()
        .join("\n");
    let close: String = (0..depth)
        .map(|_| "</RequestMessage>")
        .collect::<Vec<_>>()
        .join("\n");
    let xml = format!("{open}\n<BatchCount type=\"Integer\" value=\"1\"/>\n{close}");
    let result = TTLVXMLDeserializer::from_xml(&xml);
    assert!(
        result.is_ok(),
        "depth-63 structure with leaf must succeed: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// X18: Round-trip — TTLV struct → XML → TTLV struct
// ---------------------------------------------------------------------------
#[test]
fn x18_round_trip_xml() {
    use crate::ttlv::{
        TTLV, TTLValue,
        xml::{TTLVXMLDeserializer, TTLVXMLSerializer},
    };

    let original = TTLV {
        tag: "RequestMessage".to_owned(),
        value: TTLValue::Structure(vec![TTLV {
            tag: "BatchCount".to_owned(),
            value: TTLValue::Integer(3),
        }]),
    };

    let xml = TTLVXMLSerializer::to_xml(&original).expect("XML serialization must succeed");
    let recovered = TTLVXMLDeserializer::from_xml(&xml).expect("XML deserialization must succeed");
    assert_eq!(
        original, recovered,
        "XML round-trip must preserve the TTLV structure"
    );
}
