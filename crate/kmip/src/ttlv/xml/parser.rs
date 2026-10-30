//! Unified KMIP XML parser (merged legacy & refactored implementations).
//!
//! Responsibilities:
//! 1. Split a concatenated KMIP XML test vector file into individual
//!    `<RequestMessage>` / `<ResponseMessage>` fragments.
//! 2. Perform placeholder substitution for `$NOW`, `$NOW-<delta>` and
//!    `$UNIQUE_IDENTIFIER_<n>` producing deterministic, test-friendly values.
//! 3. Inject `type="Structure"` into well-known structural tags when omitted
//!    so the TTLV XML deserializer can correctly treat them as structures.
//! 4. Convert each fragment XML -> TTLV tree (`TTLVXMLDeserializer`) -> strongly
//!    typed `RequestMessage` / `ResponseMessage` via existing `from_ttlv`.
//!
//! This file now supersedes the temporary `parser_refactored.rs` which is
//! reduced to a thin re-export (or will be removed).
//!
//! The merge keeps the deterministic placeholder behavior from the legacy
//! parser and the cleaner split / transform layering from the refactored one.

use std::{fmt::Write as _, sync::LazyLock};

use quick_xml::{Reader, XmlVersion, events::Event};
use regex::Regex;

use crate::{
    KmipError,
    kmip_0::kmip_messages::{RequestMessage, ResponseMessage},
    ttlv::{TTLV, from_ttlv, xml::TTLVXMLDeserializer},
};

/// Static regex: matches `$NOW-<digits>` placeholders.
#[expect(
    clippy::expect_used,
    reason = "regex literal is valid; exercised by XML parser tests"
)]
static RE_NOW_DELTA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$NOW-\d+").expect("static regex RE_NOW_DELTA"));

/// Static regex: matches `$UNIQUE_IDENTIFIER_<digits>` placeholders.
#[expect(
    clippy::expect_used,
    reason = "regex literal is valid; exercised by XML parser tests"
)]
static RE_UID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$UNIQUE_IDENTIFIER_(\d+)").expect("static regex RE_UID"));

/// Pre-compiled regexes for injecting `type="Structure"` into well-known structural tags.
static STRUCTURAL_TAG_REGEXES: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    STRUCTURAL_TAGS
        .iter()
        .filter_map(|tag| {
            let pattern = format!(r"<{tag}\b[^>]*>");
            Regex::new(&pattern).ok().map(|re| (*tag, re))
        })
        .collect()
});

/// Reconstruct an XML start/empty tag (with attributes) from a `quick_xml` event.
/// If `self_closing` is true, emits `<tag .../>`, otherwise `<tag ...>`.
fn reconstruct_tag(
    name: &str,
    attrs: quick_xml::events::attributes::Attributes,
    self_closing: bool,
    out: &mut String,
) {
    out.push('<');
    out.push_str(name);
    for attr in attrs.flatten() {
        if let Ok(val) = attr.normalized_value(XmlVersion::Implicit1_0) {
            out.push(' ');
            out.push_str(attr.key.as_ref());
            out.push_str("=\"");
            out.push_str(&val);
            out.push('"');
        }
    }
    if self_closing {
        out.push_str("/>");
    } else {
        out.push('>');
    }
}

// Helper to backfill LocateResponse.located_items when omitted in XML
fn backfill_locate_response(resp: &mut ResponseMessage) {
    for bi in &mut resp.batch_item {
        if let crate::kmip_0::kmip_messages::ResponseMessageBatchItemVersioned::V21(inner) = bi {
            if let Some(crate::kmip_2_1::kmip_operations::Operation::LocateResponse(lr)) =
                &mut inner.response_payload
            {
                if lr.located_items.is_none() {
                    let len = lr.unique_identifier.as_ref().map_or(0_usize, Vec::len);
                    let cnt = i32::try_from(len).unwrap_or(i32::MAX);
                    lr.located_items = Some(cnt);
                }
            }
        }
    }
}
// Known structural KMIP tags that should be treated as Structures even if no type attribute present
const STRUCTURAL_TAGS: &[&str] = &[
    "RequestMessage",
    "RequestHeader",
    "BatchItem",
    "RequestPayload",
    "ResponseMessage",
    "ResponseHeader",
    "ResponsePayload",
    "ProtocolVersion",
    "Attributes",
    "AttributeReference",
    "CommonAttributes",
    "PrivateKeyAttributes",
    "PublicKeyAttributes",
    "Digest",
    "RandomNumberGenerator",
    // Post-process: ensure LocateResponse.located_items reflects number of returned IDs
    "KeyBlock",
    "KeyValue",
    "TemplateAttribute",
    "Name",
    "KMIP",
    "Attribute",
    "SymmetricKey",
    "PrivateKey",
    "PublicKey",
    "SecretData",
];

pub struct KmipXmlDoc {
    pub requests: Vec<RequestMessage>,
    pub responses: Vec<ResponseMessage>,
}

impl KmipXmlDoc {
    /// Parse KMIP XML content into a `KmipXmlDoc` (requests + responses)
    pub fn new(xml: &str) -> Result<Self, KmipError> {
        parse_internal(xml)
    }

    /// Read a KMIP XML file from disk and parse it into a `KmipXmlDoc`
    pub fn new_with_file(path: &std::path::Path) -> Result<Self, KmipError> {
        let xml = std::fs::read_to_string(path)
            .map_err(|e| KmipError::Default(format!("read xml file: {e}")))?;
        Self::new(&xml)
    }
}

fn substitute_placeholders(raw: &str) -> String {
    // Normalize timestamps: replace $NOW-<delta> first, then plain $NOW.
    let mut out = RE_NOW_DELTA.replace_all(raw, "0").into_owned();
    out = out.replace("$NOW", "0");
    // Deterministic unique identifiers.
    RE_UID
        .replace_all(&out, |caps: &regex::Captures| {
            let idx = caps.get(1).map_or("0", |m| m.as_str());
            format!("uid-{idx}")
        })
        .into_owned()
}

fn xml_fragment_to_ttlv(fragment: &str) -> Result<TTLV, KmipError> {
    TTLVXMLDeserializer::from_xml(fragment)
}

fn normalize_fragment(fragment: &str) -> String {
    let mut substituted = substitute_placeholders(fragment);

    // Inject structure type hints if absent
    for (tag, re) in STRUCTURAL_TAG_REGEXES.iter() {
        substituted = re
            .replace_all(&substituted, |caps: &regex::Captures| {
                let matched = &caps[0];
                if matched.contains(" type=\"") || matched.contains(" type =\"") {
                    matched.to_owned()
                } else {
                    let insert_pos = 1 + tag.len();
                    let remainder = &matched[insert_pos..];
                    format!("<{tag} type=\"Structure\"{remainder}")
                }
            })
            .into_owned();
    }

    substituted
}

pub(crate) fn parse_message_ttlvs(xml: &str) -> Result<Vec<TTLV>, KmipError> {
    let mut ttlvs = Vec::new();

    // Stream over XML bytes to extract top-level RequestMessage / ResponseMessage snippets.
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut depth: i32 = 0;
    let mut capturing = false;
    let mut current = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = e.name().as_ref().to_owned();
                if !capturing && (name == "RequestMessage" || name == "ResponseMessage") {
                    capturing = true;
                    depth = 0;
                    current.clear();
                }
                if capturing {
                    reconstruct_tag(&name, e.attributes(), false, &mut current);
                    depth += 1;
                }
            }
            Ok(Event::Empty(e)) => {
                let name = e.name().as_ref().to_owned();
                if !capturing && (name == "RequestMessage" || name == "ResponseMessage") {
                    current.clear();
                    reconstruct_tag(&name, e.attributes(), true, &mut current);
                    let normalized = normalize_fragment(&current);
                    ttlvs.push(xml_fragment_to_ttlv(&normalized)?);
                    current.clear();
                } else if capturing {
                    reconstruct_tag(&name, e.attributes(), true, &mut current);
                }
            }
            Ok(Event::Text(e)) if capturing => {
                current.push_str(&e);
            }
            Ok(Event::CData(e)) if capturing => {
                current.push_str("<![CDATA[");
                current.push_str(&e.into_inner());
                current.push_str("]]>");
            }
            Ok(Event::End(e)) => {
                let name = e.name().as_ref().to_owned();
                if capturing {
                    let _ = write!(&mut current, "</{name}>");
                    depth -= 1;
                    if depth == 0 {
                        let normalized = normalize_fragment(&current);
                        ttlvs.push(xml_fragment_to_ttlv(&normalized)?);
                        capturing = false;
                        current.clear();
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(KmipError::Default(format!("XML read error: {e}"))),
            _ => {}
        }
        buf.clear();
    }

    if capturing {
        return Err(KmipError::Default(
            "unterminated KMIP message fragment".into(),
        ));
    }

    Ok(ttlvs)
}

fn parse_internal(xml: &str) -> Result<KmipXmlDoc, KmipError> {
    let mut requests = Vec::new();
    let mut responses = Vec::new();

    for ttlv in parse_message_ttlvs(xml)? {
        match &*ttlv.tag {
            "RequestMessage" => {
                requests.push(from_ttlv(ttlv).map_err(|e| KmipError::Default(e.to_string()))?);
            }
            "ResponseMessage" => {
                let mut response: ResponseMessage =
                    from_ttlv(ttlv).map_err(|e| KmipError::Default(e.to_string()))?;
                backfill_locate_response(&mut response);
                responses.push(response);
            }
            other => {
                return Err(KmipError::Default(format!(
                    "Unexpected top-level tag: {other}"
                )));
            }
        }
    }

    Ok(KmipXmlDoc {
        requests,
        responses,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_request() {
        // Provide a minimal valid KMIP 2.1 RequestMessage with proper KMIP XML test structure.
        // Our TTLVXMLDeserializer expects every start element to represent a Structure and primitive
        // leaves expressed as empty tags with type/value attributes.
        // This message: Activate(uid-0)
        let xml = r#"<RequestMessage type="Structure">
    <RequestHeader type="Structure">
        <ProtocolVersion type="Structure">
            <ProtocolVersionMajor type="Integer" value="2"/>
            <ProtocolVersionMinor type="Integer" value="1"/>
        </ProtocolVersion>
        <BatchCount type="Integer" value="1"/>
    </RequestHeader>
    <BatchItem type="Structure">
        <Operation type="Enumeration" value="18" name="Activate"/>
        <RequestPayload type="Structure">
            <UniqueIdentifier type="TextString" value="uid-0"/>
        </RequestPayload>
    </BatchItem>
</RequestMessage>"#;
        let doc = match KmipXmlDoc::new(xml) {
            Ok(d) => d,
            Err(e) => panic!("parse minimal valid request: {e}"),
        };
        assert_eq!(doc.requests.len(), 1, "expected exactly one request parsed");
        assert!(doc.responses.is_empty(), "expected no responses parsed");
    }

    #[test]
    fn unique_identifier_placeholder_does_not_allocate_by_index() {
        let input = format!("$UNIQUE_IDENTIFIER_{}", usize::MAX);
        assert_eq!(
            substitute_placeholders(&input),
            format!("uid-{}", usize::MAX)
        );
    }
}
