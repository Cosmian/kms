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

use std::fmt::Write as _;

use quick_xml::{Reader, events::Event};
use regex::Regex;

use crate::{
    KmipError,
    error::result::KmipResult,
    kmip_0::kmip_messages::{RequestMessage, ResponseMessage},
    ttlv::{TTLV, from_ttlv, xml::TTLVXMLDeserializer},
};

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

fn substitute_placeholders(raw: &str, uid_state: &mut Vec<String>) -> KmipResult<String> {
    // Normalize timestamps: replace $NOW-<delta> first, then plain $NOW
    let mut out = Regex::new(r"\$NOW-\d+")?.replace_all(raw, "0").into_owned();
    out = out.replace("$NOW", "0");
    // Deterministic unique identifiers
    out = Regex::new(r"\$UNIQUE_IDENTIFIER_(\d+)")?
        .replace_all(&out, |caps: &regex::Captures| {
            let idx: usize = caps
                .get(1)
                .and_then(|m| m.as_str().parse::<usize>().ok())
                .unwrap_or(0);
            if uid_state.len() <= idx {
                uid_state.resize(idx + 1, String::new());
            }
            uid_state.get_mut(idx).map_or_else(
                || format!("uid-{idx}"),
                |slot| {
                    if slot.is_empty() {
                        *slot = format!("uid-{idx}");
                    }
                    slot.clone()
                },
            )
        })
        .into_owned();
    Ok(out)
}

fn xml_fragment_to_ttlv(fragment: &str) -> Result<TTLV, KmipError> {
    TTLVXMLDeserializer::from_xml(fragment)
}

fn normalize_fragment(fragment: &str, uid_state: &mut Vec<String>) -> KmipResult<String> {
    let mut substituted = substitute_placeholders(fragment, uid_state)?;

    // Inject structure type hints if absent
    for tag in STRUCTURAL_TAGS {
        // Match the full start tag (including attributes) so we can accurately
        // detect an existing type attribute and avoid duplicating it.
        let pattern = format!(r"<{tag}\\b[^>]*>");
        let Ok(re) = Regex::new(&pattern) else {
            continue;
        };

        substituted = re
            .replace_all(&substituted, |caps: &regex::Captures| {
                let matched = &caps[0]; // e.g., "<Tag ...>" or "<Tag/>"
                // If a type attribute already exists, leave as-is
                if matched.contains(" type=\"") || matched.contains(" type =\"") {
                    matched.to_owned()
                } else {
                    // Insert type="Structure" immediately after the tag name
                    // matched starts with "<" then the tag name; keep the remainder as-is
                    let insert_pos = 1 + tag.len();
                    let remainder = &matched[insert_pos..];
                    format!("<{tag} type=\"Structure\"{remainder}")
                }
            })
            .into_owned();
    }

    Ok(substituted)
}

fn parse_internal(xml: &str) -> Result<KmipXmlDoc, KmipError> {
    let mut uid_state = Vec::new();
    let mut requests = Vec::new();
    let mut responses = Vec::new();

    // Stream over XML bytes to extract top-level RequestMessage / ResponseMessage snippets
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);
    let mut buf = Vec::new();
    let mut depth: i32 = 0;
    let mut capturing = false;
    let mut current = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if !capturing && (name == "RequestMessage" || name == "ResponseMessage") {
                    capturing = true;
                    depth = 0; // depth relative to root
                    current.clear();
                }
                if capturing {
                    // Reconstruct start tag with attributes
                    current.push('<');
                    current.push_str(&name);
                    for attr in e.attributes().flatten() {
                        if let Ok(val) = attr.unescape_value() {
                            current.push(' ');
                            current.push_str(&String::from_utf8_lossy(attr.key.as_ref()));
                            current.push_str("=\"");
                            current.push_str(&val);
                            current.push('"');
                        }
                    }
                    current.push('>');
                    depth += 1;
                }
            }
            Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if !capturing && (name == "RequestMessage" || name == "ResponseMessage") {
                    // Self-closing root (unlikely in KMIP); treat as full fragment
                    current.clear();
                    current.push('<');
                    current.push_str(&name);
                    for attr in e.attributes().flatten() {
                        if let Ok(val) = attr.unescape_value() {
                            current.push(' ');
                            current.push_str(&String::from_utf8_lossy(attr.key.as_ref()));
                            current.push_str("=\"");
                            current.push_str(&val);
                            current.push('"');
                        }
                    }
                    current.push_str("/>");
                    // Process immediately
                    let normalized = normalize_fragment(&current, &mut uid_state)?;
                    let ttlv = xml_fragment_to_ttlv(&normalized)?;
                    match ttlv.tag.as_str() {
                        "RequestMessage" => requests
                            .push(from_ttlv(ttlv).map_err(|e| KmipError::Default(e.to_string()))?),
                        "ResponseMessage" => {
                            let mut resp: ResponseMessage =
                                from_ttlv(ttlv).map_err(|e| KmipError::Default(e.to_string()))?;
                            // Backfill LocateResponse.located_items when omitted in XML
                            backfill_locate_response(&mut resp);
                            responses.push(resp);
                        }
                        other => {
                            return Err(KmipError::Default(format!(
                                "Unexpected top-level tag: {other}"
                            )));
                        }
                    }
                    current.clear();
                } else if capturing {
                    current.push('<');
                    current.push_str(&name);
                    for attr in e.attributes().flatten() {
                        if let Ok(val) = attr.unescape_value() {
                            current.push(' ');
                            current.push_str(&String::from_utf8_lossy(attr.key.as_ref()));
                            current.push_str("=\"");
                            current.push_str(&val);
                            current.push('"');
                        }
                    }
                    current.push_str("/>");
                }
            }
            Ok(Event::Text(e)) => {
                if capturing {
                    if let Ok(txt) = e.unescape() {
                        current.push_str(&txt);
                    } else {
                        current.push_str(&String::from_utf8_lossy(e.as_ref()));
                    }
                }
            }
            Ok(Event::CData(e)) => {
                if capturing {
                    current.push_str("<![CDATA[");
                    current.push_str(&String::from_utf8_lossy(&e.into_inner()));
                    current.push_str("]]>");
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if capturing {
                    let _ = write!(&mut current, "</{name}>");
                    depth -= 1;
                    if depth == 0 {
                        // Completed one fragment
                        let normalized = normalize_fragment(&current, &mut uid_state)?;
                        let ttlv = xml_fragment_to_ttlv(&normalized)?;
                        match ttlv.tag.as_str() {
                            "RequestMessage" => requests.push(
                                from_ttlv(ttlv).map_err(|e| KmipError::Default(e.to_string()))?,
                            ),
                            "ResponseMessage" => {
                                let mut resp: ResponseMessage = from_ttlv(ttlv)
                                    .map_err(|e| KmipError::Default(e.to_string()))?;
                                // Backfill LocateResponse.located_items when omitted in XML
                                backfill_locate_response(&mut resp);
                                responses.push(resp);
                            }
                            other => {
                                return Err(KmipError::Default(format!(
                                    "Unexpected top-level tag: {other}"
                                )));
                            }
                        }
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

    // If we reached EOF still capturing, that's a malformed XML or truncated file.
    if capturing {
        return Err(KmipError::Default(
            "unterminated KMIP message fragment".into(),
        ));
    }

    Ok(KmipXmlDoc {
        requests,
        responses,
    })
}

#[cfg(test)]
#[allow(clippy::panic)]
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
}
