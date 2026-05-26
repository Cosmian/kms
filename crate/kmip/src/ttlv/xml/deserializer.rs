//! Deterministic test XML -> TTLV deserializer utilities (split from `serializer.rs`).
//!
//! Provides `TTLVXMLDeserializer::from_xml` used for round‑trip unit tests.

use std::collections::HashSet;

use quick_xml::{Reader, events::Event};
use time::OffsetDateTime;

use crate::{
    KmipError,
    ttlv::{KmipEnumerationVariant, TTLV, TTLValue, enum_lookup::lookup_enum_code},
};

// Strict behavior is now always enforced for enumerations and usage mask tokens.
// We still tolerate missing type="Structure" in upstream test vectors for
// interoperability (some community vectors omit it), but all other previously
// "permissive" fallbacks are removed.
const ALLOW_IMPLICIT_STRUCTURE: bool = true; // keep acceptance of existing vectors

/// Maximum XML element nesting depth accepted by the TTLV XML parser.
///
/// An excessively deep XML document would grow the internal `stack` without bound,
/// exhausting heap memory (`DoS`). Limiting to 64 levels is far above any legitimate
/// KMIP XML depth (typical maximum ~8 levels) while preventing the attack.
const MAX_XML_STACK_DEPTH: usize = 64;

pub struct TTLVXMLDeserializer;
impl TTLVXMLDeserializer {
    // Group non-contiguous <Attribute> vendor-attribute children under an <Attributes> aggregate
    // so that Serde sees one sequence instead of duplicate map keys. This preserves the original
    // relative order within Attribute children and of non-Attribute members before/after the group.
    fn group_vendor_attributes(root: &mut TTLV) {
        if let TTLValue::Structure(children) = &mut root.value {
            // recurse first
            for child in children.iter_mut() {
                Self::group_vendor_attributes(child);
            }
            // Only normalize inside Attributes aggregates
            if root.tag == "Attributes" {
                // Fast-path: if there are 0 or 1 Attribute children, nothing to do
                let attr_count = children.iter().filter(|c| c.tag == "Attribute").count();
                if attr_count <= 1 {
                    return;
                }
                // Rebuild as: prefix (non-Attribute before first), all Attribute (in original order), suffix (remaining non-Attribute)
                let mut prefix: Vec<TTLV> = Vec::new();
                let mut attrs: Vec<TTLV> = Vec::new();
                let mut suffix: Vec<TTLV> = Vec::new();
                let mut seen_first_attr = false;
                for ch in std::mem::take(children) {
                    if ch.tag == "Attribute" {
                        attrs.push(ch);
                        seen_first_attr = true;
                    } else if !seen_first_attr {
                        prefix.push(ch);
                    } else {
                        suffix.push(ch);
                    }
                }
                // Reassemble
                children.extend(prefix);
                children.extend(attrs);
                children.extend(suffix);
            }
        }
    }

    // Deduplicate single-instance attribute structures that appear multiple times within Attributes
    // We keep the first occurrence and drop subsequent ones for tags that map to single-instance fields.
    fn dedup_single_instance_attributes(root: &mut TTLV) {
        // Only process structures
        if let TTLValue::Structure(children) = &mut root.value {
            // Traverse recursively
            for child in children.iter_mut() {
                Self::dedup_single_instance_attributes(child);
            }
            // If this node looks like an Attributes aggregate (heuristic: contains many attribute-like tags)
            // perform dedup on known single-instance attribute tags (ProtectStopDate, ProcessStartDate, etc.)
            let mut seen: HashSet<String> = HashSet::new();
            // NOTE: Do NOT include "Attribute" here for KMIP 2.1. Under an Attributes aggregate,
            // multiple <Attribute> elements are used to carry Vendor-Defined Attributes and must
            // be preserved. Deduplicating them would drop all but the first vendor attribute.
            let single_instance_tags: [&str; 6] = [
                "ProtectStopDate",
                "ProcessStartDate",
                "ActivationDate",
                "DeactivationDate",
                "DestroyDate",
                "CompromiseDate",
            ];
            children.retain(|c| {
                if single_instance_tags.contains(&c.tag.as_str()) {
                    if seen.contains(&c.tag) {
                        // drop duplicate
                        false
                    } else {
                        seen.insert(c.tag.clone());
                        true
                    }
                } else {
                    true
                }
            });
        }
    }

    pub fn from_xml(xml: &str) -> Result<TTLV, KmipError> {
        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);
        let mut buf = Vec::new();
        let mut stack: Vec<TTLV> = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::Start(e)) => {
                    let mut tag = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                    // Preserve original RNGAlgorithm tag spelling (spec uses RNGAlgorithm). Older
                    // logic rewrote to RngAlgorithm which conflicted with explicit serde rename.
                    if tag.starts_with("PKCS_11") {
                        tag = tag.replace("PKCS_11", "PKCS11");
                    }
                    if stack.len() >= MAX_XML_STACK_DEPTH {
                        return Err(KmipError::Default(format!(
                            "TTLV XML structure depth exceeds maximum allowed depth ({MAX_XML_STACK_DEPTH})"
                        )));
                    }
                    let mut node_type = None;
                    for a in e.attributes().flatten() {
                        if a.key.as_ref() == b"type" {
                            node_type = Some(String::from_utf8_lossy(&a.value).into_owned());
                        }
                    }
                    let ttlv = TTLV {
                        tag: tag.clone(),
                        value: TTLValue::Structure(Vec::new()),
                    };
                    stack.push(match node_type.as_deref() {
                        Some("Structure") => ttlv,
                        None if ALLOW_IMPLICIT_STRUCTURE => ttlv,
                        None => {
                            return Err(KmipError::Default(format!(
                                "missing type=\"Structure\" for element '{tag}'"
                            )));
                        }
                        other => {
                            return Err(KmipError::Default(format!(
                                "expected Structure start for tag '{tag}', got {other:?}"
                            )));
                        }
                    });
                }
                Ok(Event::Empty(e)) => {
                    let mut tag = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                    // Keep RNGAlgorithm as-is.
                    if tag.starts_with("PKCS_11") {
                        tag = tag.replace("PKCS_11", "PKCS11");
                    }
                    let mut ty = None;
                    let mut value: Option<String> = None;
                    let mut name: Option<String> = None;
                    for a in e.attributes().flatten() {
                        let k = a.key.as_ref();
                        let v = String::from_utf8_lossy(&a.value).into_owned();
                        match k {
                            b"type" => ty = Some(v),
                            b"value" => value = Some(v),
                            b"name" => name = Some(v),
                            _ => {}
                        }
                    }
                    if ty.is_none() && value.is_none() && ALLOW_IMPLICIT_STRUCTURE {
                        // Accept an implicit empty structure (e.g., ResponsePayload with no members)
                        let ttlv = TTLV {
                            tag,
                            value: TTLValue::Structure(Vec::new()),
                        };
                        if let Some(parent) = stack.last_mut() {
                            if let TTLValue::Structure(children) = &mut parent.value {
                                children.push(ttlv);
                            }
                        } else {
                            return Ok(ttlv);
                        }
                        continue;
                    }
                    let ty = ty.ok_or_else(|| {
                        KmipError::Default(format!("missing type attribute for element '{tag}'"))
                    })?;
                    let mut ttlv = TTLV {
                        tag,
                        value: Self::parse_primitive(&ty, value.as_deref(), name.as_deref())?,
                    };
                    // Root empty element case
                    if stack.is_empty() {
                        Self::group_vendor_attributes(&mut ttlv);
                        Self::dedup_single_instance_attributes(&mut ttlv);
                        return Ok(ttlv);
                    }
                    if let Some(parent) = stack.last_mut() {
                        if let TTLValue::Structure(children) = &mut parent.value {
                            children.push(ttlv);
                        }
                    }
                }
                Ok(Event::End(e)) => {
                    let end_tag_vec = e.name().as_ref().to_vec();
                    let ttlv = stack
                        .pop()
                        .ok_or_else(|| KmipError::Default("unbalanced XML".into()))?;
                    debug_assert_eq!(ttlv.tag.as_bytes(), end_tag_vec.as_slice());
                    if let Some(parent) = stack.last_mut() {
                        if let TTLValue::Structure(children) = &mut parent.value {
                            children.push(ttlv);
                        }
                    } else {
                        let mut root = ttlv;
                        Self::group_vendor_attributes(&mut root);
                        Self::dedup_single_instance_attributes(&mut root);
                        return Ok(root);
                    }
                }
                Ok(
                    Event::Text(_)
                    | Event::CData(_)
                    | Event::Comment(_)
                    | Event::Decl(_)
                    | Event::PI(_)
                    | Event::DocType(_),
                ) => {}
                Err(e) => return Err(KmipError::Default(format!("XML parse error: {e}"))),
            }
            buf.clear();
        }
        Err(KmipError::Default("no root element".into()))
    }

    fn parse_primitive(
        ty: &str,
        value: Option<&str>,
        name: Option<&str>,
    ) -> Result<TTLValue, KmipError> {
        use TTLValue::{
            Boolean, ByteString, DateTime, DateTimeExtended, Enumeration, Integer, Interval,
            LongInteger, TextString,
        };
        Ok(match ty {
            "Integer" => {
                let raw = value.ok_or_else(|| KmipError::Default("missing value".into()))?;
                let parsed_i32: i32 = if let Ok(v) = raw.parse::<i32>() {
                    v
                } else {
                    // Attempt textual CryptographicUsageMask (bit field) tokens separated by ',' or '|'
                    let mut acc: i32 = 0;
                    let mut any = false;
                    let mut unknown_tokens: Vec<String> = Vec::new();
                    for token in raw.split(|c: char| c == ',' || c == '|' || c.is_whitespace()) {
                        if token.is_empty() {
                            continue;
                        }
                        let bit = match token {
                            // KMIP CryptographicUsageMask bit values (kmip_0::kmip_types::CryptographicUsageMask)
                            // and ProtectionStorageMasks combined when provided as tokens
                            "Sign" | "Software" => Some(0x0000_0001),
                            "Verify" | "Hardware" => Some(0x0000_0002),
                            "Encrypt" | "OnProcessor" => Some(0x0000_0004),
                            "Decrypt" | "OnSystem" => Some(0x0000_0008),
                            "WrapKey" | "OffSystem" => Some(0x0000_0010),
                            "UnwrapKey" | "Hypervisor" => Some(0x0000_0020),
                            "OperatingSystem" => Some(0x0000_0040),
                            "MACGenerate" | "Container" => Some(0x0000_0080),
                            "MACVerify" | "OnPremises" => Some(0x0000_0100),
                            "DeriveKey" | "OffPremises" => Some(0x0000_0200),
                            "KeyAgreement" | "Outsourced" => Some(0x0000_0800),
                            "CertificateSign" | "Validated" => Some(0x0000_1000),
                            "CRLSign" | "SameJurisdiction" => Some(0x0000_2000),
                            "Authenticate" => Some(0x0010_0000),
                            "Unrestricted" => Some(0x0020_0000),
                            "SelfManaged" => Some(0x0000_0400),
                            _ => None,
                        };
                        if let Some(b) = bit {
                            acc |= b;
                            any = true;
                        } else {
                            unknown_tokens.push(token.to_owned());
                        }
                    }
                    if !unknown_tokens.is_empty() {
                        return Err(KmipError::Default(format!(
                            "unknown CryptographicUsageMask tokens: {unknown_tokens:?}"
                        )));
                    }
                    if any {
                        acc
                    } else {
                        return Err(KmipError::Default(format!(
                            "invalid Integer value '{raw}' for CryptographicUsageMask"
                        )));
                    }
                };
                Integer(parsed_i32)
            }
            "LongInteger" => LongInteger(
                value
                    .ok_or_else(|| KmipError::Default("missing value".into()))?
                    .parse()
                    .map_err(|e| KmipError::Default(format!("long parse: {e}")))?,
            ),
            "BigInteger" => {
                let raw = value.ok_or_else(|| KmipError::Default("missing value".into()))?;
                // Accept the following literal forms:
                //   1. 0x... (hex, big-endian two's complement bytes)
                //   2. <hex without 0x> (if any hex alphabetic characters present a-fA-F)
                //   3. <decimal integer> (optionally negative)
                // The KMIP XML interop vectors frequently provide leading zero padded hex without 0x.
                let is_decimal_candidate = raw
                    .chars()
                    .all(|c| c.is_ascii_digit() || (c == '-' && raw.len() > 1));
                let contains_hex_alpha = raw
                    .chars()
                    .any(|c| c.is_ascii_hexdigit() && c.is_ascii_alphabetic());
                let bytes = if let Some(stripped) = raw.strip_prefix("0x") {
                    let even_hex = if stripped.len() % 2 == 1 {
                        format!("0{stripped}")
                    } else {
                        stripped.to_owned()
                    };
                    hex::decode(&even_hex)
                        .map_err(|e| KmipError::Default(format!("bigint hex decode: {e}")))?
                } else if contains_hex_alpha {
                    // Treat as hex (letters force hex interpretation)
                    let s = raw.trim_start_matches('0');
                    let hex_body = if s.is_empty() {
                        "00".to_owned()
                    } else {
                        s.to_owned()
                    };
                    let even_hex = if hex_body.len() % 2 == 1 {
                        format!("0{hex_body}")
                    } else {
                        hex_body
                    };
                    hex::decode(&even_hex)
                        .map_err(|e| KmipError::Default(format!("bigint hex decode: {e}")))?
                } else if is_decimal_candidate {
                    // Decimal parse; build two's complement padded to a multiple of 8 bytes for consistency with existing encoder expectations.
                    let bi = raw
                        .parse::<num_bigint_dig::BigInt>()
                        .map_err(|e| KmipError::Default(format!("bigint decimal parse: {e}")))?;
                    let (sign, mut mag) = bi.to_bytes_be();
                    if mag.is_empty() {
                        mag.push(0_u8);
                    }
                    if sign == num_bigint_dig::Sign::Minus {
                        let mut bytes = mag;
                        if !bytes.len().is_multiple_of(8) {
                            bytes.splice(0..0, vec![0_u8; 8 - (bytes.len() % 8)]);
                        }
                        for b in &mut bytes {
                            *b = !*b;
                        }
                        for b in bytes.iter_mut().rev() {
                            let (nb, carry) = b.overflowing_add(1);
                            *b = nb;
                            if !carry {
                                break;
                            }
                        }
                        bytes
                    } else {
                        if !mag.len().is_multiple_of(8) {
                            mag.splice(0..0, vec![0_u8; 8 - (mag.len() % 8)]);
                        }
                        mag
                    }
                } else {
                    return Err(KmipError::Default(format!(
                        "unsupported BigInteger literal '{raw}'"
                    )));
                };
                let kbi = crate::ttlv::kmip_big_int::KmipBigInt::from_signed_bytes_be(&bytes);
                TTLValue::BigInteger(kbi)
            }
            "Enumeration" => {
                let raw = value.ok_or_else(|| KmipError::Default("missing value".into()))?;
                // Try numeric first; otherwise attempt known textual KMIP enumeration name mapping
                // via the shared lookup table in `enum_lookup`. Returns (code, canonical_variant_name).
                // (lookup_enum_code is imported from crate::ttlv::enum_lookup)
                // Provide correct Tag codes for AttributeReference names used in vectors
                let lookup_attribute_reference_tag = |s: &str| -> Option<u32> {
                    match s {
                        // Accurate Tag codes from kmip_2_1::kmip_types::Tag
                        "ActivationDate" => Some(0x42_0001),
                        "CryptographicAlgorithm" => Some(0x42_0028),
                        "CryptographicLength" => Some(0x42_002A),
                        "CryptographicUsageMask" => Some(0x42_002C),
                        "Digest" => Some(0x42_0034),
                        "InitialDate" => Some(0x42_0039),
                        "KeyFormatType" => Some(0x42_0042),
                        "LastChangeDate" => Some(0x42_0048),
                        "LeaseTime" => Some(0x42_0049),
                        "Link" => Some(0x42_004A),
                        "Name" => Some(0x42_0053),
                        "ObjectType" => Some(0x42_0057),
                        "OriginalCreationDate" => Some(0x42_00BC),
                        "RandomNumberGenerator" => Some(0x42_00DE),
                        "State" => Some(0x42_008D),
                        "UniqueIdentifier" => Some(0x42_0094),
                        "ShortUniqueIdentifier" => Some(0x42_0136),
                        "AlwaysSensitive" => Some(0x42_0121),
                        "NeverExtractable" => Some(0x42_0123),
                        // Lifecycle / date-related attributes (batch added for test vectors)
                        "CompromiseDate" => Some(0x42_0020),
                        "CompromiseOccurrenceDate" => Some(0x42_0021),
                        "DeactivationDate" => Some(0x42_002F),
                        "DestroyDate" => Some(0x42_0033),
                        "ArchiveDate" => Some(0x42_0005),
                        "Extractable" => Some(0x42_0122),
                        // Usage limits related
                        "UsageLimits" => Some(0x42_0095),
                        "UsageLimitsCount" => Some(0x42_0096),
                        "UsageLimitsTotal" => Some(0x42_0097),
                        "UsageLimitsUnit" => Some(0x42_0098),
                        // Protection storage mask(s)
                        "ProtectionStorageMask" => Some(0x42_015E),
                        "ProtectionStorageMasks" => Some(0x42_015F),
                        "CommonProtectionStorageMasks" => Some(0x42_0163),
                        "PrivateProtectionStorageMasks" => Some(0x42_0164),
                        "PublicProtectionStorageMasks" => Some(0x42_0165),
                        // Validity
                        "ValidityIndicator" => Some(0x42_009B),
                        "ValidityDate" => Some(0x42_009A),
                        // KMIP 1.4 mandatory vectors include this AttributeName in GetAttributeList.
                        // Even if the Rust KMIP 1.4 model does not expose an Attribute::Fresh variant,
                        // the XML test vectors are normative and must remain parseable.
                        "Fresh" => Some(0x42_00CB),
                        // Misc frequently referenced attributes
                        "Description" => Some(0x42_00FC),
                        "ProcessStartDate" => Some(0x42_0067),
                        "ProtectStopDate" => Some(0x42_0068),
                        "RevocationReason" => Some(0x42_0081),
                        "RevocationReasonCode" => Some(0x42_0082),
                        // Sensitivity related
                        "Sensitive" => Some(0x42_0120),
                        // Name & alternative naming structures
                        "ApplicationSpecificInformation" => Some(0x42_0004),
                        "AlternativeName" => Some(0x42_00BF),
                        // Certificate related frequently referenced
                        "CertificateLength" => Some(0x42_00AD),
                        "CertificateSubjectCN" => Some(0x42_0108),
                        // Random number generation related
                        // Accept both historical internal form RngAlgorithm and spec form RNGAlgorithm
                        "RngAlgorithm" | "RNGAlgorithm" => Some(0x42_00DA),
                        _ => None,
                    }
                };
                // Support decimal or 0x prefixed hexadecimal numeric enumeration literals.
                let (v, final_name) = if let Some(stripped) = raw.strip_prefix("0x") {
                    match u32::from_str_radix(stripped, 16) {
                        Ok(num) => (num, name.unwrap_or("").to_owned()),
                        Err(_) => {
                            if let Some((code, canonical)) = lookup_enum_code(raw) {
                                (code, canonical.to_owned())
                            } else if let Some(code) = lookup_attribute_reference_tag(raw) {
                                (code, name.unwrap_or(raw).to_owned())
                            } else {
                                return Err(KmipError::Default(format!(
                                    "unknown Enumeration value '{raw}'"
                                )));
                            }
                        }
                    }
                } else {
                    match raw.parse::<u32>() {
                        Ok(num) => (num, name.unwrap_or("").to_owned()),
                        Err(_) => {
                            if let Some((code, canonical)) = lookup_enum_code(raw) {
                                (code, canonical.to_owned())
                            } else if let Some(code) = lookup_attribute_reference_tag(raw) {
                                (code, name.unwrap_or(raw).to_owned())
                            } else {
                                return Err(KmipError::Default(format!(
                                    "unknown Enumeration value '{raw}'"
                                )));
                            }
                        }
                    }
                };
                Enumeration(KmipEnumerationVariant {
                    value: v,
                    name: final_name,
                })
            }
            "Boolean" => Boolean(
                match value.ok_or_else(|| KmipError::Default("missing value".into()))? {
                    "true" => true,
                    "false" => false,
                    other => return Err(KmipError::Default(format!("invalid boolean: {other}"))),
                },
            ),
            "TextString" => TextString(value.unwrap_or("").to_owned()),
            "ByteString" => ByteString(
                value
                    .map(|v| hex::decode(v).unwrap_or_default())
                    .unwrap_or_default(),
            ),
            "DateTime" => {
                let raw = value.ok_or_else(|| KmipError::Default("missing value".into()))?;
                // Accept either epoch seconds (numeric) or RFC3339/ISO8601 string
                let trimmed = raw.trim();
                if trimmed.chars().all(|c| c.is_ascii_digit()) {
                    let ts: i64 = trimmed.parse().map_err(|e| {
                        KmipError::Default(format!("datetime parse: {e}; raw='{raw}'"))
                    })?;
                    DateTime(
                        OffsetDateTime::from_unix_timestamp(ts)
                            .map_err(|e| KmipError::Default(format!("etime: {e}")))?,
                    )
                } else if trimmed
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '+' || c == '-')
                    && trimmed.chars().any(|c| c == '+' || c == '-')
                {
                    // Support simple integer arithmetic expressions like "0+3600" or "1695000000-60+30"
                    // Strictly left-to-right evaluation (only + and -) with integer components.
                    let mut total: i64 = 0;
                    let mut buf = String::new();
                    let mut sign: i64 = 1; // sign for current term
                    let mut first = true;
                    for ch in trimmed.chars() {
                        match ch {
                            '+' | '-' => {
                                if !buf.is_empty() {
                                    let part: i64 = buf.parse().map_err(|e| {
                                        KmipError::Default(format!(
                                            "datetime expr parse: {e}; raw='{raw}'"
                                        ))
                                    })?;
                                    if first {
                                        total = part * sign;
                                        first = false;
                                    } else {
                                        total += part * sign;
                                    }
                                    buf.clear();
                                } else if first && ch == '-' {
                                    // Leading negative sign before first digits
                                }
                                sign = if ch == '-' { -1 } else { 1 };
                            }
                            d if d.is_ascii_digit() => buf.push(d),
                            other => {
                                return Err(KmipError::Default(format!(
                                    "invalid char '{other}' in datetime arithmetic expression '{raw}'"
                                )));
                            }
                        }
                    }
                    if !buf.is_empty() {
                        let part: i64 = buf.parse().map_err(|e| {
                            KmipError::Default(format!("datetime expr parse: {e}; raw='{raw}'"))
                        })?;
                        if first {
                            total = part * sign;
                        } else {
                            total += part * sign;
                        }
                    }
                    DateTime(
                        OffsetDateTime::from_unix_timestamp(total)
                            .map_err(|e| KmipError::Default(format!("etime: {e}")))?,
                    )
                } else {
                    // Attempt flexible RFC3339 parse
                    let parsed = OffsetDateTime::parse(
                        trimmed,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .map_err(|e| KmipError::Default(format!("datetime parse: {e}; raw='{raw}'")))?;
                    DateTime(parsed)
                }
            }
            "Interval" => Interval(
                value
                    .ok_or_else(|| KmipError::Default("missing value".into()))?
                    .parse()
                    .map_err(|e| KmipError::Default(format!("interval parse: {e}")))?,
            ),
            "DateTimeExtended" => DateTimeExtended(
                value
                    .ok_or_else(|| KmipError::Default("missing value".into()))?
                    .parse()
                    .map_err(|e| KmipError::Default(format!("dtext parse: {e}")))?,
            ),
            other => return Err(KmipError::Default(format!("unsupported type: {other}"))),
        })
    }
}
