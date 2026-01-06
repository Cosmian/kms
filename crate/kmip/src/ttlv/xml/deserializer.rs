//! Deterministic test XML -> TTLV deserializer utilities (split from `serializer.rs`).
//!
//! Provides `TTLVXMLDeserializer::from_xml` used for round‑trip unit tests.

use std::collections::HashSet;

use quick_xml::{Reader, events::Event};
use time::OffsetDateTime;

use crate::{
    KmipError,
    ttlv::{KmipEnumerationVariant, TTLV, TTLValue},
};

// Strict behavior is now always enforced for enumerations and usage mask tokens.
// We still tolerate missing type="Structure" in upstream test vectors for
// interoperability (some community vectors omit it), but all other previously
// "permissive" fallbacks are removed.
const ALLOW_IMPLICIT_STRUCTURE: bool = true; // keep acceptance of existing vectors

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
                // Try numeric first; otherwise attempt known textual KMIP enumeration name mapping.
                // Returns (code, canonical_variant_name)
                let lookup_enum_code = |s: &str| -> Option<(u32, &'static str)> {
                    // Normalized variants (strip optional hyphens in some aliases for matching)
                    let key = s.replace('-', "_");
                    match key.as_str() {
                        // Operations (OperationEnumeration) with correct KMIP codes
                        "Create" => Some((0x0000_0001, "Create")),
                        "CreateKeyPair" => Some((0x0000_0002, "CreateKeyPair")),
                        "Register" => Some((0x0000_0003, "Register")),
                        "ReKey" => Some((0x0000_0004, "ReKey")),
                        "DeriveKey" => Some((0x0000_0005, "DeriveKey")),
                        "Certify" => Some((0x0000_0006, "Certify")),
                        "ReCertify" => Some((0x0000_0007, "ReCertify")),
                        "Locate" => Some((0x0000_0008, "Locate")),
                        "Check" => Some((0x0000_0009, "Check")),
                        "Get" => Some((0x0000_000A, "Get")),
                        "GetAttributes" => Some((0x0000_000B, "GetAttributes")),
                        "GetAttributeList" => Some((0x0000_000C, "GetAttributeList")),
                        "AddAttribute" => Some((0x0000_000D, "AddAttribute")),
                        "ModifyAttribute" => Some((0x0000_000E, "ModifyAttribute")),
                        "DeleteAttribute" => Some((0x0000_000F, "DeleteAttribute")),
                        "ObtainLease" => Some((0x0000_0010, "ObtainLease")),
                        "GetUsageAllocation" => Some((0x0000_0011, "GetUsageAllocation")),
                        "Activate" => Some((0x0000_0012, "Activate")),
                        "Revoke" => Some((0x0000_0013, "Revoke")),
                        "Destroy" => Some((0x0000_0014, "Destroy")),
                        "Archive" => Some((0x0000_0015, "Archive")),
                        "Recover" => Some((0x0000_0016, "Recover")),
                        "Validate" => Some((0x0000_0017, "Validate")),
                        "Query" => Some((0x0000_0018, "Query")),
                        "Cancel" => Some((0x0000_0019, "Cancel")),
                        "Poll" => Some((0x0000_001A, "Poll")),
                        "Notify" => Some((0x0000_001B, "Notify")),
                        "Put" => Some((0x0000_001C, "Put")),
                        "ReKeyKeyPair" => Some((0x0000_001D, "ReKeyKeyPair")),
                        "DiscoverVersions" => Some((0x0000_001E, "DiscoverVersions")),
                        "Encrypt" => Some((0x0000_001F, "Encrypt")),
                        "Decrypt" => Some((0x0000_0020, "Decrypt")),
                        "Sign" => Some((0x0000_0021, "Sign")),
                        "SignatureVerify" => Some((0x0000_0022, "SignatureVerify")),
                        "MAC" => Some((0x0000_0023, "MAC")),
                        "MACVerify" => Some((0x0000_0024, "MACVerify")),
                        "RNGRetrieve" => Some((0x0000_0025, "RNGRetrieve")),
                        "RNGSeed" => Some((0x0000_0026, "RNGSeed")),
                        "Hash" => Some((0x0000_0027, "Hash")),
                        "CreateSplitKey" => Some((0x0000_0028, "CreateSplitKey")),
                        "JoinSplitKey" => Some((0x0000_0029, "JoinSplitKey")),
                        "Import" => Some((0x0000_002A, "Import")),
                        "Export" => Some((0x0000_002B, "Export")),
                        "Log" => Some((0x0000_002C, "Log")),
                        "Login" => Some((0x0000_002D, "Login")),
                        "Logout" => Some((0x0000_002E, "Logout")),
                        "DelegatedLogin" => Some((0x0000_002F, "DelegatedLogin")),
                        "AdjustAttribute" => Some((0x0000_0030, "AdjustAttribute")),
                        "SetAttribute" => Some((0x0000_0031, "SetAttribute")),
                        "SetEndpointRole" => Some((0x0000_0032, "SetEndpointRole")),
                        // Map both textual spellings to the canonical Rust enum variant PKCS11
                        "PKCS_11" | "PKCS11" => Some((0x0000_0033, "PKCS11")),
                        "Interop" => Some((0x0000_0034, "Interop")),
                        "ReProvision" => Some((0x0000_0035, "ReProvision")),
                        "SetDefaults" => Some((0x0000_0036, "SetDefaults")),
                        "SetConstraints" => Some((0x0000_0037, "SetConstraints")),
                        "GetConstraints" => Some((0x0000_0038, "GetConstraints")),
                        "QueryAsynchronousRequests" => {
                            Some((0x0000_0039, "QueryAsynchronousRequests"))
                        }
                        "Process" => Some((0x0000_003A, "Process")),
                        "Ping" => Some((0x0000_003B, "Ping")),
                        // QueryFunction enumeration
                        "QueryOperations" => Some((0x0000_0001, "QueryOperations")),
                        "QueryObjects" => Some((0x0000_0002, "QueryObjects")),
                        "QueryServerInformation" => Some((0x0000_0003, "QueryServerInformation")),
                        "QueryApplicationNamespaces" => {
                            Some((0x0000_0004, "QueryApplicationNamespaces"))
                        }
                        "QueryExtensionList" => Some((0x0000_0005, "QueryExtensionList")),
                        "QueryExtensionMap" => Some((0x0000_0006, "QueryExtensionMap")),
                        "QueryAttestationTypes" => Some((0x0000_0007, "QueryAttestationTypes")),
                        "QueryRNGs" => Some((0x0000_0008, "QueryRNGs")),
                        "QueryValidations" => Some((0x0000_0009, "QueryValidations")),
                        "QueryProfiles" => Some((0x0000_000A, "QueryProfiles")),
                        "QueryCapabilities" => Some((0x0000_000B, "QueryCapabilities")),
                        "QueryClientRegistrationMethods" => {
                            Some((0x0000_000C, "QueryClientRegistrationMethods"))
                        }
                        "QueryDefaultsInformation" => {
                            Some((0x0000_000D, "QueryDefaultsInformation"))
                        }
                        "QueryStorageProtectionMasks" => {
                            Some((0x0000_000E, "QueryStorageProtectionMasks"))
                        }
                        // ResultStatusEnumeration
                        "Success" => Some((0x0000_0000, "Success")),
                        "OperationFailed" => Some((0x0000_0001, "OperationFailed")),
                        "OperationPending" | "Pending" => Some((0x0000_0002, "OperationPending")),
                        "OperationUndone" => Some((0x0000_0003, "OperationUndone")),
                        // BatchErrorContinuationOption / Undo (value 3) should use canonical name "Undo"
                        "Undo" => Some((0x0000_0003, "Undo")),
                        // ObjectType
                        "Certificate" => Some((0x0000_0001, "Certificate")),
                        "SymmetricKey" => Some((0x0000_0002, "SymmetricKey")),
                        "PublicKey" => Some((0x0000_0003, "PublicKey")),
                        "PrivateKey" => Some((0x0000_0004, "PrivateKey")),
                        "SecretData" => Some((0x0000_0007, "SecretData")),
                        "SplitKey" => Some((0x0000_0005, "SplitKey")),
                        "Template" => Some((0x0000_0006, "Template")),
                        "OpaqueObject" => Some((0x0000_0008, "OpaqueObject")),
                        "PGPKey" => Some((0x0000_0009, "PGPKey")),
                        "CertificateRequest" => Some((0x0000_000A, "CertificateRequest")),
                        // NameType
                        "UninterpretedTextString" => Some((0x1, "UninterpretedTextString")),
                        "URI" => Some((0x2, "URI")),
                        // SecretDataType
                        "Password" => Some((0x0000_0001, "Password")),
                        "Seed" => Some((0x0000_0002, "Seed")),
                        // State
                        "PreActive" => Some((0x0000_0001, "PreActive")),
                        "Active" => Some((0x0000_0002, "Active")),
                        "Deactivated" => Some((0x0000_0003, "Deactivated")),
                        "Compromised" => Some((0x0000_0004, "Compromised")),
                        "Destroyed" => Some((0x0000_0005, "Destroyed")),
                        "DestroyedCompromised" => Some((0x0000_0006, "DestroyedCompromised")),
                        // KeyFormatType (aliases from vectors)
                        "Raw" => Some((0x01, "Raw")),
                        "Opaque" => Some((0x02, "Opaque")),
                        "PKCS1" | "PKCS_1" => Some((0x03, "PKCS1")),
                        "PKCS8" | "PKCS_8" => Some((0x04, "PKCS8")),
                        "X509" | "X_509" => Some((0x05, "X509")),
                        // Additional KeyFormatType values frequently seen in interop vectors
                        "ECPrivateKey" => Some((0x0000_0011, "ECPrivateKey")),
                        "TransparentRSAPublicKey" => Some((0x0000_0006, "TransparentRSAPublicKey")),
                        "TransparentRSAPrivateKey" => {
                            Some((0x0000_0007, "TransparentRSAPrivateKey"))
                        }
                        "TransparentSymmetricKey" => Some((0x0000_0007, "TransparentSymmetricKey")),
                        "TransparentDSAPublicKey" => Some((0x0000_0008, "TransparentDSAPublicKey")),
                        "TransparentDSAPrivateKey" => {
                            Some((0x0000_0009, "TransparentDSAPrivateKey"))
                        }
                        "TransparentDHPrivateKey" => Some((0x0000_000B, "TransparentDHPrivateKey")),
                        "TransparentDHPublicKey" => Some((0x0000_000A, "TransparentDHPublicKey")),
                        "TransparentECDSAPublicKey" => {
                            Some((0x0000_000C, "TransparentECDSAPublicKey"))
                        }
                        "TransparentECDSAPrivateKey" => {
                            Some((0x0000_000D, "TransparentECDSAPrivateKey"))
                        }
                        "TransparentECDHPrivateKey" => {
                            Some((0x0000_000F, "TransparentECDHPrivateKey"))
                        }
                        "TransparentECDHPublicKey" => {
                            Some((0x0000_000E, "TransparentECDHPublicKey"))
                        }
                        "TransparentECMQVPrivateKey" => {
                            Some((0x0000_0010, "TransparentECMQVPrivateKey"))
                        }
                        // CryptographicAlgorithm (canonical Rust enum variant names have no underscore after HMAC)
                        "DES" => Some((0x0000_0001, "DES")),
                        // KMIP 1.4 enum variant is named `ThreeES` while KMIP 2.1 uses `THREE_DES`.
                        // To remain cross-version compatible, emit only the numeric code and leave
                        // the name empty so downstream typed deserialization matches by value.
                        "THREE_DES" | "3DES" | "DES3" => Some((0x0000_0002, "")),
                        "AES" => Some((0x0000_0003, "AES")),
                        "RSA" => Some((0x0000_0004, "RSA")),
                        "DSA" => Some((0x0000_0005, "DSA")),
                        "ECDSA" => Some((0x0000_0006, "ECDSA")),
                        // Vendor / extension algorithms present in mandatory vectors
                        "HMAC_SHA1" => Some((0x0000_0007, "HMACSHA1")),
                        "HMAC_SHA224" => Some((0x0000_0008, "HMACSHA224")),
                        "HMAC_SHA256" => Some((0x0000_0009, "HMACSHA256")),
                        "HMAC_SHA384" => Some((0x0000_000A, "HMACSHA384")),
                        "HMAC_SHA512" => Some((0x0000_000B, "HMACSHA512")),
                        "ChaCha20" => Some((0x0000_001C, "ChaCha20")),
                        "ChaCha20Poly1305" => Some((0x0000_001E, "ChaCha20Poly1305")),
                        // HashingAlgorithm (XML uses SHA_256 style, canonical variant removes underscore)
                        "SHA1" | "SHA_1" => Some((0x0000_0004, "SHA1")),
                        "SHA224" | "SHA_224" => Some((0x0000_0005, "SHA224")),
                        "SHA256" | "SHA_256" => Some((0x0000_0006, "SHA256")),
                        "SHA384" | "SHA_384" => Some((0x0000_0007, "SHA384")),
                        "SHA512" | "SHA_512" => Some((0x0000_0008, "SHA512")),
                        // RevocationReasonCode (spec 1.0 Table 167) - only mapping needed by vectors currently
                        "Unspecified" | "UNSPECIFIED_RNG" | "RNG_Unspecified" => {
                            Some((0x0000_0001, "Unspecified"))
                        }
                        "KeyCompromise" => Some((0x0000_0002, "KeyCompromise")),
                        "CACompromise" => Some((0x0000_0003, "CACompromise")),
                        // ErrorReason (ResultReason) mappings (KMIP 1.x/2.x) - textual camelCase used in vectors
                        "ItemNotFound" => Some((0x0000_0001, "Item_Not_Found")),
                        "ResponseTooLarge" => Some((0x0000_0002, "Response_Too_Large")),
                        "AuthenticationNotSuccessful" => {
                            Some((0x0000_0003, "Authentication_Not_Successful"))
                        }
                        "InvalidMessage" => Some((0x0000_0004, "Invalid_Message")),
                        "OperationNotSupported" => Some((0x0000_0005, "Operation_Not_Supported")),
                        "MissingData" => Some((0x0000_0006, "Missing_Data")),
                        "InvalidField" => Some((0x0000_0007, "Invalid_Field")),
                        "FeatureNotSupported" => Some((0x0000_0008, "Feature_Not_Supported")),
                        "OperationCanceledByRequester" => {
                            Some((0x0000_0009, "Operation_Canceled_By_Requester"))
                        }
                        "CryptographicFailure" => Some((0x0000_000A, "Cryptographic_Failure")),
                        "PermissionDenied" => Some((0x0000_000C, "Permission_Denied")),
                        "ObjectArchived" => Some((0x0000_000D, "Object_Archived")),
                        "ApplicationNamespaceNotSupported" => {
                            Some((0x0000_000F, "Application_Namespace_Not_Supported"))
                        }
                        "KeyFormatTypeNotSupported" => {
                            Some((0x0000_0010, "Key_Format_Type_Not_Supported"))
                        }
                        "KeyCompressionTypeNotSupported" => {
                            Some((0x0000_0011, "Key_Compression_Type_Not_Supported"))
                        }
                        "EncodingOptionError" => Some((0x0000_0012, "Encoding_Option_Error")),
                        "KeyValueNotPresent" => Some((0x0000_0013, "Key_Value_Not_Present")),
                        "AttestationRequired" => Some((0x0000_0014, "Attestation_Required")),
                        "AttestationFailed" => Some((0x0000_0015, "Attestation_Failed")),
                        "Sensitive" => Some((0x0000_0016, "Sensitive")),
                        "NotExtractable" => Some((0x0000_0017, "Not_Extractable")),
                        "ObjectAlreadyExists" => Some((0x0000_0018, "Object_Already_Exists")),
                        "InvalidTicket" => Some((0x0000_0019, "Invalid_Ticket")),
                        "UsageLimitExceeded" => Some((0x0000_001A, "Usage_Limit_Exceeded")),
                        "NumericRange" => Some((0x0000_001B, "Numeric_Range")),
                        "InvalidDataType" => Some((0x0000_001C, "Invalid_Data_Type")),
                        "ReadOnlyAttribute" => Some((0x0000_001D, "Read_Only_Attribute")),
                        "MultiValuedAttribute" => Some((0x0000_001E, "Multi_Valued_Attribute")),
                        "UnsupportedAttribute" => Some((0x0000_001F, "Unsupported_Attribute")),
                        "AttributeInstanceNotFound" => {
                            Some((0x0000_0020, "Attribute_Instance_Not_Found"))
                        }
                        "AttributeNotFound" => Some((0x0000_0021, "Attribute_Not_Found")),
                        "AttributeReadOnly" => Some((0x0000_0022, "Attribute_Read_Only")),
                        "AttributeSingleValued" => Some((0x0000_0023, "Attribute_Single_Valued")),
                        "BadCryptographicParameters" => {
                            Some((0x0000_0024, "Bad_Cryptographic_Parameters"))
                        }
                        "BadPassword" => Some((0x0000_0025, "Bad_Password")),
                        "CodecError" => Some((0x0000_0026, "Codec_Error")),
                        "IllegalObjectType" => Some((0x0000_0028, "Illegal_Object_Type")),
                        "IncompatibleCryptographicUsageMask" => {
                            Some((0x0000_0029, "Incompatible_Cryptographic_Usage_Mask"))
                        }
                        "InternalServerError" => Some((0x0000_002A, "Internal_Server_Error")),
                        "InvalidAsynchronousCorrelationValue" => {
                            Some((0x0000_002B, "Invalid_Asynchronous_Correlation_Value"))
                        }
                        "InvalidAttribute" => Some((0x0000_002C, "Invalid_Attribute")),
                        "InvalidAttributeValue" => Some((0x0000_002D, "Invalid_Attribute_Value")),
                        "InvalidCorrelationValue" => {
                            Some((0x0000_002E, "Invalid_Correlation_Value"))
                        }
                        "InvalidCSR" => Some((0x0000_002F, "Invalid_CSR")),
                        "InvalidObjectType" => Some((0x0000_0030, "Invalid_Object_Type")),
                        "KeyWrapTypeNotSupported" => {
                            Some((0x0000_0032, "Key_Wrap_Type_Not_Supported"))
                        }
                        "MissingInitializationVector" => {
                            Some((0x0000_0034, "Missing_Initialization_Vector"))
                        }
                        "NonUniqueNameAttribute" => {
                            Some((0x0000_0035, "Non_Unique_Name_Attribute"))
                        }
                        "ObjectDestroyed" => Some((0x0000_0036, "Object_Destroyed")),
                        "ObjectNotFound" => Some((0x0000_0037, "Object_Not_Found")),
                        "NotAuthorised" => Some((0x0000_0039, "Not_Authorised")),
                        "ServerLimitExceeded" => Some((0x0000_003A, "Server_Limit_Exceeded")),
                        "UnknownEnumeration" => Some((0x0000_003B, "Unknown_Enumeration")),
                        "UnknownMessageExtension" => {
                            Some((0x0000_003C, "Unknown_Message_Extension"))
                        }
                        "UnknownTag" => Some((0x0000_003D, "Unknown_Tag")),
                        "UnsupportedCryptographicParameters" => {
                            Some((0x0000_003E, "Unsupported_Cryptographic_Parameters"))
                        }
                        "UnsupportedProtocolVersion" => {
                            Some((0x0000_003F, "Unsupported_Protocol_Version"))
                        }
                        "WrappingObjectArchived" => Some((0x0000_0040, "Wrapping_Object_Archived")),
                        "WrappingObjectDestroyed" => {
                            Some((0x0000_0041, "Wrapping_Object_Destroyed"))
                        }
                        "WrappingObjectNotFound" => {
                            Some((0x0000_0042, "Wrapping_Object_Not_Found"))
                        }
                        "WrongKeyLifecycleState" => {
                            Some((0x0000_0043, "Wrong_Key_Lifecycle_State"))
                        }
                        "ProtectionStorageUnavailable" => {
                            Some((0x0000_0044, "Protection_Storage_Unavailable"))
                        }
                        "PKCS11CodecError" => Some((0x0000_0045, "PKCS_11_Codec_Error")),
                        "PKCS11InvalidFunction" => Some((0x0000_0046, "PKCS_11_Invalid_Function")),
                        "PKCS11InvalidInterface" => {
                            Some((0x0000_0047, "PKCS_11_Invalid_Interface"))
                        }
                        "PrivateProtectionStorageUnavailable" => {
                            Some((0x0000_0048, "Private_Protection_Storage_Unavailable"))
                        }
                        "PublicProtectionStorageUnavailable" => {
                            Some((0x0000_0049, "Public_Protection_Storage_Unavailable"))
                        }
                        "UnknownObjectGroup" => Some((0x0000_004A, "Unknown_Object_Group")),
                        "ConstraintViolation" => Some((0x0000_004B, "Constraint_Violation")),
                        "DuplicateProcessRequest" => {
                            Some((0x0000_004C, "Duplicate_Process_Request"))
                        }
                        "GeneralFailure" => Some((0x0000_0100, "General_Failure")),
                        // ValidityIndicator (KMIP 1.4 / 2.1) values
                        "Valid" => Some((0x0000_0001, "Valid")),
                        "Invalid" => Some((0x0000_0002, "Invalid")),
                        "Fresh" => Some((0x0000_0003, "Fresh")),
                        // BlockCipherMode
                        "GCM" => Some((0x0000_0009, "GCM")),
                        "CBC" => Some((0x0000_0001, "CBC")),
                        "ECB" => Some((0x0000_0002, "ECB")),
                        "XTS" => Some((0x0000_000B, "XTS")),
                        "CTR" => Some((0x0000_0006, "CTR")),
                        "CFB" => Some((0x0000_0004, "CFB")),
                        "OFB" => Some((0x0000_0005, "OFB")),
                        "PCBC" => Some((0x0000_0003, "PCBC")),
                        "CCM" => Some((0x0000_0008, "CCM")),
                        "CMAC" => Some((0x0000_0007, "CMAC")),
                        "AEAD" => Some((0x0000_0012, "AEAD")),
                        "AESKeyWrapPadding" => Some((0x0000_000C, "AESKeyWrapPadding")),
                        "NISTKeyWrap" => Some((0x0000_000D, "NISTKeyWrap")),
                        // PaddingMethod
                        "None" => Some((0x1, "None")),
                        "OAEP" => Some((0x2, "OAEP")),
                        "PKCS5" => Some((0x0000_0008, "PKCS5")),
                        "PKCS7" => Some((0x0000_0009, "PKCS7")),
                        "PSS" => Some((0x0000_000A, "PSS")),
                        // RNGAlgorithm (vectors alias ANSIX9_31 for ANSI_X931)
                        "ANSI_X931" | "ANSIX9_31" | "ANSI_X9_31" => Some((0x5, "ANSI_X931")),
                        "FIPS186_2" | "FIPS_186_2" => Some((0x2, "FIPS186_2")),
                        "DRBG" => Some((0x3, "DRBG")),
                        "NRBG" => Some((0x4, "NRBG")),
                        "ANSI_X962" | "ANSI_X9_62" => Some((0x6, "ANSI_X962")),
                        // UsageLimitsUnit (KMIP 2.1 Table 517)
                        "Byte" => Some((0x0000_0001, "Byte")),
                        "Block" => Some((0x0000_0002, "Block")),
                        "Object" => Some((0x0000_0003, "Object")),
                        "Operation" => Some((0x0000_0004, "Operation")),
                        // ProtectionLevel (KMIP 2.1 Profiles QS-M-2-21 etc.)
                        "Low" => Some((0x0000_0001, "Low")),
                        "Medium" => Some((0x0000_0002, "Medium")),
                        "High" => Some((0x0000_0003, "High")),
                        // BatchErrorContinuationOption (codes overlap with general small integers)
                        "Continue" => Some((0x0000_0001, "Continue")),
                        "Stop" => Some((0x0000_0002, "Stop")),
                        // MaskGenerator (OAEP) - spec default MGF1 maps to enum variant MFG1
                        "MGF1" => Some((0x0000_0001, "MFG1")),
                        // InteropFunction (used in BL-M-* vectors) values per spec draft: Begin, End
                        "Begin" => Some((0x0000_0001, "Begin")),
                        "End" => Some((0x0000_0002, "End")),
                        // PKCS#11 Function names (subset used in test vectors). These MUST match the
                        // discriminant values of the PKCS11Function enum defined in kmip_operations.rs
                        // (C_Initialize=0x0000_0001, C_GetInfo=0x0000_0002, C_Finalize=0x0000_0003). The
                        // previous vendor-range placeholder codes (0x8000_0001..) caused a mismatch when the
                        // XML parser produced Enumeration TTLV elements whose numeric values could not be
                        // mapped back to the enum, leading to downstream deserialization cursor corruption
                        // and the observed u8 DateTime mismatch panic. Aligning these codes restores proper
                        // enum round‑trip semantics for PKCS11-M-1-21.
                        "C_Initialize" => Some((0x0000_0001, "C_Initialize")),
                        "C_GetInfo" => Some((0x0000_0002, "C_GetInfo")),
                        "C_Finalize" => Some((0x0000_0003, "C_Finalize")),
                        // PKCS#11 Return Codes subset
                        "OK" => Some((0x0000_0000, "OK")),
                        // LinkType enumeration (KMIP 2.1)
                        "CertificateLink" => Some((0x0000_0101, "CertificateLink")),
                        "PublicKeyLink" => Some((0x0000_0102, "PublicKeyLink")),
                        "PrivateKeyLink" => Some((0x0000_0103, "PrivateKeyLink")),
                        "DerivationBaseObjectLink" => {
                            Some((0x0000_0104, "DerivationBaseObjectLink"))
                        }
                        "DerivedKeyLink" => Some((0x0000_0105, "DerivedKeyLink")),
                        "ReplacementObjectLink" => Some((0x0000_0106, "ReplacementObjectLink")),
                        "ReplacedObjectLink" => Some((0x0000_0107, "ReplacedObjectLink")),
                        "ParentLink" => Some((0x0000_0108, "ParentLink")),
                        "ChildLink" => Some((0x0000_0109, "ChildLink")),
                        "PreviousLink" => Some((0x0000_010A, "PreviousLink")),
                        "NextLink" => Some((0x0000_010B, "NextLink")),
                        "PKCS12CertificateLink" => Some((0x0000_010C, "PKCS12CertificateLink")),
                        "PKCS12PasswordLink" => Some((0x0000_010D, "PKCS12PasswordLink")),
                        "WrappingKeyLink" => Some((0x0000_010E, "WrappingKeyLink")),
                        _ => None,
                    }
                };
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
