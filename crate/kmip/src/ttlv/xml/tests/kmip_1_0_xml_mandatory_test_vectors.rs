//! Non-regression tests for KMIP 1.0 mandatory XML test vectors.
//!
//! Test vectors are sourced from the OASIS KMIP 1.0 profile specifications:
//! - SKLC (Symmetric Key Lifecycle)
//! - SKFF (Symmetric Key Find and Fetch)
//! - AKLC (Asymmetric Key Lifecycle)
//! - OMOS (Opaque Managed Object Store)
//!
//! Each XML file in `./src/kmip_1_0/specifications/XML/mandatory/` contains
//! one or more `RequestMessage` / `ResponseMessage` pairs wrapped in a
//! `<KmipTestCase>` root element.  The parser strips the wrapper and deserialises
//! the KMIP messages via the TTLV XML pipeline.

use std::{fs, path::PathBuf};

use crate::ttlv::xml::KmipXmlDoc;

#[test]
fn test_parse_all_kmip_1_0_mandatory_vectors() {
    let base = PathBuf::from("./src/kmip_1_0/specifications/XML/mandatory");
    assert!(base.is_dir(), "mandatory directory missing: {base:?}");
    let mut parsed = 0_usize;
    let mut failures: Vec<String> = Vec::new();
    for entry in fs::read_dir(&base).expect("list mandatory dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("xml") {
            continue;
        }
        match KmipXmlDoc::new_with_file(&path) {
            Ok(doc) => {
                assert_eq!(
                    doc.requests.len(),
                    doc.responses.len(),
                    "mismatched req/resp count in {path:?}"
                );
                parsed += 1;
            }
            Err(e) => {
                failures.push(format!("{}: {e}", path.display()));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "Failed to parse {} KMIP 1.0 mandatory vector(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(parsed > 0, "no xml files parsed");
}

// ── SKLC (Symmetric Key Lifecycle) ───────────────────────────────────────────

#[test]
fn test_sklc_m_1_kmip_1_0() {
    let path = PathBuf::from("./src/kmip_1_0/specifications/XML/mandatory/SKLC-M-1-10.xml");
    assert!(path.is_file(), "missing {path:?}");
    let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("{e}"));
    // Create + GetAttributes + Destroy = 3 request/response pairs
    assert_eq!(doc.requests.len(), 3, "SKLC-M-1: expected 3 requests");
    assert_eq!(doc.responses.len(), 3, "SKLC-M-1: expected 3 responses");
}

#[test]
fn test_sklc_m_2_kmip_1_0() {
    let path = PathBuf::from("./src/kmip_1_0/specifications/XML/mandatory/SKLC-M-2-10.xml");
    assert!(path.is_file(), "missing {path:?}");
    let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        doc.requests.len(),
        doc.responses.len(),
        "SKLC-M-2: mismatched req/resp count"
    );
}

#[test]
fn test_sklc_m_3_kmip_1_0() {
    let path = PathBuf::from("./src/kmip_1_0/specifications/XML/mandatory/SKLC-M-3-10.xml");
    assert!(path.is_file(), "missing {path:?}");
    let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        doc.requests.len(),
        doc.responses.len(),
        "SKLC-M-3: mismatched req/resp count"
    );
}

// ── SKFF (Symmetric Key Find and Fetch) ──────────────────────────────────────

#[test]
fn test_skff_m_1_kmip_1_0() {
    let path = PathBuf::from("./src/kmip_1_0/specifications/XML/mandatory/SKFF-M-1-10.xml");
    assert!(path.is_file(), "missing {path:?}");
    let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("{e}"));
    // Create + Destroy = 2 pairs
    assert_eq!(doc.requests.len(), 2, "SKFF-M-1: expected 2 requests");
    assert_eq!(doc.responses.len(), 2, "SKFF-M-1: expected 2 responses");
}

#[test]
fn test_skff_m_2_to_12_kmip_1_0() {
    for i in 2..=12_usize {
        let name = format!("SKFF-M-{i}-10.xml");
        let path = PathBuf::from(format!(
            "./src/kmip_1_0/specifications/XML/mandatory/{name}"
        ));
        assert!(path.is_file(), "missing {path:?}");
        let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("parse {name}: {e}"));
        assert_eq!(
            doc.requests.len(),
            doc.responses.len(),
            "SKFF-M-{i}: mismatched req/resp count"
        );
    }
}

// ── AKLC (Asymmetric Key Lifecycle) ──────────────────────────────────────────

#[test]
fn test_aklc_m_1_kmip_1_0() {
    let path = PathBuf::from("./src/kmip_1_0/specifications/XML/mandatory/AKLC-M-1-10.xml");
    assert!(path.is_file(), "missing {path:?}");
    let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        doc.requests.len(),
        doc.responses.len(),
        "AKLC-M-1: mismatched req/resp count"
    );
}

#[test]
fn test_aklc_m_2_kmip_1_0() {
    let path = PathBuf::from("./src/kmip_1_0/specifications/XML/mandatory/AKLC-M-2-10.xml");
    assert!(path.is_file(), "missing {path:?}");
    let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        doc.requests.len(),
        doc.responses.len(),
        "AKLC-M-2: mismatched req/resp count"
    );
}

#[test]
fn test_aklc_m_3_kmip_1_0() {
    let path = PathBuf::from("./src/kmip_1_0/specifications/XML/mandatory/AKLC-M-3-10.xml");
    assert!(path.is_file(), "missing {path:?}");
    let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        doc.requests.len(),
        doc.responses.len(),
        "AKLC-M-3: mismatched req/resp count"
    );
}

// ── OMOS (Opaque Managed Object Store) ───────────────────────────────────────

#[test]
fn test_omos_m_1_kmip_1_0() {
    let path = PathBuf::from("./src/kmip_1_0/specifications/XML/mandatory/OMOS-M-1-10.xml");
    assert!(path.is_file(), "missing {path:?}");
    let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("{e}"));
    // Register + Destroy = 2 pairs
    assert_eq!(doc.requests.len(), 2, "OMOS-M-1: expected 2 requests");
    assert_eq!(doc.responses.len(), 2, "OMOS-M-1: expected 2 responses");
}
