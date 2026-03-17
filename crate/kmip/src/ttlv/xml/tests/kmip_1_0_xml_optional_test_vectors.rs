//! Non-regression tests for KMIP 1.0 optional XML test vectors.
//!
//! Test vectors are sourced from the OASIS KMIP 1.0 profile specifications:
//! - SKLC-O (Symmetric Key Lifecycle — optional)
//! - SKFF-O (Symmetric Key Find and Fetch — optional)
//! - AKLC-O (Asymmetric Key Lifecycle — optional)
//! - OMOS-O (Opaque Managed Object Store — optional)
//!
//! Each XML file in `./src/kmip_1_0/specifications/XML/optional/` contains
//! one or more `RequestMessage` / `ResponseMessage` pairs wrapped in a
//! `<KmipTestCase>` root element.

use std::{fs, path::PathBuf};

use crate::ttlv::xml::KmipXmlDoc;

#[test]
fn test_parse_all_kmip_1_0_optional_vectors() {
    let base = PathBuf::from("./src/kmip_1_0/specifications/XML/optional");
    assert!(base.is_dir(), "optional directory missing: {base:?}");
    let mut parsed = 0_usize;
    let mut failures: Vec<String> = Vec::new();
    for entry in fs::read_dir(&base).expect("list optional dir") {
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
        "Failed to parse {} KMIP 1.0 optional vector(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(parsed > 0, "no xml files parsed");
}

// ── SKLC-O (Symmetric Key Lifecycle — optional) ───────────────────────────────

#[test]
fn test_sklc_o_1_kmip_1_0() {
    let path = PathBuf::from("./src/kmip_1_0/specifications/XML/optional/SKLC-O-1-10.xml");
    assert!(path.is_file(), "missing {path:?}");
    let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        doc.requests.len(),
        doc.responses.len(),
        "SKLC-O-1: mismatched req/resp count"
    );
}

// ── SKFF-O (Symmetric Key Find and Fetch — optional) ─────────────────────────

#[test]
fn test_skff_o_1_to_6_kmip_1_0() {
    for i in 1..=6_usize {
        let name = format!("SKFF-O-{i}-10.xml");
        let path = PathBuf::from(format!("./src/kmip_1_0/specifications/XML/optional/{name}"));
        assert!(path.is_file(), "missing {path:?}");
        let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("parse {name}: {e}"));
        assert_eq!(
            doc.requests.len(),
            doc.responses.len(),
            "SKFF-O-{i}: mismatched req/resp count"
        );
    }
}

// ── AKLC-O (Asymmetric Key Lifecycle — optional) ──────────────────────────────

#[test]
fn test_aklc_o_1_kmip_1_0() {
    let path = PathBuf::from("./src/kmip_1_0/specifications/XML/optional/AKLC-O-1-10.xml");
    assert!(path.is_file(), "missing {path:?}");
    let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        doc.requests.len(),
        doc.responses.len(),
        "AKLC-O-1: mismatched req/resp count"
    );
}

// ── OMOS-O (Opaque Managed Object Store — optional) ──────────────────────────

#[test]
fn test_omos_o_1_kmip_1_0() {
    let path = PathBuf::from("./src/kmip_1_0/specifications/XML/optional/OMOS-O-1-10.xml");
    assert!(path.is_file(), "missing {path:?}");
    let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        doc.requests.len(),
        doc.responses.len(),
        "OMOS-O-1: mismatched req/resp count"
    );
}
