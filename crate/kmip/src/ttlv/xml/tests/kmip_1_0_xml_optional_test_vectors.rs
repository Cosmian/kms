//! Non-regression tests for KMIP 1.0 optional XML test vectors.
//!
//! Test vectors are sourced from the OASIS KMIP 1.0 profile specifications:
//! - SKLC-O (Symmetric Key Lifecycle — optional)
//! - SKFF-O (Symmetric Key Find and Fetch — optional)
//! - AKLC-O (Asymmetric Key Lifecycle — optional)
//! - OMOS-O (Opaque Managed Object Store — optional)
//!
//! Each XML file in `../../kmip/v1.0/XML/optional/` contains
//! one or more `RequestMessage` / `ResponseMessage` pairs wrapped in a
//! `<KmipTestCase>` root element.

use std::path::PathBuf;

use super::common::parse_all_xml_vectors;
use crate::ttlv::xml::KmipXmlDoc;

#[test]
fn test_parse_all_kmip_1_0_optional_vectors() {
    parse_all_xml_vectors("../../kmip/v1.0/XML/optional", "KMIP 1.0 optional");
}

// ── SKLC-O (Symmetric Key Lifecycle — optional) ───────────────────────────────

#[test]
fn test_sklc_o_1_kmip_1_0() {
    let path = PathBuf::from("../../kmip/v1.0/XML/optional/SKLC-O-1-10.xml");
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
        let path = PathBuf::from(format!("../../kmip/v1.0/XML/optional/{name}"));
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
    let path = PathBuf::from("../../kmip/v1.0/XML/optional/AKLC-O-1-10.xml");
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
    let path = PathBuf::from("../../kmip/v1.0/XML/optional/OMOS-O-1-10.xml");
    assert!(path.is_file(), "missing {path:?}");
    let doc = KmipXmlDoc::new_with_file(&path).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        doc.requests.len(),
        doc.responses.len(),
        "OMOS-O-1: mismatched req/resp count"
    );
}
