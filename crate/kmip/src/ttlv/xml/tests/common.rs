//! Shared helpers for KMIP XML test vector parsing.

use std::{fs, path::PathBuf};

use crate::ttlv::xml::KmipXmlDoc;

/// Generate a test function that parses all XML vectors in a directory.
///
/// Usage:
/// ```ignore
/// xml_vector_test!(test_name, "../../kmip/v1.4/XML/mandatory", "KMIP 1.4 mandatory");
/// ```
macro_rules! xml_vector_test {
    ($name:ident, $dir:expr, $label:expr) => {
        #[test]
        fn $name() {
            super::common::parse_all_xml_vectors($dir, $label);
        }
    };
}

pub(super) use xml_vector_test;

/// Parse all XML files in the given directory and assert:
/// - each file parses successfully
/// - request/response counts match in every file
///
/// Returns the number of successfully parsed files.
///
/// # Panics
/// Panics if any file fails to parse or has mismatched req/resp counts.
pub(super) fn parse_all_xml_vectors(dir: &str, version_label: &str) -> usize {
    parse_all_xml_vectors_with_skip(dir, version_label, &[])
}

/// Same as [`parse_all_xml_vectors`] but allows skipping specific filenames.
///
/// `skip_files` contains basenames (e.g. `"SASED-M-2-13.xml"`) to exclude from
/// parsing — typically because they use deprecated KMIP features not supported
/// by the current parser (e.g. the `Template` object type removed in KMIP 2.0).
pub(super) fn parse_all_xml_vectors_with_skip(
    dir: &str,
    version_label: &str,
    skip_files: &[&str],
) -> usize {
    let base = PathBuf::from(dir);
    assert!(base.is_dir(), "{version_label} directory missing: {base:?}");
    let mut parsed = 0_usize;
    let mut failures: Vec<String> = Vec::new();
    for entry in fs::read_dir(&base).expect("list dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("xml") {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if skip_files.contains(&name) {
                continue;
            }
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
        "{version_label} XML parse failures:\n{}",
        failures.join("\n")
    );
    assert!(parsed > 0, "{version_label}: no xml files parsed");
    parsed
}
