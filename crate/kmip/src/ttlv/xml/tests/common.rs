//! Shared helpers for KMIP XML test vector parsing.

use std::{collections::BTreeSet, fs, path::PathBuf};

use crate::{
    kmip_0::kmip_messages::{RequestMessage, ResponseMessage},
    ttlv::{
        KmipFlavor, TTLV, TTLValue, from_ttlv, to_ttlv,
        xml::{KmipXmlDoc, parse_message_ttlvs},
    },
};

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

const ROUND_TRIP_ALLOWED_DROPS: &[(&str, &str)] = &[
    // not modelled: Attributes.certificate_subject_cn
    ("BL-M-10-21.xml", "CertificateSubjectCN"),
    // `$MAC_DATA` placeholder decodes to an empty ByteString, and an empty MAC Verify
    // `mac_data` is omitted (optional for multi-part MAC Verify)
    ("CS-AC-M-6-13.xml", "MACData"),
    ("CS-AC-M-6-14.xml", "MACData"),
    ("CS-AC-M-6-20.xml", "MACData"),
    ("CS-AC-M-6-21.xml", "MACData"),
];

fn tag_names(ttlv: &TTLV) -> BTreeSet<String> {
    let mut tags = BTreeSet::new();
    tags.insert(ttlv.tag.to_string());
    if let TTLValue::Structure(children) = &ttlv.value {
        for child in children {
            tags.extend(tag_names(child));
        }
    }
    tags
}

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
        let xml = match fs::read_to_string(&path) {
            Ok(xml) => xml,
            Err(e) => {
                failures.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        let doc = match KmipXmlDoc::new(&xml) {
            Ok(doc) => doc,
            Err(e) => {
                failures.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        let ttlvs = match parse_message_ttlvs(&xml) {
            Ok(ttlvs) => ttlvs,
            Err(e) => {
                failures.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        if doc.requests.len() != doc.responses.len() {
            failures.push(format!(
                "mismatched req/resp count in {}: {} requests, {} responses",
                path.display(),
                doc.requests.len(),
                doc.responses.len()
            ));
            continue;
        }

        let flavor = if dir.contains("/v1.") {
            KmipFlavor::Kmip1
        } else {
            KmipFlavor::Kmip2
        };
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let mut round_trip_ok = true;
        for original in ttlvs {
            let original_tags = tag_names(&original);
            let again = match original.tag.as_ref() {
                "RequestMessage" => from_ttlv::<RequestMessage>(original.clone())
                    .and_then(|message| to_ttlv(&message)),
                "ResponseMessage" => from_ttlv::<ResponseMessage>(original.clone())
                    .and_then(|message| to_ttlv(&message)),
                tag => {
                    failures.push(format!(
                        "{}: unexpected top-level tag {tag}",
                        path.display()
                    ));
                    round_trip_ok = false;
                    continue;
                }
            };
            let again = match again {
                Ok(ttlv) => ttlv,
                Err(e) => {
                    failures.push(format!("{}: TTLV round trip failed: {e}", path.display()));
                    round_trip_ok = false;
                    continue;
                }
            };
            if let Err(e) = again.to_bytes(flavor) {
                failures.push(format!(
                    "{}: round-trip TTLV is not binary encodable: {e}",
                    path.display()
                ));
                round_trip_ok = false;
            }
            let dropped = original_tags
                .difference(&tag_names(&again))
                .filter(|tag| {
                    !ROUND_TRIP_ALLOWED_DROPS.iter().any(|(file, allowed_tag)| {
                        *file == file_name && *allowed_tag == tag.as_str()
                    })
                })
                .cloned()
                .collect::<Vec<_>>();
            if !dropped.is_empty() {
                failures.push(format!(
                    "{}: round trip dropped tags {dropped:?}",
                    path.display()
                ));
                round_trip_ok = false;
            }
        }
        if round_trip_ok {
            parsed += 1;
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
