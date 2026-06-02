use super::common::parse_all_xml_vectors_with_skip;

/// Files that use deprecated KMIP 1.x features not supported by the current parser.
/// - `SASED-M-2-13.xml`: uses the `Template` object type (deprecated in KMIP 1.4, removed in 2.0).
const SKIP_FILES: &[&str] = &["SASED-M-2-13.xml"];

#[test]
fn test_parse_all_kmip_1_3_mandatory_vectors() {
    parse_all_xml_vectors_with_skip(
        "../../kmip/v1.3/XML/mandatory",
        "KMIP 1.3 mandatory",
        SKIP_FILES,
    );
}
