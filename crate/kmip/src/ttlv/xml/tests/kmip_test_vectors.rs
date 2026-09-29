//! Non-regression tests for KMIP XML test vectors across all supported versions.
//!
//! Test vectors are sourced from OASIS KMIP profile specifications (v1.0 through v2.1).
//! Each XML file contains one or more `RequestMessage` / `ResponseMessage` pairs.
//! The parser deserialises the KMIP messages via the TTLV XML pipeline.

use super::common::xml_vector_test;

// ═══════════════════════════════════════════════════════════════════════════════
// KMIP 1.0
// ═══════════════════════════════════════════════════════════════════════════════

xml_vector_test!(
    test_parse_all_kmip_1_0_mandatory_vectors,
    "../../kmip/v1.0/XML/mandatory",
    "KMIP 1.0 mandatory"
);
xml_vector_test!(
    test_parse_all_kmip_1_0_optional_vectors,
    "../../kmip/v1.0/XML/optional",
    "KMIP 1.0 optional"
);

// ═══════════════════════════════════════════════════════════════════════════════
// KMIP 1.3
// ═══════════════════════════════════════════════════════════════════════════════

/// SASED-M-2-13.xml uses the `Template` object type (deprecated in KMIP 2.0,
/// not supported by our parser) — skip it.
const KMIP_1_3_MANDATORY_SKIP: &[&str] = &["SASED-M-2-13.xml"];

#[test]
fn test_parse_all_kmip_1_3_mandatory_vectors() {
    super::common::parse_all_xml_vectors_with_skip(
        "../../kmip/v1.3/XML/mandatory",
        "KMIP 1.3 mandatory",
        KMIP_1_3_MANDATORY_SKIP,
    );
}

xml_vector_test!(
    test_parse_all_kmip_1_3_optional_vectors,
    "../../kmip/v1.3/XML/optional",
    "KMIP 1.3 optional"
);

// ═══════════════════════════════════════════════════════════════════════════════
// KMIP 1.4
// ═══════════════════════════════════════════════════════════════════════════════

xml_vector_test!(
    test_parse_all_kmip_1_4_mandatory_vectors,
    "../../kmip/v1.4/XML/mandatory",
    "KMIP 1.4 mandatory"
);
xml_vector_test!(
    test_parse_all_kmip_1_4_optional_vectors,
    "../../kmip/v1.4/XML/optional",
    "KMIP 1.4 optional"
);

// ═══════════════════════════════════════════════════════════════════════════════
// KMIP 2.0
// ═══════════════════════════════════════════════════════════════════════════════

xml_vector_test!(
    test_parse_all_kmip_2_0_mandatory_vectors,
    "../../kmip/v2.0/XML/mandatory",
    "KMIP 2.0 mandatory"
);
xml_vector_test!(
    test_parse_all_kmip_2_0_optional_vectors,
    "../../kmip/v2.0/XML/optional",
    "KMIP 2.0 optional"
);

// ═══════════════════════════════════════════════════════════════════════════════
// KMIP 2.1
// ═══════════════════════════════════════════════════════════════════════════════

xml_vector_test!(
    test_parse_all_kmip_2_1_mandatory_vectors,
    "../../kmip/v2.1/XML/mandatory",
    "KMIP 2.1 mandatory"
);
xml_vector_test!(
    test_parse_all_kmip_2_1_optional_vectors,
    "../../kmip/v2.1/XML/optional",
    "KMIP 2.1 optional"
);
