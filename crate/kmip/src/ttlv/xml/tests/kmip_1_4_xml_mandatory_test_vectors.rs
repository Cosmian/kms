use super::common::parse_all_xml_vectors;

#[test]
fn test_parse_all_kmip_1_4_mandatory_vectors() {
    parse_all_xml_vectors("../../kmip/v1.4/XML/mandatory", "KMIP 1.4 mandatory");
}
