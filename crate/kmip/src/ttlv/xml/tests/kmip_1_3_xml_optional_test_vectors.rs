use super::common::parse_all_xml_vectors;

#[test]
fn test_parse_all_kmip_1_3_optional_vectors() {
    parse_all_xml_vectors("../../kmip/v1.3/XML/optional", "KMIP 1.3 optional");
}
