use super::common::parse_all_xml_vectors;

#[test]
fn test_parse_all_kmip_2_0_optional_vectors() {
    parse_all_xml_vectors("../../kmip/v2.0/XML/optional", "KMIP 2.0 optional");
}
