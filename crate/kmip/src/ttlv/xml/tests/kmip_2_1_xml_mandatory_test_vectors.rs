use std::path::PathBuf;

use super::common::parse_all_xml_vectors;
use crate::{
    kmip_0::kmip_messages::ResponseMessageBatchItemVersioned as V,
    kmip_2_1::{
        kmip_messages::ResponseMessageBatchItem, kmip_operations::Operation,
        kmip_types::AttributeReference,
    },
    ttlv::xml::KmipXmlDoc,
};

#[test]
fn test_parse_all_kmip_2_1_mandatory_vectors() {
    parse_all_xml_vectors("../../kmip/v2.1/XML/mandatory", "KMIP 2.1 mandatory");
}

#[test]
fn tl_m_3_21_attribute_reference_count() {
    let path = PathBuf::from("../../kmip/v2.1/XML/mandatory/TL-M-3-21.xml");
    assert!(path.is_file(), "missing TL-M-3-21.xml at {path:?}");
    let doc = KmipXmlDoc::new_with_file(&path).expect("parse TL-M-3-21.xml");
    // Find the response containing GetAttributeList

    // Iterate all responses and their batch items to find the GetAttributeList response payload
    let mut found = false;
    for resp in &doc.responses {
        for bi in &resp.batch_item {
            if let V::V21(ResponseMessageBatchItem {
                response_payload: Some(Operation::GetAttributeListResponse(ga)),
                ..
            }) = bi
            {
                let refs = ga
                    .attribute_references
                    .as_ref()
                    .expect("attribute_references");
                assert_eq!(refs.len(), 28, "expected 28 AttributeReference items");
                let vendor_count = refs
                    .iter()
                    .filter(|r| matches!(r, AttributeReference::Vendor(_)))
                    .count();
                assert_eq!(vendor_count, 5, "expected 5 VendorAttribute references");
                found = true;
                break;
            }
        }
        if found {
            break;
        }
    }
    assert!(
        found,
        "did not find GetAttributeListResponse in TL-M-3-21 responses"
    );
}
