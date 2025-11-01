use std::{fs, path::PathBuf};

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
    let base = PathBuf::from("./src/kmip_2_1/specifications/XML/mandatory");
    assert!(base.is_dir(), "mandatory directory missing: {base:?}");
    let mut parsed = 0_usize;
    for entry in fs::read_dir(&base).expect("list mandatory dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("xml") {
            continue;
        }
        let doc = KmipXmlDoc::new_with_file(&path).expect("parse xml test vector");
        assert_eq!(
            doc.requests.len(),
            doc.responses.len(),
            "mismatched req/resp count in {path:?}"
        );
        // (Optional) validations could go here; currently we only assert the file parses.
        parsed += 1;
    }
    assert!(parsed > 0, "no xml files parsed");
}

#[test]
fn tl_m_3_21_attribute_reference_count() {
    let path = PathBuf::from("./src/kmip_2_1/specifications/XML/mandatory/TL-M-3-21.xml");
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
