use std::{fs, path::PathBuf};

use crate::ttlv::xml::KmipXmlDoc;

#[test]
fn test_parse_all_kmip_1_4_optional_vectors() {
    let base = PathBuf::from("./src/kmip_1_4/specifications/XML/optional");
    assert!(base.is_dir(), "optional directory missing: {base:?}");
    let mut parsed = 0_usize;
    for entry in fs::read_dir(&base).expect("list optional dir") {
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
        parsed += 1;
    }
    assert!(parsed > 0, "no xml files parsed");
}
