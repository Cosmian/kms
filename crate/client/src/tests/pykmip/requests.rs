use cosmian_logger::log_init;
use tracing::info;

use crate::{
    kmip_1_4::{
        kmip_data_structures::TemplateAttribute,
        kmip_operations::{Create, Operation, Query},
        kmip_types::{
            CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, ObjectType,
            QueryFunction,
        },
    },
    send_to_pykmip_server,
};

#[test]
fn test_query() {
    log_init(option_env!("RUST_LOG"));

    let query = Query {
        query_function: Some(vec![
            QueryFunction::QueryOperations,
            QueryFunction::QueryObjects,
        ]),
    };

    let query_response = send_to_pykmip_server!(query, Query, QueryResponse);

    let Some(supported_operations) = &query_response.operation else {
        panic!("No supported operations")
    };
    assert!(!supported_operations.is_empty());
}

#[test]
fn test_create_aes_symmetric_key() {
    // log_init(option_env!("RUST_LOG"));
    log_init(Some("debug"));
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(128),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::KeyAgreement,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        // object_type: Some(ObjectType::SymmetricKey), // Not supported by the PyKMIP server
        // unique_identifier: Some(key_id), // Not supported by the PyKMIP server
        sensitive: Some(false),
        // custom_attribute: Some(vec![CustomAttributeValue::TextString(
        //     "custom value".to_owned(),
        // )]),  // Not supported by the PyKMIP server
        ..Attributes::default()
    };
    // Note: PyKMIP server does not support Custom Attributes with Structures
    // attributes
    //     .set_tags(&["tag1".to_owned(), "tag2".to_owned()])
    //     .unwrap();

    let create_kk = Create {
        object_type: ObjectType::SymmetricKey,
        template_attribute: TemplateAttribute {
            attribute: Some(attributes.to_attributes()),
        },
    };

    let response = send_to_pykmip_server!(create_kk, Create, CreateResponse);

    info!("Response: {:#?}", response);
}
