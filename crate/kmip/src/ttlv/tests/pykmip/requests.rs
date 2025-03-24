use cosmian_logger::log_init;
use tracing::{info, trace};

use crate::{
    kmip_1_4::{
        kmip_attributes::Attributes,
        kmip_data_structures::TemplateAttribute,
        kmip_messages::{
            RequestMessage, RequestMessageBatchItem, RequestMessageHeader, ResponseMessage,
        },
        kmip_operations::{Create, Operation, Query},
        kmip_types::{
            CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, ObjectType,
            OperationEnumeration, ProtocolVersion, QueryFunction,
        },
    },
    send_to_pykmip_server,
    ttlv::{self, from_ttlv, tests::pykmip::socket_client::create_default_client, to_ttlv},
};

#[test]
fn test_query() {
    log_init(option_env!("RUST_LOG"));
    let client = create_default_client().unwrap();

    // Create a simple KMIP request (same as HTTP client test)
    let request_data = request_message();
    let response = client.send_request(&request_data).unwrap();
    // Check that we got a response
    assert!(!response.is_empty());

    // parse the response TTLV bytes
    let ttlv = ttlv::TTLV::from_bytes_1_4(&response).unwrap();
    info!("Response TTLV: {:#?}", ttlv);

    // parse the response message
    let response_message = from_ttlv::<ResponseMessage>(ttlv).unwrap();
    info!("Response Message: {:#?}", response_message);

    // check the `MessageResponse` is a `QueryResponse`
    #[allow(clippy::expect_used)]
    let Operation::QueryResponse(query_response) = response_message
        .batch_item
        .first()
        .expect("No batch item")
        .response_payload
        .as_ref()
        .expect("No response payload")
    else {
        panic!("No Query Response")
    };
    let Some(supported_operations) = &query_response.operation else {
        panic!("No supported operations")
    };
    assert!(!supported_operations.is_empty());
}

fn request_message() -> Vec<u8> {
    // KMIP Request Message (same as HTTP client test)
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 4,
            },
            maximum_response_size: Some(1_048_576),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItem {
            operation: OperationEnumeration::Query,
            ephemeral: None,
            unique_batch_item_id: None,
            request_payload: Operation::Query(Query {
                query_function: vec![QueryFunction::QueryOperations, QueryFunction::QueryObjects],
            }),
            message_extension: None,
        }],
    };

    let ttlv = to_ttlv(&request_message).unwrap();
    trace!("Request TTLV: {:#?}", ttlv);
    ttlv.to_bytes_1_4().unwrap()
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
    // PyKMIP server does not support Custom Attributes with Structures
    // attributes
    //     .set_tags(&["tag1".to_owned(), "tag2".to_owned()])
    //     .unwrap();

    // let kk = SymmetricKey {
    //     key_block: KeyBlock {
    //         cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
    //         key_format_type: KeyFormatType::TransparentSymmetricKey,
    //         key_compression_type: None,
    //         key_value: Some(KeyValue {
    //             key_material: KeyMaterial::TransparentSymmetricKey {
    //                 key: Zeroizing::from(key_bytes),
    //             },
    //             attributes: Some(attributes),
    //         }),
    //         cryptographic_length: Some(128),
    //         key_wrapping_data: None,
    //     },
    // };
    let create_kk = Create {
        object_type: ObjectType::SymmetricKey,
        template_attribute: TemplateAttribute {
            attribute: Some(attributes.to_attributes()),
            name: None,
        },
    };

    let response = send_to_pykmip_server!(create_kk, Create, CreateResponse);

    info!("Response: {:#?}", response);
}
