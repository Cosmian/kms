use cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4::{
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{GetAttributes, Operation},
        kmip_types::OperationEnumeration,
    },
    ttlv::KmipFlavor,
};
use cosmian_kms_client::SocketClient;
use cosmian_logger::log_init;
use log::info;

use super::create_1_4::create_symmetric_key;
use crate::tests::ttlv_tests::{add_attribute_1_4::add_attributes, get_client};

#[test]
fn test_get_attribute_1_4() {
    // log_init(option_env!("RUST_LOG"));
    log_init(Some("debug"));

    let client = get_client();

    // Create a symmetric key
    let key_id = create_symmetric_key(&client);
    info!("Key ID: {}", key_id);

    add_attributes(&client, &key_id);

    // Add attributes to the key
    get_attributes(&client, &key_id);
}

pub(crate) fn get_attributes(client: &SocketClient, key_id: &str) {
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::GetAttributes,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::GetAttributes(GetAttributes {
                    unique_identifier: key_id.to_owned(),
                    attribute_name: Some(vec![
                        "x-Product_Version".to_owned(),
                        "x-Vendor".to_owned(),
                    ]),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send request");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 1,
        }
    );
    assert_eq!(response.batch_item.len(), 3);

    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };
    let ResponseMessageBatchItemVersioned::V14(batch_item) = response_batch_item else {
        panic!("Expected V14 response message");
    };
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    assert_eq!(batch_item.unique_batch_item_id, Some(b"12345".to_vec()));
    let Some(Operation::AddAttributeResponse(_add_att_response)) = &batch_item.response_payload
    else {
        panic!("Expected AddAttributeResponse");
    };
}
