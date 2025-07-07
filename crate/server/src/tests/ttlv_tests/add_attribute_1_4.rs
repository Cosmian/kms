use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4::{
        kmip_attributes::{Attribute, CustomAttributeValue},
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{AddAttribute, Operation},
        kmip_types::OperationEnumeration,
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;
use log::info;

use super::{create_1_4::create_symmetric_key, socket_client::SocketClient};
use crate::tests::ttlv_tests::get_client;

#[test]
fn test_add_attribute_1_4() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));

    let client = get_client();

    // Create a symmetric key
    let key_id = create_symmetric_key(&client);
    info!("Key ID: {key_id}");

    // Add attributes to the key
    add_attributes(&client, &key_id);
}

pub(crate) fn add_attributes(client: &SocketClient, key_id: &str) {
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 4,
            },
            batch_count: 3,
            ..Default::default()
        },
        batch_item: vec![
            RequestMessageBatchItemVersioned::V14(RequestMessageBatchItem {
                operation: OperationEnumeration::AddAttribute,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::AddAttribute(AddAttribute {
                    unique_identifier: key_id.to_owned(),
                    attribute: Attribute::CustomAttribute((
                        "x-Product_Version".to_owned(),
                        CustomAttributeValue::TextString("7.0.3 build-19480866".to_owned()),
                    )),
                }),
                message_extension: None,
            }),
            RequestMessageBatchItemVersioned::V14(RequestMessageBatchItem {
                operation: OperationEnumeration::AddAttribute,
                ephemeral: None,
                unique_batch_item_id: Some(b"123456".to_vec()),
                request_payload: Operation::AddAttribute(AddAttribute {
                    unique_identifier: key_id.to_owned(),
                    attribute: Attribute::CustomAttribute((
                        "x-Vendor".to_owned(),
                        CustomAttributeValue::TextString("VMware, Inc.".to_owned()),
                    )),
                }),
                message_extension: None,
            }),
            RequestMessageBatchItemVersioned::V14(RequestMessageBatchItem {
                operation: OperationEnumeration::AddAttribute,
                ephemeral: None,
                unique_batch_item_id: Some(b"123456".to_vec()),
                request_payload: Operation::AddAttribute(AddAttribute {
                    unique_identifier: key_id.to_owned(),
                    attribute: Attribute::CustomAttribute((
                        "x-Product".to_owned(),
                        CustomAttributeValue::TextString("VMware vSphere".to_owned()),
                    )),
                }),
                message_extension: None,
            }),
        ],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send request");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 4,
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
