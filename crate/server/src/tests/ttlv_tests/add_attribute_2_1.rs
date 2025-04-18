use cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        kmip_attributes::Attribute,
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{AddAttribute, Operation},
        kmip_types::{OperationEnumeration, VendorAttribute, VendorAttributeValue},
    },
    ttlv::KmipFlavor,
};
use cosmian_kms_client::SocketClient;
use cosmian_logger::log_init;
use log::info;

use super::create_1_4::create_symmetric_key;
use crate::tests::ttlv_tests::get_client;

#[test]
fn test_add_attribute_1_4() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));

    let client = get_client();

    // Create a symmetric key
    let key_id = create_symmetric_key(&client);
    info!("Key ID: {}", key_id);

    // Add attributes to the key
    add_attributes(&client, &key_id);
}

pub(crate) fn add_attributes(client: &SocketClient, key_id: &str) {
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 3,
            ..Default::default()
        },
        batch_item: vec![
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem {
                operation: OperationEnumeration::AddAttribute,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::AddAttribute(AddAttribute {
                    unique_identifier:
                        cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                            key_id.to_owned(),
                        ),
                    new_attribute: Attribute::VendorAttribute(VendorAttribute {
                        vendor_identification: "VMware, Inc.".to_owned(),
                        attribute_name: "x-Product_Version".to_owned(),
                        attribute_value: VendorAttributeValue::TextString(
                            "7.0.3 build-19480866".to_owned(),
                        ),
                    }),
                }),
                message_extension: None,
            }),
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem {
                operation: OperationEnumeration::AddAttribute,
                ephemeral: None,
                unique_batch_item_id: Some(b"123456".to_vec()),
                request_payload: Operation::AddAttribute(AddAttribute {
                    unique_identifier:
                        cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                            key_id.to_owned(),
                        ),
                    new_attribute: Attribute::VendorAttribute(VendorAttribute {
                        vendor_identification: "VMware, Inc.".to_owned(),
                        attribute_name: "-Product_Name".to_owned(),
                        attribute_value: VendorAttributeValue::TextString(
                            "VMware vSphere".to_owned(),
                        ),
                    }),
                }),
                message_extension: None,
            }),
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem {
                operation: OperationEnumeration::AddAttribute,
                ephemeral: None,
                unique_batch_item_id: Some(b"123456".to_vec()),
                request_payload: Operation::AddAttribute(AddAttribute {
                    unique_identifier:
                        cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                            key_id.to_owned(),
                        ),
                    new_attribute: Attribute::VendorAttribute(VendorAttribute {
                        vendor_identification: "VMware, Inc.".to_owned(),
                        attribute_name: "x-Product".to_owned(),
                        attribute_value: VendorAttributeValue::TextString(
                            "VMware vSphere".to_owned(),
                        ),
                    }),
                }),
                message_extension: None,
            }),
        ],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip2, &request_message)
        .expect("Failed to send request");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 2,
            protocol_version_minor: 1,
        }
    );
    assert_eq!(response.batch_item.len(), 3);

    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };
    let ResponseMessageBatchItemVersioned::V21(batch_item) = response_batch_item else {
        panic!("Expected V21 response message");
    };
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    assert_eq!(batch_item.unique_batch_item_id, Some(b"12345".to_vec()));
    let Some(Operation::AddAttributeResponse(_add_att_response)) = &batch_item.response_payload
    else {
        panic!("Expected AddAttributeResponse");
    };
}
