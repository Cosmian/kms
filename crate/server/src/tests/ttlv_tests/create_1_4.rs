use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{CryptographicUsageMask, ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4::{
        kmip_attributes::Attribute,
        kmip_data_structures::TemplateAttribute,
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Create, Operation},
        kmip_types::{CryptographicAlgorithm, ObjectType, OperationEnumeration},
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;

use super::socket_client::SocketClient;
use crate::tests::ttlv_tests::get_client;

#[test]
fn test_create_1_4() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();

    // Create a symmetric key
    create_symmetric_key(&client);
}

pub(super) fn create_symmetric_key(client: &SocketClient) -> String {
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
                operation: OperationEnumeration::Create,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::Create(Create {
                    object_type: ObjectType::SymmetricKey,
                    template_attribute: TemplateAttribute {
                        attribute: Some(vec![
                            Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                            Attribute::CryptographicUsageMask(
                                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                            ),
                            Attribute::CryptographicLength(256),
                        ]),
                    },
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
    assert_eq!(response.batch_item.len(), 1);

    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };

    let ResponseMessageBatchItemVersioned::V14(batch_item) = response_batch_item else {
        panic!("Expected V14 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    assert_eq!(batch_item.unique_batch_item_id, Some(b"12345".to_vec()));

    let Some(Operation::CreateResponse(create_response)) = &batch_item.response_payload else {
        panic!("Expected CreateResponse");
    };

    assert!(create_response.object_type == ObjectType::SymmetricKey);
    assert!(!create_response.unique_identifier.is_empty());
    assert!(create_response.template_attribute.is_none());
    create_response.unique_identifier.clone()
}
