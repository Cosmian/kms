use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ErrorReason, ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Operation, RNGRetrieve, RNGSeed},
        kmip_types::OperationEnumeration,
    },
    ttlv::{KmipFlavor, TTLV, TTLValue, from_ttlv, to_ttlv},
};
use cosmian_logger::log_init;

use crate::tests::ttlv_tests::get_client;

#[test]
fn test_rng_retrieve_and_seed_2_1_binary() {
    log_init(option_env!("RUST_LOG"));
    let client = get_client();
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 2,
            ..Default::default()
        },
        batch_item: vec![
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem {
                operation: OperationEnumeration::RNGRetrieve,
                ephemeral: None,
                unique_batch_item_id: Some(b"rng-retrieve".to_vec()),
                request_payload: Operation::RNGRetrieve(RNGRetrieve { data_length: 32 }),
                message_extension: None,
            }),
            RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem {
                operation: OperationEnumeration::RNGSeed,
                ephemeral: None,
                unique_batch_item_id: Some(b"rng-seed".to_vec()),
                request_payload: Operation::RNGSeed(RNGSeed {
                    data: vec![0x5A; 32],
                }),
                message_extension: None,
            }),
        ],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip2, &request_message)
        .expect("Failed to send RNG request");

    assert_eq!(response.batch_item.len(), 2);
    let ResponseMessageBatchItemVersioned::V21(retrieve) = &response.batch_item[0] else {
        panic!("Expected KMIP 2.1 RNG Retrieve response");
    };
    assert_eq!(retrieve.result_status, ResultStatusEnumeration::Success);
    assert_eq!(retrieve.operation, Some(OperationEnumeration::RNGRetrieve));
    assert_eq!(
        retrieve.unique_batch_item_id,
        Some(b"rng-retrieve".to_vec())
    );
    let Some(Operation::RNGRetrieveResponse(payload)) = &retrieve.response_payload else {
        panic!("Expected RNG Retrieve response payload");
    };
    assert_eq!(payload.data.len(), 32);

    let ResponseMessageBatchItemVersioned::V21(seed) = &response.batch_item[1] else {
        panic!("Expected KMIP 2.1 RNG Seed response");
    };
    assert_eq!(seed.result_status, ResultStatusEnumeration::Success);
    assert_eq!(seed.operation, Some(OperationEnumeration::RNGSeed));
    assert_eq!(seed.unique_batch_item_id, Some(b"rng-seed".to_vec()));
    let Some(Operation::RNGSeedResponse(payload)) = &seed.response_payload else {
        panic!("Expected RNG Seed response payload");
    };
    assert_eq!(payload.amount_of_seed_data, 32);
}

#[test]
fn test_invalid_payload_echoes_operation_2_1() {
    log_init(option_env!("RUST_LOG"));
    let client = get_client();
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem {
                operation: OperationEnumeration::RNGRetrieve,
                ephemeral: None,
                unique_batch_item_id: Some(b"rng-bad".to_vec()),
                request_payload: Operation::RNGRetrieve(RNGRetrieve { data_length: 32 }),
                message_extension: None,
            },
        )],
    };
    let mut ttlv = to_ttlv(&request_message).expect("Failed to serialize RNG request");
    let TTLValue::Structure(children) = &mut ttlv.value else {
        panic!("Expected RequestMessage structure");
    };
    let Some(batch_item) = children.iter_mut().find(|child| &*child.tag == "BatchItem") else {
        panic!("Expected BatchItem");
    };
    let TTLValue::Structure(children) = &mut batch_item.value else {
        panic!("Expected BatchItem structure");
    };
    let Some(payload) = children
        .iter_mut()
        .find(|child| &*child.tag == "RequestPayload")
    else {
        panic!("Expected RequestPayload");
    };
    payload.value = TTLValue::Structure(vec![]);

    let request_bytes = ttlv
        .to_bytes(KmipFlavor::Kmip2)
        .expect("Failed to serialize invalid request");
    let response_bytes = client
        .send_raw_request(&request_bytes)
        .expect("Failed to send invalid request");
    let response_ttlv =
        TTLV::from_bytes(&response_bytes, KmipFlavor::Kmip2).expect("Invalid response TTLV");
    let response: ResponseMessage = from_ttlv(response_ttlv).expect("Invalid response message");

    assert_eq!(response.batch_item.len(), 1);
    let ResponseMessageBatchItemVersioned::V21(batch_item) = &response.batch_item[0] else {
        panic!("Expected KMIP 2.1 response");
    };
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::OperationFailed
    );
    assert_eq!(batch_item.result_reason, Some(ErrorReason::Invalid_Message));
    assert_eq!(
        batch_item.operation,
        Some(OperationEnumeration::RNGRetrieve)
    );
    assert_eq!(batch_item.unique_batch_item_id, Some(b"rng-bad".to_vec()));
}
