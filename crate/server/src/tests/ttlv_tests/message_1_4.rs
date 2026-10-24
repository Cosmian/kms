//! KMIP 1.4 message-level semantics over the binary socket: ID Placeholder for requests that
//! omit the Unique Identifier, and per-item failure of operations the server does not run.

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{
            BatchErrorContinuationOption, CryptographicUsageMask, ProtocolVersion,
            ResultStatusEnumeration,
        },
    },
    kmip_1_4::{
        kmip_attributes::Attribute,
        kmip_data_structures::TemplateAttribute,
        kmip_messages::{RequestMessageBatchItem, ResponseMessageBatchItem},
        kmip_operations::{Create, Destroy, Operation, Query},
        kmip_types::{
            CryptographicAlgorithm, ObjectType, OperationEnumeration, QueryFunction, ResultReason,
        },
    },
    ttlv::{KmipEnumerationVariant, KmipFlavor, TTLV, TTLValue, from_ttlv, to_ttlv},
};
use cosmian_logger::log_init;

use crate::tests::ttlv_tests::get_client;

fn header(
    batch_count: i32,
    batch_error_continuation_option: Option<BatchErrorContinuationOption>,
) -> RequestMessageHeader {
    RequestMessageHeader {
        protocol_version: ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 4,
        },
        batch_count,
        batch_error_continuation_option,
        ..Default::default()
    }
}

fn item(id: &[u8], operation: Operation) -> RequestMessageBatchItemVersioned {
    let mut item = RequestMessageBatchItem::new(operation);
    item.unique_batch_item_id = Some(id.to_vec());
    RequestMessageBatchItemVersioned::V14(item)
}

fn v14(response: &ResponseMessage, index: usize) -> &ResponseMessageBatchItem {
    let Some(ResponseMessageBatchItemVersioned::V14(item)) = response.batch_item.get(index) else {
        panic!("Expected KMIP 1.4 response batch item {index}");
    };
    item
}

/// A KMIP 1.4 Destroy without Unique Identifier uses the ID Placeholder set by the Create
/// before it in the batch (KMIP 1.4 §4.21: the Unique Identifier is optional).
#[test]
fn test_omitted_unique_identifier_uses_id_placeholder_1_4_binary() {
    log_init(option_env!("RUST_LOG"));
    let create = Operation::Create(Create {
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
    });
    let response = get_client()
        .send_request::<RequestMessage, ResponseMessage>(
            KmipFlavor::Kmip1,
            &RequestMessage {
                request_header: header(2, None),
                batch_item: vec![
                    item(b"create", create),
                    item(
                        b"destroy",
                        Operation::Destroy(Destroy {
                            unique_identifier: None,
                        }),
                    ),
                ],
            },
        )
        .expect("Failed to send request");
    assert_eq!(response.batch_item.len(), 2);
    let Some(Operation::CreateResponse(created)) = &v14(&response, 0).response_payload else {
        panic!("Expected CreateResponse");
    };
    let destroy = v14(&response, 1);
    assert_eq!(destroy.result_status, ResultStatusEnumeration::Success);
    let Some(Operation::DestroyResponse(destroyed)) = &destroy.response_payload else {
        panic!("Expected DestroyResponse");
    };
    assert_eq!(destroyed.unique_identifier, created.unique_identifier);
}

/// A server-to-client operation (Notify) fails its own item with Operation Not Supported;
/// with Continue, the next item still runs.
#[test]
fn test_unsupported_operation_fails_per_item_1_4_binary() {
    log_init(option_env!("RUST_LOG"));
    let query = || {
        Operation::Query(Query {
            query_function: Some(vec![QueryFunction::QueryOperations]),
        })
    };
    let mut ttlv = to_ttlv(&RequestMessage {
        request_header: header(2, Some(BatchErrorContinuationOption::Continue)),
        batch_item: vec![item(b"notify", query()), item(b"query", query())],
    })
    .expect("Failed to serialize request");
    let TTLValue::Structure(children) = &mut ttlv.value else {
        panic!("Expected RequestMessage structure");
    };
    let Some(TTLValue::Structure(first_item)) = children
        .iter_mut()
        .find(|child| &*child.tag == "BatchItem")
        .map(|child| &mut child.value)
    else {
        panic!("Expected BatchItem structure");
    };
    for child in first_item.iter_mut() {
        if &*child.tag == "Operation" {
            child.value = TTLValue::Enumeration(KmipEnumerationVariant {
                value: 0x0000_001B,
                name: "Notify".into(),
            });
        }
    }
    let request_bytes = ttlv.to_bytes(KmipFlavor::Kmip1).expect("Failed to encode");
    let response_bytes = get_client()
        .send_raw_request(&request_bytes)
        .expect("Failed to send request");
    let response: ResponseMessage = from_ttlv(
        TTLV::from_bytes(&response_bytes, KmipFlavor::Kmip1).expect("Invalid response TTLV"),
    )
    .expect("Invalid response message");
    assert_eq!(response.batch_item.len(), 2);
    let notify = v14(&response, 0);
    assert_eq!(notify.operation, Some(OperationEnumeration::Notify));
    assert_eq!(notify.unique_batch_item_id, Some(b"notify".to_vec()));
    assert_eq!(
        notify.result_reason,
        Some(ResultReason::OperationNotSupported)
    );
    assert_eq!(
        v14(&response, 1).result_status,
        ResultStatusEnumeration::Success
    );
}
