//! KMIP 2.1 message-level semantics over the binary socket: Batch Error Continuation Option,
//! critical Message Extensions, ID Placeholder, Ephemeral and Batch Count.

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{
            Authentication, BatchErrorContinuationOption, Credential, CredentialType,
            CredentialValue, CryptographicUsageMask, ErrorReason, MessageExtension,
            ProtocolVersion, ResultStatusEnumeration,
        },
    },
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_messages::{RequestMessageBatchItem, ResponseMessageBatchItem},
        kmip_objects::ObjectType,
        kmip_operations::{Activate, Create, Encrypt, Get, Locate, Operation, Query},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, Name, NameType, OperationEnumeration,
            QueryFunction, UniqueIdentifier,
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
            protocol_version_major: 2,
            protocol_version_minor: 1,
        },
        batch_count,
        batch_error_continuation_option,
        ..Default::default()
    }
}

fn item(operation: Operation) -> RequestMessageBatchItemVersioned {
    RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(operation))
}

fn query() -> Operation {
    Operation::Query(Query {
        query_function: Some(vec![QueryFunction::QueryOperations]),
        ..Default::default()
    })
}

fn create_aes() -> Operation {
    Operation::Create(Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
            cryptographic_length: Some(256),
            ..Default::default()
        },
        protection_storage_masks: None,
    })
}

fn send(
    request_header: RequestMessageHeader,
    batch_item: Vec<RequestMessageBatchItemVersioned>,
) -> ResponseMessage {
    get_client()
        .send_request::<RequestMessage, ResponseMessage>(
            KmipFlavor::Kmip2,
            &RequestMessage {
                request_header,
                batch_item,
            },
        )
        .expect("Failed to send request")
}

fn v21(response: &ResponseMessage, index: usize) -> &ResponseMessageBatchItem {
    let Some(ResponseMessageBatchItemVersioned::V21(item)) = response.batch_item.get(index) else {
        panic!("Expected KMIP 2.1 response batch item {index}");
    };
    item
}

fn missing_get() -> Operation {
    Operation::Get(Get {
        unique_identifier: Some(UniqueIdentifier::TextString(
            "batch-semantics-missing-object".to_owned(),
        )),
        ..Default::default()
    })
}

#[test]
fn test_batch_default_stop_2_1_binary() {
    log_init(option_env!("RUST_LOG"));
    let response = send(header(2, None), vec![item(missing_get()), item(query())]);
    assert_eq!(response.batch_item.len(), 1);
    assert_eq!(
        v21(&response, 0).result_status,
        ResultStatusEnumeration::OperationFailed
    );
}

#[test]
fn test_batch_continue_2_1_binary() {
    log_init(option_env!("RUST_LOG"));
    let response = send(
        header(2, Some(BatchErrorContinuationOption::Continue)),
        vec![item(missing_get()), item(query())],
    );
    assert_eq!(response.batch_item.len(), 2);
    assert_eq!(
        v21(&response, 0).result_status,
        ResultStatusEnumeration::OperationFailed
    );
    assert_eq!(
        v21(&response, 1).result_status,
        ResultStatusEnumeration::Success
    );
}

#[test]
fn test_critical_message_extension_2_1_binary() {
    log_init(option_env!("RUST_LOG"));
    let mut batch_item = RequestMessageBatchItem::new(query());
    batch_item.message_extension = Some(vec![MessageExtension {
        vendor_identification: "test.vendor".to_owned(),
        criticality_indicator: true,
        vendor_extension: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::VendorExtension {},
    }]);
    let response = send(
        header(1, None),
        vec![RequestMessageBatchItemVersioned::V21(batch_item)],
    );
    assert_eq!(response.batch_item.len(), 1);
    let batch_item = v21(&response, 0);
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::OperationFailed
    );
    assert_eq!(
        batch_item.result_reason,
        Some(ErrorReason::Unknown_Message_Extension)
    );
}

#[test]
fn test_omitted_unique_identifier_uses_id_placeholder_2_1_binary() {
    log_init(option_env!("RUST_LOG"));
    let request_message = RequestMessage {
        request_header: header(2, None),
        batch_item: vec![
            item(create_aes()),
            item(Operation::Activate(Activate {
                unique_identifier: UniqueIdentifier::id_placeholder(),
            })),
        ],
    };
    let mut ttlv = to_ttlv(&request_message).expect("Failed to serialize request");
    // The Activate payload is the last batch item: drop its Unique Identifier from the wire.
    let TTLValue::Structure(children) = &mut ttlv.value else {
        panic!("Expected RequestMessage structure");
    };
    let Some(TTLValue::Structure(item_children)) = children
        .iter_mut()
        .rfind(|child| &*child.tag == "BatchItem")
        .map(|child| &mut child.value)
    else {
        panic!("Expected BatchItem structure");
    };
    let Some(TTLValue::Structure(payload)) = item_children
        .iter_mut()
        .find(|child| &*child.tag == "RequestPayload")
        .map(|child| &mut child.value)
    else {
        panic!("Expected RequestPayload structure");
    };
    payload.retain(|child| &*child.tag != "UniqueIdentifier");
    assert!(payload.is_empty());

    let request_bytes = ttlv
        .to_bytes(KmipFlavor::Kmip2)
        .expect("Failed to encode request");
    let response_bytes = get_client()
        .send_raw_request(&request_bytes)
        .expect("Failed to send request");
    let response: ResponseMessage = from_ttlv(
        TTLV::from_bytes(&response_bytes, KmipFlavor::Kmip2).expect("Invalid response TTLV"),
    )
    .expect("Invalid response message");
    assert_eq!(response.batch_item.len(), 2);
    assert_eq!(
        v21(&response, 0).result_status,
        ResultStatusEnumeration::Success
    );
    assert_eq!(
        v21(&response, 1).result_status,
        ResultStatusEnumeration::Success
    );
}

#[test]
fn test_ephemeral_encrypt_2_1_binary() {
    log_init(option_env!("RUST_LOG"));
    let created = send(header(1, None), vec![item(create_aes())]);
    let Some(Operation::CreateResponse(created)) = &v21(&created, 0).response_payload else {
        panic!("Expected CreateResponse");
    };
    let activated = send(
        header(1, None),
        vec![item(Operation::Activate(Activate {
            unique_identifier: created.unique_identifier.clone(),
        }))],
    );
    assert_eq!(
        v21(&activated, 0).result_status,
        ResultStatusEnumeration::Success
    );
    let mut batch_item = RequestMessageBatchItem::new(Operation::Encrypt(Box::new(Encrypt {
        unique_identifier: Some(created.unique_identifier.clone()),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        }),
        data: Some(vec![0_u8; 16].into()),
        ..Default::default()
    })));
    batch_item.ephemeral = Some(true);
    let response = send(
        header(1, None),
        vec![RequestMessageBatchItemVersioned::V21(batch_item)],
    );
    let batch_item = v21(&response, 0);
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    let Some(Operation::EncryptResponse(encrypted)) = &batch_item.response_payload else {
        panic!("Expected EncryptResponse");
    };
    assert!(encrypted.data.is_none());
}

#[test]
fn test_batch_count_mismatch_2_1_binary() {
    log_init(option_env!("RUST_LOG"));
    let mut ttlv = to_ttlv(&RequestMessage {
        request_header: header(1, None),
        batch_item: vec![item(query())],
    })
    .expect("Failed to serialize request");
    let TTLValue::Structure(children) = &mut ttlv.value else {
        panic!("Expected RequestMessage structure");
    };
    let Some(TTLValue::Structure(header_children)) = children
        .iter_mut()
        .find(|child| &*child.tag == "RequestHeader")
        .map(|child| &mut child.value)
    else {
        panic!("Expected RequestHeader structure");
    };
    let Some(batch_count) = header_children
        .iter_mut()
        .find(|child| &*child.tag == "BatchCount")
    else {
        panic!("Expected BatchCount");
    };
    batch_count.value = TTLValue::Integer(2);

    let request_bytes = ttlv
        .to_bytes(KmipFlavor::Kmip2)
        .expect("Failed to encode request");
    let response_bytes = get_client()
        .send_raw_request(&request_bytes)
        .expect("Failed to send request");
    let response: ResponseMessage = from_ttlv(
        TTLV::from_bytes(&response_bytes, KmipFlavor::Kmip2).expect("Invalid response TTLV"),
    )
    .expect("Invalid response message");
    let batch_item = v21(&response, 0);
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::OperationFailed
    );
    assert_eq!(batch_item.result_reason, Some(ErrorReason::Invalid_Message));
}

fn send_bytes(request_bytes: &[u8]) -> ResponseMessage {
    let response_bytes = get_client()
        .send_raw_request(request_bytes)
        .expect("Failed to send request");
    from_ttlv(TTLV::from_bytes(&response_bytes, KmipFlavor::Kmip2).expect("Invalid response TTLV"))
        .expect("Invalid response message")
}

fn query_message_bytes() -> Vec<u8> {
    to_ttlv(&RequestMessage {
        request_header: header(1, None),
        batch_item: vec![item(query())],
    })
    .expect("Failed to serialize request")
    .to_bytes(KmipFlavor::Kmip2)
    .expect("Failed to encode request")
}

/// Byte offset of the first TTLV item with `tag` and `item_type` in an encoded message.
fn find_item(bytes: &[u8], tag: [u8; 3], item_type: u8) -> usize {
    bytes
        .windows(4)
        .position(|w| matches!(w, [a, b, c, t] if [*a, *b, *c] == tag && *t == item_type))
        .expect("item not found")
}

/// Undo reverts the earlier operations (KMIP 2.1 §9.6): a created object is deleted and an
/// activated key is back to Pre-Active; both items are reported Operation Undone.
#[test]
fn test_batch_undo_reverts_create_and_activate_2_1_binary() {
    log_init(option_env!("RUST_LOG"));
    let response = send(header(1, None), vec![item(create_aes())]);
    let Some(Operation::CreateResponse(created)) = &v21(&response, 0).response_payload else {
        panic!("Expected CreateResponse");
    };
    let preactive_uid = created.unique_identifier.clone();

    let name = format!(
        "batch-undo-{}",
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    let Operation::Create(mut named_create) = create_aes() else {
        panic!("Expected Create");
    };
    named_create.attributes.name = Some(vec![Name {
        name_value: name.clone(),
        name_type: NameType::UninterpretedTextString,
    }]);
    let response = send(
        header(3, Some(BatchErrorContinuationOption::Undo)),
        vec![
            item(Operation::Create(named_create)),
            item(Operation::Activate(Activate {
                unique_identifier: preactive_uid.clone(),
            })),
            item(missing_get()),
        ],
    );
    assert_eq!(response.batch_item.len(), 3);
    for index in 0..2 {
        assert_eq!(
            v21(&response, index).result_status,
            ResultStatusEnumeration::OperationUndone
        );
    }
    assert_eq!(
        v21(&response, 2).result_status,
        ResultStatusEnumeration::OperationFailed
    );

    // The created key is gone
    let response = send(
        header(1, None),
        vec![item(Operation::Locate(Box::new(Locate {
            attributes: Attributes {
                name: Some(vec![Name {
                    name_value: name,
                    name_type: NameType::UninterpretedTextString,
                }]),
                ..Default::default()
            },
            ..Default::default()
        })))],
    );
    let Some(Operation::LocateResponse(located)) = &v21(&response, 0).response_payload else {
        panic!("Expected LocateResponse");
    };
    assert!(located.unique_identifier.as_ref().is_none_or(Vec::is_empty));

    // The activated key is Pre-Active again, so it can be activated
    let response = send(
        header(1, None),
        vec![item(Operation::Activate(Activate {
            unique_identifier: preactive_uid,
        }))],
    );
    assert_eq!(
        v21(&response, 0).result_status,
        ResultStatusEnumeration::Success
    );
}

/// An operation the server does not implement fails its own item with Operation Not
/// Supported; with Continue, the next item still runs.
#[test]
fn test_unsupported_operation_fails_per_item_2_1_binary() {
    log_init(option_env!("RUST_LOG"));
    let mut ttlv = to_ttlv(&RequestMessage {
        request_header: header(2, Some(BatchErrorContinuationOption::Continue)),
        batch_item: vec![item(query()), item(query())],
    })
    .expect("Failed to serialize request");
    let TTLValue::Structure(children) = &mut ttlv.value else {
        panic!("Expected RequestMessage structure");
    };
    // Turn the first item into a Poll, which this server does not implement
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
                value: 0x0000_001A,
                name: "Poll".into(),
            });
        }
    }
    let response = send_bytes(&ttlv.to_bytes(KmipFlavor::Kmip2).expect("encode"));
    assert_eq!(response.batch_item.len(), 2);
    assert_eq!(
        v21(&response, 0).operation,
        Some(OperationEnumeration::Poll)
    );
    assert_eq!(
        v21(&response, 0).result_reason,
        Some(ErrorReason::Operation_Not_Supported)
    );
    assert_eq!(
        v21(&response, 1).result_status,
        ResultStatusEnumeration::Success
    );
}

/// Undefined tags and enumeration values get their own result reasons (KMIP 2.1 §11.42),
/// and a message without a protocol version is an Invalid Message.
#[test]
fn test_unknown_tag_enumeration_and_missing_version_2_1_binary() {
    log_init(option_env!("RUST_LOG"));
    let reason = |response: &ResponseMessage| v21(response, 0).result_reason;

    // Operation tag 0x42005C replaced by the undefined tag 0x42FFFE
    let mut bytes = query_message_bytes();
    let operation = find_item(&bytes, [0x42, 0x00, 0x5C], 0x05);
    bytes[operation + 1..operation + 3].copy_from_slice(&[0xFF, 0xFE]);
    assert_eq!(reason(&send_bytes(&bytes)), Some(ErrorReason::Unknown_Tag));

    // Operation value replaced by the undefined value 0xFFFF
    let mut bytes = query_message_bytes();
    let operation = find_item(&bytes, [0x42, 0x00, 0x5C], 0x05);
    bytes[operation + 8..operation + 12].copy_from_slice(&[0, 0, 0xFF, 0xFF]);
    assert_eq!(
        reason(&send_bytes(&bytes)),
        Some(ErrorReason::Unknown_Enumeration)
    );

    // A Request Message whose Request Header carries no Protocol Version
    let response = send_bytes(&[
        0x42, 0x00, 0x78, 0x01, 0, 0, 0, 0x08, 0x42, 0x00, 0x77, 0x01, 0, 0, 0, 0,
    ]);
    assert_eq!(reason(&response), Some(ErrorReason::Invalid_Message));
    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 2,
            protocol_version_minor: 1,
        }
    );
}

/// The server cannot produce the Server Hashed Password a Hashed Password credential requires
/// (KMIP 2.1 Table 398), so such a request is rejected as not supported.
#[test]
fn test_hashed_password_credential_is_rejected_2_1_binary() {
    log_init(option_env!("RUST_LOG"));
    let mut request_header = header(1, None);
    request_header.authentication = Some(Authentication {
        credential: vec![Credential {
            credential_type: CredentialType::HashedPassword,
            credential_value: CredentialValue::HashedPassword {
                username: "user".to_owned(),
                timestamp: time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1000,
                hashing_algorithm: None,
                hashed_password: vec![0; 64],
            },
        }],
    });
    let response = send(request_header, vec![item(query())]);
    assert_eq!(
        v21(&response, 0).result_reason,
        Some(ErrorReason::Feature_Not_Supported)
    );
}
