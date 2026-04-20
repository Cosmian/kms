//! KMIP 1.0 Register + `GetAttributes` round-trip for `OperationPolicyName`.
//!
//! Synology DSM and other KMIP 1.x clients send `OperationPolicyName` as a
//! template attribute during `Register`.  The attribute was deprecated in
//! KMIP 1.3 and removed in KMIP 2.0+ so the server internally converts it to
//! a `VendorAttribute(KMIP1, __Operation Policy Name__)`.  A subsequent
//! `GetAttributes` request for `"Operation Policy Name"` must return the
//! original value, which requires the reverse mapping back to the KMIP 1.x
//! type.
//!
//! The `warn!` that the server emits during the conversion is intentionally
//! kept in production code — `log_init(None)` is used here so it does not
//! clutter test output.

use cosmian_kms_logger::log_init;
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
        kmip_data_structures::{KeyBlock, KeyValue, TemplateAttribute},
        kmip_messages::RequestMessageBatchItem,
        kmip_objects::{Object, SymmetricKey},
        kmip_operations::{GetAttributes, Operation, Register},
        kmip_types::{CryptographicAlgorithm, KeyFormatType, ObjectType, OperationEnumeration},
    },
    ttlv::KmipFlavor,
};
use zeroize::Zeroizing;

use super::socket_client::SocketClient;
use crate::tests::ttlv_tests::get_client;

/// Register a symmetric key with `OperationPolicyName("default")` using a
/// KMIP 1.0 request, then retrieve the attribute and verify the value
/// survives the KMIP 1.x → 2.1 → 1.x round-trip.
///
/// The server-side `warn!` about the KMIP 1 attribute is **not** printed
/// because `log_init(None)` initialises the logger without any targets.
#[test]
fn test_register_1_0_with_operation_policy_name() {
    // log_init(None) means the `warn!` emitted by the server during the
    // KMIP 1.x → 2.1 attribute conversion is swallowed by the logger and
    // does NOT appear in test output.
    log_init(None);

    let client = get_client();
    let key_id = register_key_with_policy_name(&client, "default");
    check_operation_policy_name(&client, &key_id, "default");
}

/// Send a KMIP 1.0 `Register` containing `OperationPolicyName` and return
/// the assigned `UniqueIdentifier`.
fn register_key_with_policy_name(client: &SocketClient, policy_name: &str) -> String {
    let object = Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            key_format_type: KeyFormatType::Raw,
            key_value: Some(KeyValue::ByteString(Zeroizing::new(vec![1, 2, 3, 4]))),
            key_compression_type: None,
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            key_wrapping_data: None,
        },
    });

    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Register,
                ephemeral: None,
                unique_batch_item_id: Some(b"policy_name_test".to_vec()),
                request_payload: Operation::Register(Register {
                    object,
                    object_type: ObjectType::SymmetricKey,
                    template_attribute: TemplateAttribute {
                        attribute: Some(vec![
                            Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                            Attribute::CryptographicUsageMask(
                                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
                            ),
                            Attribute::CryptographicLength(256),
                            Attribute::OperationPolicyName(policy_name.to_owned()),
                        ]),
                    },
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send Register request");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 0,
        }
    );
    assert_eq!(response.batch_item.len(), 1);

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Expected V14 response batch item");
    };
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "Register failed: {:?}",
        batch_item.result_reason
    );

    let Some(Operation::RegisterResponse(register_response)) = &batch_item.response_payload else {
        panic!("Expected RegisterResponse payload");
    };
    assert!(
        !register_response.unique_identifier.is_empty(),
        "Expected non-empty UniqueIdentifier"
    );
    register_response.unique_identifier.clone()
}

/// Send a KMIP 1.0 `GetAttributes` for `"Operation Policy Name"` and verify
/// the round-tripped value matches the original.
fn check_operation_policy_name(client: &SocketClient, key_id: &str, expected_policy: &str) {
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 0,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::GetAttributes,
                ephemeral: None,
                unique_batch_item_id: Some(b"policy_name_get".to_vec()),
                request_payload: Operation::GetAttributes(GetAttributes {
                    unique_identifier: Some(key_id.to_owned()),
                    attribute_name: Some(vec!["Operation Policy Name".to_owned()]),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send GetAttributes request");

    assert_eq!(response.batch_item.len(), 1);

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Expected V14 response batch item");
    };
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "GetAttributes failed: {:?}",
        batch_item.result_reason
    );

    let Some(Operation::GetAttributesResponse(get_attrs_resp)) = &batch_item.response_payload
    else {
        panic!("Expected GetAttributesResponse payload");
    };
    assert_eq!(get_attrs_resp.unique_identifier, key_id);

    let attributes = get_attrs_resp
        .attribute
        .as_ref()
        .expect("Expected at least one attribute in GetAttributesResponse");
    let policy_attr = attributes
        .iter()
        .find(|a| matches!(a, Attribute::OperationPolicyName(_)));
    let Some(Attribute::OperationPolicyName(actual)) = policy_attr else {
        panic!("Expected OperationPolicyName attribute in response, got: {attributes:?}");
    };
    assert_eq!(
        actual, expected_policy,
        "OperationPolicyName round-trip value mismatch"
    );
}
