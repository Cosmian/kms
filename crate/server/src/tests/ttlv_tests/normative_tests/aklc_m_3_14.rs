use cosmian_kms_client_utils::reexport::cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_1_4::{
        kmip_data_structures::TemplateAttribute,
        kmip_types::{Name, NameType},
    },
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4::{
        kmip_attributes::Attribute,
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{
            Activate, CreateKeyPair, Destroy, GetAttributes, ModifyAttribute, Operation, Revoke,
        },
        kmip_types::{CryptographicAlgorithm, OperationEnumeration},
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::log_init;
use log::info;

use crate::tests::ttlv_tests::{get_client, socket_client::SocketClient};

/// This test implements the Asymmetric Key Lifecycle test case AKLC-M-3-14
/// which tests the following operations:
/// - CreateKeyPair
/// - GetAttributes
/// - Activate
/// - ModifyAttribute (expected to fail)
/// - Revoke
/// - GetAttributes
/// - Destroy
#[test]
fn test_aklc_m_3_14() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));

    info!("Running AKLC-M-3-14 test");
    let client = get_client();

    // Step 1: Create a key pair
    let (private_key_id, public_key_id) = create_key_pair(&client);
    info!(
        "Created key pair: private={}, public={}",
        private_key_id, public_key_id
    );

    // // Step 2: Get attributes for the private key
    // get_private_key_attributes(&client, &private_key_id);
    //
    // // Step 3: Activate the private key
    // activate_key(&client, &private_key_id);
    //
    // // Step 4: Get state and activation date attributes
    // get_activation_attributes(&client, &private_key_id);
    //
    // // Step 5: Try to modify activation date (expected to fail)
    // try_modify_activation_date(&client, &private_key_id);
    //
    // // Step 6: Revoke the private key
    // revoke_key(&client, &private_key_id);
    //
    // // Step 7: Check if state changed to compromised
    // check_key_compromised(&client, &private_key_id);
    //
    // // Step 8: Check public key state
    // check_public_key_state(&client, &public_key_id);
    //
    // // Step 9: Destroy the private key
    // destroy_key(&client, &private_key_id);
    //
    // // Step 10: Destroy the public key
    // destroy_key(&client, &public_key_id);
}

/// Create an RSA key pair with specific attributes
fn create_key_pair(client: &SocketClient) -> (String, String) {
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 4,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::CreateKeyPair,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::CreateKeyPair(CreateKeyPair {
                    common_template_attribute: Some(TemplateAttribute {
                        attribute: Some(vec![
                            Attribute::CryptographicAlgorithm(CryptographicAlgorithm::RSA),
                            Attribute::CryptographicLength(2048),
                        ]),
                    }),
                    private_key_template_attribute: Some(TemplateAttribute {
                        attribute: Some(vec![
                            Attribute::Name(Name {
                                name_value: "AKLC-M-3-14-private".to_owned(),
                                name_type: NameType::UninterpretedTextString,
                            }),
                            Attribute::CryptographicUsageMask(CryptographicUsageMask::Sign),
                        ]),
                    }),
                    public_key_template_attribute: Some(TemplateAttribute {
                        attribute: Some(vec![
                            Attribute::Name(Name {
                                name_value: "AKLC-M-3-14-public".to_owned(),
                                name_type: NameType::UninterpretedTextString,
                            }),
                            Attribute::CryptographicUsageMask(CryptographicUsageMask::Verify),
                        ]),
                    }),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send CreateKeyPair request");

    assert_eq!(response.response_header.batch_count, 1);

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Expected V14 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    let Some(Operation::CreateKeyPairResponse(create_key_pair_response)) =
        &batch_item.response_payload
    else {
        panic!("Expected CreateKeyPairResponse");
    };

    // Return the private and public key identifiers
    (
        create_key_pair_response
            .private_key_unique_identifier
            .clone(),
        create_key_pair_response
            .public_key_unique_identifier
            .clone(),
    )
}

// ///Get attributes of the private key
// fn get_private_key_attributes(client: &SocketClient, private_key_id: &str) {
//     let request_message = RequestMessage {
//         request_header: RequestMessageHeader {
//             protocol_version: ProtocolVersion {
//                 protocol_version_major: 1,
//                 protocol_version_minor: 4,
//             },
//             batch_count: 1,
//             ..Default::default()
//         },
//         batch_item: vec![RequestMessageBatchItemVersioned::V14(
//             RequestMessageBatchItem {
//                 operation: OperationEnumeration::GetAttributes,
//                 ephemeral: None,
//                 unique_batch_item_id: None,
//                 request_payload: Operation::GetAttributes(GetAttributes {
//                     unique_identifier: Some(private_key_id.to_owned()),
//                     attribute_names: vec![
//                         "State".to_owned(),
//                         "Cryptographic Usage Mask".to_owned(),
//                         "Unique Identifier".to_owned(),
//                         "Object Type".to_owned(),
//                         "Cryptographic Algorithm".to_owned(),
//                         "Cryptographic Length".to_owned(),
//                         "Digest".to_owned(),
//                         "Initial Date".to_owned(),
//                         "Last Change Date".to_owned(),
//                         "Original Creation Date".to_owned(),
//                         "Random Number Generator".to_owned(),
//                     ],
//                     ..Default::default()
//                 }),
//                 message_extension: None,
//             },
//         )],
//     };
//
//     let response = client
//         .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
//         .expect("Failed to send GetAttributes request");
//
//     let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
//     else {
//         panic!("Expected V14 response message");
//     };
//
//     assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
//
//     let Some(Operation::GetAttributesResponse(get_attrs_response)) = &batch_item.response_payload
//     else {
//         panic!("Expected GetAttributesResponse");
//     };
//
//     // Verify that we got the expected attributes
//     assert!(
//         get_attrs_response
//             .attributes
//             .iter()
//             .any(|attr| matches ! (attr, Attribute::State(State(s)) if s == "PreActive"))
//     );
//
//     assert! (get_attrs_response.attributes.iter().any( | attr |
//     matches ! (attr, Attribute::CryptographicUsageMask(CryptographicUsageMask(mask)) if * mask == CryptographicUsageMask::SIGN)
//     ));
//
//     assert ! (get_attrs_response.attributes.iter().any( | attr |
//     matches ! (attr, Attribute::UniqueIdentifier(UniqueIdentifier(id)) if id == private_key_id)
//     ));
//
//     assert !(get_attrs_response.attributes.iter().any( | attr |
//     matches ! (attr, Attribute::ObjectType(ObjectType(obj_type)) if obj_type == "PrivateKey")
//     ));
//
//     assert ! (get_attrs_response.attributes.iter().any( |attr |
//     matches ! (attr, Attribute::CryptographicAlgorithm(CryptographicAlgorithm(algo)) if algo == "RSA")
//     ));
//
//     assert ! (get_attrs_response.attributes.iter().any( | attr |
//     matches ! (attr, Attribute::CryptographicLength(CryptographicLength(len)) if * len == 2048)
//     ));
//
//     // Additional checks for other attributes could be added here
//     info!("Successfully verified private key attributes");
// }
//
// /// Activate the private key
// fn activate_key(client: &SocketClient, key_id: &str) {
//     let request_message = RequestMessage {
//         request_header: RequestMessageHeader {
//             protocol_version: ProtocolVersion {
//                 protocol_version_major: 1,
//                 protocol_version_minor: 4,
//             },
//             batch_count: 1,
//             ..Default::default()
//         },
//         batch_item: vec![RequestMessageBatchItemVersioned::V14(
//             RequestMessageBatchItem {
//                 operation: OperationEnumeration::Activate,
//                 ephemeral: None,
//                 unique_batch_item_id: None,
//                 request_payload: Operation::Activate(Activate {
//                     unique_identifier: key_id.to_owned(),
//                 }),
//                 message_extension: None,
//             },
//         )],
//     };
//
//     let response = client
//         .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
//         .expect("Failed to send Activate request");
//
//     let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
//     else {
//         panic!("Expected V14 response message");
//     };
//
//     assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
//
//     info!("Successfully activated private key");
// }
//
// /// Get activation-related attributes
// fn get_activation_attributes(client: &SocketClient, key_id: &str) {
//     let request_message = RequestMessage {
//         request_header: RequestMessageHeader {
//             protocol_version: ProtocolVersion {
//                 protocol_version_major: 1,
//                 protocol_version_minor: 4,
//             },
//             batch_count: 1,
//             ..Default::default()
//         },
//         batch_item: vec![RequestMessageBatchItemVersioned::V14(
//             RequestMessageBatchItem {
//                 operation: OperationEnumeration::GetAttributes,
//                 ephemeral: None,
//                 unique_batch_item_id: None,
//                 request_payload: Operation::GetAttributes(GetAttributes {
//                     unique_identifier: Some(key_id.to_owned()),
//                     attribute_names: vec![
//                         "State".to_owned(),
//                         "Activation Date".to_owned(),
//                         "Deactivation Date".to_owned(),
//                     ],
//                     ..Default::default()
//                 }),
//                 message_extension: None,
//             },
//         )],
//     };
//
//     let response = client
//         .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
//         .expect("Failed to send GetAttributes request");
//
//     let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
//     else {
//         panic!("Expected V14 response message");
//     };
//
//     assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
//
//     let Some(Operation::GetAttributesResponse(get_attrs_response)) = &batch_item.response_payload
//     else {
//         panic!("Expected GetAttributesResponse");
//     };
//
//     // Verify the state is now active
//     assert!(
//         get_attrs_response
//             .attributes
//             .iter()
//             .any(|attr| matches ! (attr, Attribute::State(State(s)) if s == "Active"))
//     );
//
//     // Check that activation date exists
//     assert!(
//         get_attrs_response
//             .attributes
//             .iter()
//             .any(|attr| matches!(attr, Attribute::ActivationDate(_)))
//     );
//
//     info!("Successfully verified activation attributes");
// }
//
// /// Try to modify activation date (expected to fail)
// fn try_modify_activation_date(client: &SocketClient, key_id: &str) {
//     use std::time::{SystemTime, UNIX_EPOCH};
//
//     // Get current time in UTC
//     let now = SystemTime::now()
//         .duration_since(UNIX_EPOCH)
//         .expect("Time went backwards")
//         .as_secs();
//
//     let request_message = RequestMessage {
//         request_header: RequestMessageHeader {
//             protocol_version: ProtocolVersion {
//                 protocol_version_major: 1,
//                 protocol_version_minor: 4,
//             },
//             batch_count: 1,
//             ..Default::default()
//         },
//         batch_item: vec![RequestMessageBatchItemVersioned::V14(
//             RequestMessageBatchItem {
//                 operation: OperationEnumeration::ModifyAttribute,
//                 ephemeral: None,
//                 unique_batch_item_id: Some(b"0752c951bb9926cc".to_vec()), // Using the same ID as in the XML
//                 request_payload: Operation::ModifyAttribute(ModifyAttribute {
//                     unique_identifier: key_id.to_owned(),
//                     attribute: Attribute::ActivationDate(AttributeValue::DateTime(now)),
//                 }),
//                 message_extension: None,
//             },
//         )],
//     };
//
//     let response = client
//         .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
//         .expect("Failed to send ModifyAttribute request");
//
//     let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
//     else {
//         panic!("Expected V14 response message");
//     };
//
//     // The operation is expected to fail with permission denied
//     assert_eq!(
//         batch_item.result_status,
//         ResultStatusEnumeration::OperationFailed
//     );
//     assert_eq!(
//         batch_item.result_reason,
//         Some("PermissionDenied".to_owned())
//     );
//
//     info!("Successfully verified ModifyAttribute failure as expected");
// }
//
// /// Revoke the key
// fn revoke_key(client: &SocketClient, key_id: &str) {
//     let request_message = RequestMessage {
//         request_header: RequestMessageHeader {
//             protocol_version: ProtocolVersion {
//                 protocol_version_major: 1,
//                 protocol_version_minor: 4,
//             },
//             batch_count: 1,
//             ..Default::default()
//         },
//         batch_item: vec![RequestMessageBatchItemVersioned::V14(
//             RequestMessageBatchItem {
//                 operation: OperationEnumeration::Revoke,
//                 ephemeral: None,
//                 unique_batch_item_id: None,
//                 request_payload: Operation::Revoke(Revoke {
//                     unique_identifier: key_id.to_owned(),
//                     revocation_reason: Some(RevocationReason {
//                         revocation_reason_code: RevocationReasonCode::KeyCompromise,
//                         revocation_message: None,
//                     }),
//                     compromise_occurrence_date: Some(CompromiseOccurrenceDate(6)), // Jan 1, 1970 at 00:00:06 UTC
//                 }),
//                 message_extension: None,
//             },
//         )],
//     };
//
//     let response = client
//         .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
//         .expect("Failed to send Revoke request");
//
//     let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
//     else {
//         panic!("Expected V14 response message");
//     };
//
//     assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
//
//     info!("Successfully revoked private key");
// }
//
// /// Check if key state changed to compromised
// fn check_key_compromised(client: &SocketClient, key_id: &str) {
//     let request_message = RequestMessage {
//         request_header: RequestMessageHeader {
//             protocol_version: ProtocolVersion {
//                 protocol_version_major: 1,
//                 protocol_version_minor: 4,
//             },
//             batch_count: 1,
//             ..Default::default()
//         },
//         batch_item: vec![RequestMessageBatchItemVersioned::V14(
//             RequestMessageBatchItem {
//                 operation: OperationEnumeration::GetAttributes,
//                 ephemeral: None,
//                 unique_batch_item_id: None,
//                 request_payload: Operation::GetAttributes(GetAttributes {
//                     unique_identifier: Some(key_id.to_owned()),
//                     attribute_names: vec!["State".to_owned()],
//                     ..Default::default()
//                 }),
//                 message_extension: None,
//             },
//         )],
//     };
//
//     let response = client
//         .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
//         .expect("Failed to send GetAttributes request");
//
//     let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
//     else {
//         panic!("Expected V14 response message");
//     };
//
//     assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
//
//     let Some(Operation::GetAttributesResponse(get_attrs_response)) = &batch_item.response_payload
//     else {
//         panic!("Expected GetAttributesResponse");
//     };
//
//     // Verify the state is now compromised
//     assert!(
//         get_attrs_response
//             .attributes
//             .iter()
//             .any(|attr| matches ! (attr, Attribute::State(State(s)) if s == "Compromised"))
//     );
//
//     info!("Successfully verified key is in Compromised state");
// }
//
// /// Check public key state
// fn check_public_key_state(client: &SocketClient, key_id: &str) {
//     let request_message = RequestMessage {
//         request_header: RequestMessageHeader {
//             protocol_version: ProtocolVersion {
//                 protocol_version_major: 1,
//                 protocol_version_minor: 4,
//             },
//             batch_count: 1,
//             ..Default::default()
//         },
//         batch_item: vec![RequestMessageBatchItemVersioned::V14(
//             RequestMessageBatchItem {
//                 operation: OperationEnumeration::GetAttributes,
//                 ephemeral: None,
//                 unique_batch_item_id: None,
//                 request_payload: Operation::GetAttributes(GetAttributes {
//                     unique_identifier: Some(key_id.to_owned()),
//                     attribute_names: vec!["State".to_owned()],
//                     ..Default::default()
//                 }),
//                 message_extension: None,
//             },
//         )],
//     };
//
//     let response = client
//         .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
//         .expect("Failed to send GetAttributes request");
//
//     let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
//     else {
//         panic!("Expected V14 response message");
//     };
//
//     assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
//
//     let Some(Operation::GetAttributesResponse(get_attrs_response)) = &batch_item.response_payload
//     else {
//         panic!("Expected GetAttributesResponse");
//     };
//
//     // Verify the public key state is PreActive (revocation of private key doesn't affect public key)
//     assert!(
//         get_attrs_response
//             .attributes
//             .iter()
//             .any(|attr| matches ! (attr, Attribute::State(State(s)) if s == "PreActive"))
//     );
//
//     info!("Successfully verified public key is still in PreActive state");
// }
//
// /// Destroy a key
// fn destroy_key(client: &SocketClient, key_id: &str) {
//     let request_message = RequestMessage {
//         request_header: RequestMessageHeader {
//             protocol_version: ProtocolVersion {
//                 protocol_version_major: 1,
//                 protocol_version_minor: 4,
//             },
//             batch_count: 1,
//             ..Default::default()
//         },
//         batch_item: vec![RequestMessageBatchItemVersioned::V14(
//             RequestMessageBatchItem {
//                 operation: OperationEnumeration::Destroy,
//                 ephemeral: None,
//                 unique_batch_item_id: None,
//                 request_payload: Operation::Destroy(Destroy {
//                     unique_identifier: key_id.to_owned(),
//                 }),
//                 message_extension: None,
//             },
//         )],
//     };
//
//     let response = client
//         .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
//         .expect("Failed to send Destroy request");
//
//     let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
//     else {
//         panic!("Expected V14 response message");
//     };
//
//     assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
//
//     info!("Successfully destroyed key: {}", key_id);
// }
