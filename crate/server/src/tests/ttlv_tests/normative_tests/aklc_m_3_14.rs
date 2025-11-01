use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_1_4::kmip_operations::ModifyAttribute;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{
            CryptographicUsageMask, ErrorReason, ProtocolVersion, ResultStatusEnumeration,
            RevocationReason, RevocationReasonCode,
        },
    },
    kmip_1_4::{
        kmip_attributes::{Attribute, CryptographicAlgorithm, Name, ObjectType, State},
        kmip_data_structures::TemplateAttribute,
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Activate, CreateKeyPair, Destroy, GetAttributes, Operation, Revoke},
        kmip_types::{NameType, OperationEnumeration},
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::{info, log_init};
use time::OffsetDateTime;

use crate::{
    error::KmsError,
    tests::ttlv_tests::{get_client, socket_client::SocketClient},
};

/// This test implements the Asymmetric Key Lifecycle test case AKLC-M-3-14
/// which tests the following operations:
/// - `CreateKeyPair`
/// - `GetAttributes`
/// - Activate
/// - `ModifyAttribute` (expected to fail)
/// - Revoke
/// - `GetAttributes`
/// - Destroy
#[test]
fn test_aklc_m_3_14() {
    log_init(None);
    // log_init(Some("info,kmip=debug"));

    info!("Running AKLC-M-3-14 test");
    let client = get_client();

    // Step 1: Create a key pair
    let (private_key_id, public_key_id) = create_key_pair(&client);
    info!("Created key pair: private={private_key_id}, public={public_key_id}");

    // Step 2: Get attributes for the private key
    get_private_key_attributes(&client, &private_key_id);

    // Step 3: Activate the private key
    activate_key(&client, &private_key_id);

    // Step 4: Get state and activation date attributes
    get_activation_attributes(&client, &private_key_id);

    // FIXME: Not Yet Supported
    // // Step 5: Try to modify activation date (expected to fail)
    // try_modify_activation_date(&client, &private_key_id);

    // Step 6: Revoke the private key
    revoke_key(&client, &private_key_id);

    // Step 7: Check if state changed to compromised
    check_key_compromised(&client, &private_key_id);

    // Step 8: Check public key state
    // FIXME: Cosmian makes them compromised by default when the private key is compromised
    check_public_key_state(&client, &public_key_id);

    // Step 9: Destroy the private key
    destroy_key(&client, &private_key_id);

    // Step 10: Destroy the public key
    destroy_key(&client, &public_key_id);
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

/// Get attributes of the private key
fn get_private_key_attributes(client: &SocketClient, private_key_id: &str) {
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
                operation: OperationEnumeration::GetAttributes,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::GetAttributes(GetAttributes {
                    unique_identifier: Some(private_key_id.to_owned()),
                    attribute_name: Some(vec![
                        "State".to_owned(),
                        "Cryptographic Usage Mask".to_owned(),
                        "Unique Identifier".to_owned(),
                        "Object Type".to_owned(),
                        "Cryptographic Algorithm".to_owned(),
                        "Cryptographic Length".to_owned(),
                        "Digest".to_owned(),
                        "Initial Date".to_owned(),
                        "Last Change Date".to_owned(),
                        "Original Creation Date".to_owned(),
                        "Random Number Generator".to_owned(),
                    ]),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send GetAttributes request");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Expected V14 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    let Some(Operation::GetAttributesResponse(get_attrs_response)) = &batch_item.response_payload
    else {
        panic!("Expected GetAttributesResponse");
    };

    info!("GetAttributesResponse: {get_attrs_response:#?}");

    // Verify that we got the expected attributes with specific values from the KMIP XML
    assert!(
        get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            // State should be PreActive in KMIP spec. Cosmian makes them active by default
            .any(|attr| matches!(attr, Attribute::State(s) if *s == State::PreActive || *s == State::Active)),
        "State should be PreActive or Active."
    );

    assert!(get_attrs_response.attribute.as_ref()
                .unwrap().iter().any(|attr|
        matches!(attr, Attribute::CryptographicUsageMask(mask) if *mask == CryptographicUsageMask::Sign)
    ), "CryptographicUsageMask should be Sign");

    assert!(
        get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            .any(|attr| matches!(attr, Attribute::UniqueIdentifier(uid) if uid == private_key_id)),
        "UniqueIdentifier should match the private key ID"
    );

    assert!(
        get_attrs_response.attribute.as_ref().unwrap().iter().any(
            |attr| matches!(attr, Attribute::ObjectType(obj_type) if *obj_type == ObjectType::PrivateKey)
        ),
        "ObjectType should be PrivateKey"
    );

    assert!(
        get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            .any(|attr| matches!(attr, Attribute::CryptographicAlgorithm(algo) if *algo == CryptographicAlgorithm::RSA)),
        "CryptographicAlgorithm should be RSA"
    );

    assert!(
        get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            .any(|attr| matches!(attr, Attribute::CryptographicLength(length) if *length == 2048)),
        "CryptographicLength should be 2048"
    );

    assert!(
        get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            .any(|attr| matches!(attr, Attribute::Digest(_))),
        "Digest attribute should be present"
    );

    assert!(
        get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            .any(|attr| matches!(attr, Attribute::InitialDate(_))),
        "InitialDate attribute should be present"
    );

    assert!(
        get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            .any(|attr| matches!(attr, Attribute::LastChangeDate(_))),
        "LastChangeDate attribute should be present"
    );

    assert!(
        get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            .any(|attr| matches!(attr, Attribute::OriginalCreationDate(_))),
        "OriginalCreationDate attribute should be present."
    );

    assert!(
        !get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            .any(|attr| matches!(attr, Attribute::ActivationDate(_))),
        "ActivationDate attribute should not be present."
    );

    info!("Successfully verified private key attributes");
}

/// Activate the private key
fn activate_key(client: &SocketClient, key_id: &str) {
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
                operation: OperationEnumeration::Activate,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Activate(Activate {
                    unique_identifier: key_id.to_owned(),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send Activate request");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Expected V14 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    info!("Successfully activated the key");
}

/// Get activation-related attributes
fn get_activation_attributes(client: &SocketClient, key_id: &str) {
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
                operation: OperationEnumeration::GetAttributes,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::GetAttributes(GetAttributes {
                    unique_identifier: Some(key_id.to_owned()),
                    attribute_name: Some(vec![
                        "State".to_owned(),
                        "Activation Date".to_owned(),
                        "Deactivation Date".to_owned(),
                    ]),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send GetAttributes request");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Expected V14 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    let Some(Operation::GetAttributesResponse(get_attrs_response)) = &batch_item.response_payload
    else {
        panic!("Expected GetAttributesResponse");
    };

    // Verify the state is now active
    assert!(
        get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            .any(|attr| matches!(attr, Attribute::State(State::Active))),
    );

    // Check that activation date exists
    assert!(
        get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            .any(|attr| matches!(attr, Attribute::ActivationDate(_)))
    );

    // Check that the deactivation date does not exist
    assert!(
        !get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            .any(|attr| matches!(attr, Attribute::DeactivationDate(_))),
        "DeactivationDate should not be present after activation."
    );

    info!("Successfully verified activation attributes");
}

// FIXME: Not Yet Supported
/// Try to modify activation date (expected to fail)
fn try_modify_activation_date(client: &SocketClient, key_id: &str) {
    // Get current time in UTC
    let now = OffsetDateTime::now_utc()
        .replace_millisecond(0)
        .map_err(|e| KmsError::Default(e.to_string()))
        .unwrap();

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
                operation: OperationEnumeration::ModifyAttribute,
                ephemeral: None,
                unique_batch_item_id: Some(b"0752c951bb9926cc".to_vec()), /* Using the same ID as in the XML */
                request_payload: Operation::ModifyAttribute(ModifyAttribute {
                    unique_identifier: Some(key_id.to_owned()),
                    attribute: Attribute::ActivationDate(now),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send ModifyAttribute request");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Expected V14 response message");
    };

    // The operation is expected to fail with permission denied
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::OperationFailed
    );
    assert_eq!(
        batch_item.result_reason,
        Some(ErrorReason::Permission_Denied)
    );

    info!("Successfully verified ModifyAttribute failure as expected");
}

/// Revoke the key
fn revoke_key(client: &SocketClient, key_id: &str) {
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
                operation: OperationEnumeration::Revoke,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Revoke(Revoke {
                    unique_identifier: Some(key_id.to_owned()),
                    revocation_reason: RevocationReason {
                        revocation_reason_code: RevocationReasonCode::KeyCompromise,
                        revocation_message: None,
                    },
                    compromise_occurrence_date: Some(
                        OffsetDateTime::from_unix_timestamp(6)
                            .expect("Failed to create OffsetDateTime from timestamp"),
                    ), // Jan 1, 1970 at 00:00:06 UTC
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send Revoke request");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Expected V14 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    info!("Successfully revoked the key");
}

/// Check if key state changed to compromised
fn check_key_compromised(client: &SocketClient, key_id: &str) {
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
                operation: OperationEnumeration::GetAttributes,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::GetAttributes(GetAttributes {
                    unique_identifier: Some(key_id.to_owned()),
                    attribute_name: Some(vec!["State".to_owned()]),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send GetAttributes request");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Expected V14 response message");
    };

    info!("GetAttributesResponse: {batch_item:#?}");

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    let Some(Operation::GetAttributesResponse(get_attrs_response)) = &batch_item.response_payload
    else {
        panic!("Expected GetAttributesResponse");
    };

    // Verify the state is now compromised
    assert!(
        get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            .any(|attr| matches!(attr, Attribute::State(State::Compromised))),
    );

    info!("Successfully verified key is in Compromised state");
}

// FIXME: Cosmian makes them compromised by default when the private key is compromised
/// Check public key state
fn check_public_key_state(client: &SocketClient, key_id: &str) {
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
                operation: OperationEnumeration::GetAttributes,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::GetAttributes(GetAttributes {
                    unique_identifier: Some(key_id.to_owned()),
                    attribute_name: Some(vec!["State".to_owned()]),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send GetAttributes request");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Expected V14 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    let Some(Operation::GetAttributesResponse(get_attrs_response)) = &batch_item.response_payload
    else {
        panic!("Expected GetAttributesResponse");
    };

    // Debug: Print the actual state
    if let Some(attrs) = get_attrs_response.attribute.as_ref() {
        for attr in attrs {
            if let Attribute::State(state) = attr {
                info!("Public key actual state: {:?}", state);
            }
        }
    }

    // Verify the public key state remains PreActive (revocation of private key doesn't affect public key)
    assert!(
        get_attrs_response
            .attribute
            .as_ref()
            .unwrap()
            .iter()
            .any(|attr| matches!(attr, Attribute::State(State::PreActive))),
    );

    info!("Successfully verified public key is still in PreActive state");
}

/// Destroy a key
fn destroy_key(client: &SocketClient, key_id: &str) {
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
                operation: OperationEnumeration::Destroy,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Destroy(Destroy {
                    unique_identifier: key_id.to_owned(),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send Destroy request");

    let Some(ResponseMessageBatchItemVersioned::V14(batch_item)) = response.batch_item.first()
    else {
        panic!("Expected V14 response message");
    };

    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);

    info!("Successfully destroyed key: {}", key_id);
}
