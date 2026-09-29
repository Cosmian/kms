use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_1_4::{
        kmip_attributes::{Attribute, ObjectType},
        kmip_data_structures::TemplateAttribute,
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Locate, Operation},
        kmip_types::{Name, NameType, OperationEnumeration},
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::{info, log_init};

use super::{create_1_4::create_symmetric_key, socket_client::SocketClient};
use crate::tests::ttlv_tests::get_client;

#[test]
fn test_locate_1_4() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));

    let client = get_client();

    // Create two symmetric keys
    let key_id_1 = create_symmetric_key(&client, "key_1");
    info!("Key ID: {key_id_1}");
    let key_id_2 = create_symmetric_key(&client, "key_2");
    info!("Key ID: {key_id_2}");

    // Get the symmetric key
    locate_symmetric_keys(&client, None, &[&key_id_1, &key_id_2], &[]);
    locate_symmetric_keys(&client, Some("key_1"), &[&key_id_1], &[&key_id_2]);
}

/// Regression test for GitHub issue #824 — `FortiGate` 40F sends Locate with Name filter
/// wrapped inside `TemplateAttribute` (KMIP 1.0/1.1 style).
///
/// Without the fix, every Locate returned the same first key in the database regardless
/// of the requested name.  This test creates four symmetric keys and verifies that
/// filtering by name via `TemplateAttribute` correctly returns only the matching key.
#[test]
fn test_locate_1_4_fortigate_template_attribute() {
    log_init(option_env!("RUST_LOG"));

    let client = get_client();

    // Create four symmetric keys matching FortiGate naming conventions.
    let key_names = [
        "fg2-local-id-enc-aes-16",
        "fg2-local-id-enc-aes-32",
        "fg2-local-id-auth-sha1-20",
        "fg2-local-id-auth-sha256-32",
    ];
    let mut key_ids = Vec::with_capacity(key_names.len());
    for name in &key_names {
        let id = create_symmetric_key(&client, name);
        info!("Created key '{name}' → {id}");
        key_ids.push(id);
    }

    // For each key, locate by name using TemplateAttribute (KMIP 1.0/1.1 style).
    for (i, name) in key_names.iter().enumerate() {
        let expected_id = &key_ids[i];
        let unexpected_ids: Vec<&str> = key_ids
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, id)| id.as_str())
            .collect();

        locate_with_template_attribute(&client, name, &[expected_id.as_str()], &unexpected_ids);
    }
}

/// Sends a KMIP 1.0/1.1-style Locate request where the Name filter is wrapped in a
/// `TemplateAttribute` structure (as `FortiGate` 40F does) and asserts that the
/// expected keys are present/absent in the response.
pub(super) fn locate_with_template_attribute(
    client: &SocketClient,
    name: &str,
    expected_key_uids: &[&str],
    unexpected_key_uids: &[&str],
) {
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
                operation: OperationEnumeration::Locate,
                ephemeral: None,
                unique_batch_item_id: Some(b"locate-fg".to_vec()),
                request_payload: Operation::Locate(Locate {
                    maximum_items: Some(1),
                    storage_status_mask: None,
                    object_group_member: None,
                    attribute: None,
                    // FortiGate wraps its filter attributes in TemplateAttribute.
                    template_attribute: Some(TemplateAttribute {
                        attribute: Some(vec![
                            Attribute::ObjectType(ObjectType::SymmetricKey),
                            Attribute::Name(Name {
                                name_value: name.to_owned(),
                                name_type: NameType::UninterpretedTextString,
                            }),
                        ]),
                    }),
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, &request_message)
        .expect("Failed to send Locate request");

    assert_eq!(response.batch_item.len(), 1);
    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };
    let ResponseMessageBatchItemVersioned::V14(batch_item) = response_batch_item else {
        panic!("Expected V14 response");
    };
    assert_eq!(
        batch_item.result_status,
        ResultStatusEnumeration::Success,
        "Locate for name='{name}' failed: {:?}",
        batch_item.result_reason
    );
    let Some(Operation::LocateResponse(response)) = &batch_item.response_payload else {
        panic!("Expected LocateResponse payload");
    };
    let Some(uids) = &response.unique_identifier else {
        panic!(
            "Locate for name='{name}' returned no unique identifiers (expected {expected_key_uids:?})"
        );
    };
    for &key in expected_key_uids {
        assert!(
            uids.contains(&key.to_owned()),
            "Locate for name='{name}': expected key '{key}' in response but got {uids:?}"
        );
    }
    for &key in unexpected_key_uids {
        assert!(
            !uids.contains(&key.to_owned()),
            "Locate for name='{name}': unexpected key '{key}' found in response {uids:?}"
        );
    }
}

pub(super) fn locate_symmetric_keys(
    client: &SocketClient,
    name: Option<&str>,
    expected_key_uids: &[&str],
    unexpected_key_uids: &[&str],
) {
    let protocol_major = 1;
    let kmip_flavor = if protocol_major == 2 {
        KmipFlavor::Kmip2
    } else {
        KmipFlavor::Kmip1
    };

    let mut attributes = vec![Attribute::ObjectType(ObjectType::SymmetricKey)];
    if let Some(name) = name {
        attributes.push(Attribute::Name(Name {
            name_value: name.to_owned(),
            name_type: NameType::UninterpretedTextString,
        }));
    }

    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: protocol_major,
                protocol_version_minor: 1,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V14(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Locate,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::Locate(Locate {
                    maximum_items: None,
                    storage_status_mask: None,
                    object_group_member: None,
                    attribute: Some(attributes),
                    template_attribute: None,
                }),
                message_extension: None,
            },
        )],
    };

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(kmip_flavor, &request_message)
        .expect("Failed to send request");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: protocol_major,
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
    let Some(Operation::LocateResponse(response)) = &batch_item.response_payload else {
        panic!("Expected AddAttributeResponse");
    };
    let Some(uids) = &response.unique_identifier else {
        panic!("Expected unique identifier in LocateResponse");
    };
    for &key in expected_key_uids {
        assert!(
            uids.contains(&key.to_owned()),
            "Key ID {key} not found in response"
        );
    }
    for &key in unexpected_key_uids {
        assert!(
            !uids.contains(&key.to_owned()),
            "Key ID {key} unexpectedly found in response"
        );
    }
}
