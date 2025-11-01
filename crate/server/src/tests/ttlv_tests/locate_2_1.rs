use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_1_4::{
    kmip_attributes::{Attribute, Name, ObjectType},
    kmip_types::NameType,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    kmip_2_1::{
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Locate, Operation},
        kmip_types::{OperationEnumeration, UniqueIdentifier},
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::{info, log_init};

use super::{create_1_4::create_symmetric_key, socket_client::SocketClient};
use crate::tests::ttlv_tests::get_client;

#[test]
fn test_locate_2_1() {
    // log_init(option_env!("RUST_LOG"));
    log_init(Some("debug"));

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

pub(super) fn locate_symmetric_keys(
    client: &SocketClient,
    name: Option<&str>,
    expected_key_uids: &[&str],
    unexpected_key_uids: &[&str],
) {
    let protocol_major = 2;
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
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Locate,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::Locate(Box::new(Locate {
                    maximum_items: None,
                    offset_items: None,
                    storage_status_mask: None,
                    object_group_member: None,
                    attributes: attributes.into(),
                })),
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
    let ResponseMessageBatchItemVersioned::V21(batch_item) = response_batch_item else {
        panic!("Expected V21 response message");
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
            uids.contains(&UniqueIdentifier::TextString(key.to_owned())),
            "Key ID {key} not found in response"
        );
    }
    for &key in unexpected_key_uids {
        assert!(
            !uids.contains(&UniqueIdentifier::TextString(key.to_owned())),
            "Key ID {key} unexpectedly found in response"
        );
    }
}
