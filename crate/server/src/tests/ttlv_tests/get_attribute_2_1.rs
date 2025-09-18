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
        kmip_objects::ObjectType,
        kmip_operations::{GetAttributes, Operation},
        kmip_types::{
            AttributeReference, CryptographicAlgorithm, OperationEnumeration, Tag,
            UniqueIdentifier, VendorAttributeReference,
        },
    },
    ttlv::KmipFlavor,
};
use cosmian_logger::{info, log_init};

use super::{create_1_4::create_symmetric_key, socket_client::SocketClient};
use crate::tests::ttlv_tests::{add_attribute_1_4::add_attributes, get_client};

#[test]
fn test_get_attribute_1_4() {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));

    let client = get_client();

    // Create a symmetric key
    let key_id = create_symmetric_key(&client, "key_1");
    info!("Key ID: {key_id}");

    add_attributes(&client, &key_id);

    // Add attributes to the key
    get_attributes(&client, &key_id);
}

pub(super) fn get_attributes(client: &SocketClient, key_id: &str) {
    let protocol_major = 2;
    let kmip_flavor = if protocol_major == 2 {
        KmipFlavor::Kmip2
    } else {
        KmipFlavor::Kmip1
    };

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
                operation: OperationEnumeration::GetAttributes,
                ephemeral: None,
                unique_batch_item_id: Some(b"12345".to_vec()),
                request_payload: Operation::GetAttributes(GetAttributes {
                    unique_identifier: Some(UniqueIdentifier::TextString(key_id.to_owned())),
                    attribute_reference: Some(vec![
                        AttributeReference::Vendor(VendorAttributeReference {
                            vendor_identification: "KMIP1".to_owned(),
                            attribute_name: "x-Product_Version".to_owned(),
                        }),
                        AttributeReference::Vendor(VendorAttributeReference {
                            vendor_identification: "KMIP1".to_owned(),
                            attribute_name: "x-Product".to_owned(),
                        }),
                        AttributeReference::Standard(Tag::CryptographicAlgorithm),
                        AttributeReference::Standard(Tag::ObjectType),
                    ]),
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
    let ResponseMessageBatchItemVersioned::V21(batch_item) = response_batch_item else {
        panic!("Expected V21 response message");
    };
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    assert_eq!(batch_item.unique_batch_item_id, Some(b"12345".to_vec()));
    let Some(Operation::GetAttributesResponse(response)) = &batch_item.response_payload else {
        panic!("Expected AddAttributeResponse");
    };
    assert_eq!(
        response.unique_identifier,
        UniqueIdentifier::TextString(key_id.to_owned())
    );
    let vendor_attributes = response
        .attributes
        .vendor_attributes
        .as_ref()
        .expect("Expected Vendor attributes");
    assert_eq!(vendor_attributes.len(), 2);
    assert_eq!(
        response.attributes.cryptographic_algorithm,
        Some(CryptographicAlgorithm::AES)
    );
    assert_eq!(
        response.attributes.object_type,
        Some(ObjectType::SymmetricKey)
    );
}
