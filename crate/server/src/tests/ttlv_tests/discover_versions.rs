use cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned,
        },
        kmip_operations::{DiscoverVersions, DiscoverVersionsResponse},
        kmip_types::ProtocolVersion,
    },
    kmip_1_4, kmip_2_1,
    ttlv::KmipFlavor::Kmip1,
};
use cosmian_logger::log_init;

use crate::tests::ttlv_tests::get_client;

#[test]
fn test_discover_versions_all() {
    log_init(option_env!("RUST_LOG"));

    let dv = DiscoverVersions {
        protocol_version: None,
    };

    // KMIP 1.4
    let resp = test_discover_versions_(1, 2, dv.clone());
    let Some(versions) = resp.protocol_version else {
        panic!("Expected protocol version");
    };
    assert!(versions.contains(&ProtocolVersion {
        protocol_version_major: 2,
        protocol_version_minor: 1,
    }));
    assert!(versions.contains(&ProtocolVersion {
        protocol_version_major: 1,
        protocol_version_minor: 4,
    }));

    // KMIP 2.1
    let resp = test_discover_versions_(2, 1, dv);
    let Some(versions) = resp.protocol_version else {
        panic!("Expected protocol version");
    };
    assert!(versions.contains(&ProtocolVersion {
        protocol_version_major: 2,
        protocol_version_minor: 1,
    }));
    assert!(versions.contains(&ProtocolVersion {
        protocol_version_major: 1,
        protocol_version_minor: 4,
    }));
}

#[test]
fn test_discover_versions_specific() {
    log_init(option_env!("RUST_LOG"));

    let dv = DiscoverVersions {
        protocol_version: Some(vec![ProtocolVersion {
            protocol_version_major: 1,
            protocol_version_minor: 1,
        }]),
    };

    // KMIP 1.4
    let resp = test_discover_versions_(1, 2, dv.clone());
    let Some(versions) = resp.protocol_version else {
        panic!("Expected protocol version");
    };
    assert_eq!(versions.len(), 1);
    assert!(versions.contains(&ProtocolVersion {
        protocol_version_major: 1,
        protocol_version_minor: 1,
    }));

    // KMIP 2.1
    let resp = test_discover_versions_(2, 1, dv);
    let Some(versions) = resp.protocol_version else {
        panic!("Expected protocol version");
    };
    assert_eq!(versions.len(), 1);
    assert!(versions.contains(&ProtocolVersion {
        protocol_version_major: 1,
        protocol_version_minor: 1,
    }));
}

#[test]
fn test_discover_versions_not_found() {
    log_init(option_env!("RUST_LOG"));

    let dv = DiscoverVersions {
        protocol_version: Some(vec![ProtocolVersion {
            protocol_version_major: 42,
            protocol_version_minor: 43,
        }]),
    };

    // KMIP 1.4
    let resp = test_discover_versions_(1, 2, dv.clone());
    assert!(resp.protocol_version.is_none());

    // KMIP 2.1
    let resp = test_discover_versions_(2, 1, dv);
    assert!(resp.protocol_version.is_none());
}

fn test_discover_versions_(
    major: i32,
    minor: i32,
    dv: DiscoverVersions,
) -> DiscoverVersionsResponse {
    let client = get_client();

    let mut request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: major,
                protocol_version_minor: minor,
            },
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![],
    };
    if major == 1 {
        request_message
            .batch_item
            .push(RequestMessageBatchItemVersioned::V14(
                kmip_1_4::kmip_messages::RequestMessageBatchItem {
                    operation: kmip_1_4::kmip_types::OperationEnumeration::DiscoverVersions,
                    ephemeral: None,
                    unique_batch_item_id: None,
                    request_payload: kmip_1_4::kmip_operations::Operation::DiscoverVersions(dv),
                    message_extension: None,
                },
            ));
    } else {
        request_message
            .batch_item
            .push(RequestMessageBatchItemVersioned::V21(
                kmip_2_1::kmip_messages::RequestMessageBatchItem {
                    operation: kmip_2_1::kmip_types::OperationEnumeration::DiscoverVersions,
                    ephemeral: None,
                    unique_batch_item_id: None,
                    request_payload: kmip_2_1::kmip_operations::Operation::DiscoverVersions(dv),
                    message_extension: None,
                },
            ));
    }

    let response = client
        .send_request::<RequestMessage, ResponseMessage>(Kmip1, &request_message)
        .expect("Failed to send request");

    assert_eq!(
        response.response_header.protocol_version,
        ProtocolVersion {
            protocol_version_major: major,
            protocol_version_minor: minor,
        }
    );
    assert_eq!(response.batch_item.len(), 1);
    let Some(response_batch_item) = response.batch_item.first() else {
        panic!("Expected response batch item");
    };
    if major == 1 {
        let ResponseMessageBatchItemVersioned::V14(batch_item) = response_batch_item else {
            panic!("Expected V14 request message");
        };
        let Some(kmip_1_4::kmip_operations::Operation::DiscoverVersionsResponse(resp)) =
            &batch_item.response_payload
        else {
            panic!("Expected QueryResponse");
        };
        resp.to_owned()
    } else {
        let ResponseMessageBatchItemVersioned::V21(batch_item) = response_batch_item else {
            panic!("Expected V14 request message");
        };
        let Some(kmip_2_1::kmip_operations::Operation::DiscoverVersionsResponse(resp)) =
            &batch_item.response_payload
        else {
            panic!("Expected QueryResponse");
        };
        resp.to_owned()
    }
}
