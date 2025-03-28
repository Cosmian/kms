use std::sync::OnceLock;

use cosmian_kmip::ttlv::KmipFlavor;
use tracing::debug;

use crate::{
    kmip_1_4::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItem, RequestMessageHeader, ResponseMessage,
        },
        kmip_operations::Operation,
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    SocketClient, SocketClientConfig,
};

// load the string content at compile time - same as http_client.rs
const SERVER_CA_CERTIFICATE: &str =
    include_str!("../../../../../test_data/client_server/ca/ca.crt");

pub(crate) fn wrap_in_request_message(op: Operation) -> RequestMessage {
    RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 1,
                protocol_version_minor: 4,
            },
            maximum_response_size: Some(1_048_576),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItem {
            operation: op.operation_enum(),
            ephemeral: None,
            unique_batch_item_id: None,
            request_payload: op,
            message_extension: None,
        }],
    }
}

#[allow(clippy::expect_used)]
pub(crate) fn unwrap_from_response_message(response: &ResponseMessage) -> Operation {
    let batch_item = response.batch_item.first().expect("No batch item");
    assert_eq!(batch_item.result_status, ResultStatusEnumeration::Success);
    batch_item
        .response_payload
        .as_ref()
        .expect("No response payload")
        .clone()
}

pub(crate) fn send_to_server(req: &RequestMessage) -> ResponseMessage {
    // Initialize the client once
    static CLIENT: OnceLock<SocketClient> = OnceLock::new();

    // Get or initialize the client
    let client = CLIENT.get_or_init(|| {
        let client_p12: Vec<u8> =
            include_bytes!("../../../../../test_data/client_server/user/user.client.acme.com.p12")
                .to_vec();
        let config = SocketClientConfig {
            host: "localhost".to_owned(),
            port: 5696,
            client_p12,
            client_p12_secret: "secret".to_owned(),
            server_ca_cert_pem: SERVER_CA_CERTIFICATE.to_owned(),
        };

        SocketClient::new(config).unwrap()
    });

    let response_message = client
        .send_request::<RequestMessage, ResponseMessage>(KmipFlavor::Kmip1, req)
        .unwrap();

    debug!("Response Message: {:#?}", response_message);
    response_message
}

#[macro_export]
macro_rules! send_to_pykmip_server {
    ($req:expr, $req_variant:ident, $resp_variant:ident) => {{
        // 1. Create Operation::REQ(REQ)
        let operation = Operation::$req_variant($req);

        // 2. Wrap in RequestMessage
        let request_message = $crate::tests::pykmip::client::wrap_in_request_message(operation);

        // 3. Send to PyKMIP server
        let response_message = $crate::tests::pykmip::client::send_to_server(&request_message);

        // 4 & 5. Unwrap response and extract the specific response type
        match $crate::tests::pykmip::client::unwrap_from_response_message(&response_message) {
            Operation::$resp_variant(response) => response,
            other => panic!(
                "Expected Operation::{}, got {:?}",
                stringify!($resp_variant),
                other
            ),
        }
    }};
}
