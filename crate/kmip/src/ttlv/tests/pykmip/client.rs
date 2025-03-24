use tracing::debug;

use crate::{
    kmip_1_4::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItem, RequestMessageHeader, ResponseMessage,
        },
        kmip_operations::Operation,
        kmip_types::{ProtocolVersion, ResultStatusEnumeration},
    },
    ttlv::{self, from_ttlv, tests::pykmip::socket_client::create_default_client, to_ttlv},
};

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
    let req_ttlv = to_ttlv(&req).unwrap();
    debug!("Request TTLV: {:#?}", req_ttlv);
    let req_bytes = req_ttlv.to_bytes_1_4().unwrap();

    let resp_bytes = create_default_client()
        .unwrap()
        .send_request(&req_bytes)
        .unwrap();

    // Check that we got a response
    assert!(!resp_bytes.is_empty(), "Empty response");

    // parse the response TTLV bytes
    let ttlv = ttlv::TTLV::from_bytes_1_4(&resp_bytes).unwrap();
    debug!("Response TTLV: {:#?}", ttlv);

    // parse the response message
    let response_message = from_ttlv::<ResponseMessage>(ttlv).unwrap();
    debug!("Response Message: {:#?}", response_message);
    response_message
}

#[macro_export]
macro_rules! send_to_pykmip_server {
    ($req:expr, $req_variant:ident, $resp_variant:ident) => {{
        // 1. Create Operation::REQ(REQ)
        let operation = Operation::$req_variant($req);

        // 2. Wrap in RequestMessage
        let request_message =
            $crate::ttlv::tests::pykmip::client::wrap_in_request_message(operation);

        // 3. Send to PyKMIP server
        let response_message =
            $crate::ttlv::tests::pykmip::client::send_to_server(&request_message);

        // 4 & 5. Unwrap response and extract the specific response type
        match $crate::ttlv::tests::pykmip::client::unwrap_from_response_message(&response_message) {
            Operation::$resp_variant(response) => response,
            other => panic!(
                "Expected Operation::{}, got {:?}",
                stringify!($resp_variant),
                other
            ),
        }
    }};
}
