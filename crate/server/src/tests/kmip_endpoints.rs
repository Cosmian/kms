#![allow(clippy::unwrap_in_result)]

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::{
        kmip_messages::{RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader},
        kmip_types::ProtocolVersion,
    },
    kmip_2_1::{
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Operation, Query},
        kmip_types::{OperationEnumeration, QueryFunction},
    },
    ttlv::{TTLV, to_ttlv},
};
#[cfg(feature = "non-fips")]
use cosmian_logger::log_init;

#[cfg(feature = "non-fips")]
use crate::{error::KmsError, result::KResult, tests::test_utils};

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_kmip_endpoints() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug,hyper=info,actix_web=info"));
    let request_message = RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(256),
            batch_count: 1,
            ..Default::default()
        },
        batch_item: vec![RequestMessageBatchItemVersioned::V21(
            RequestMessageBatchItem {
                operation: OperationEnumeration::Query,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload: Operation::Query(Query {
                    query_function: Some(vec![
                        QueryFunction::QueryOperations,
                        QueryFunction::QueryObjects,
                    ]),
                }),
                message_extension: None,
            },
        )],
    };

    let fut = async {
        let app = test_utils::test_app(None, None).await;
        let _ttlv: TTLV =
            test_utils::post_json_with_uri(&app, to_ttlv(&request_message)?, "/kmip").await?;
        Ok::<(), KmsError>(())
    };
    // There are many futures called in the test, and they will be stacked
    // leading to a stack overflow. We need to use Box::pin to send them to the heap and avoid this.
    Box::pin(fut).await?;
    Ok(())
}
