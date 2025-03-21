use cosmian_kmip::{
    kmip_2_1::{
        kmip_messages::{RequestMessageBatchItem, RequestMessageHeader},
        kmip_operations::{Operation, Query},
        kmip_types::{OperationEnumeration, ProtocolVersion, QueryFunction},
        RequestMessage,
    },
    ttlv::{to_ttlv, TTLV},
};
use cosmian_logger::log_init;

use crate::{error::KmsError, result::KResult, tests::test_utils};

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
        batch_item: vec![RequestMessageBatchItem {
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
        }],
    };

    let fut = async {
        let app = test_utils::test_app(None).await;
        let _ttlv: TTLV =
            test_utils::post_json_with_uri(&app, to_ttlv(&request_message)?, "/kmip").await?;
        // let _request_response: ResponseMessage =
        //     test_utils::post_2_1(&app, request_message).await?;
        Ok::<(), KmsError>(())
    };
    // There are many futures called in the test, and they will be stacked
    // leading o a stack overflow. We need to use Box::pin to send them to the heap and avoid this.
    Box::pin(fut).await?;
    Ok(())
}
