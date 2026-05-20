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

/// Build a minimal KMIP Query request message with the given protocol version.
#[cfg(feature = "non-fips")]
fn build_query_request(major: i32, minor: i32) -> RequestMessage {
    RequestMessage {
        request_header: RequestMessageHeader {
            protocol_version: ProtocolVersion {
                protocol_version_major: major,
                protocol_version_minor: minor,
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
                    query_function: Some(vec![QueryFunction::QueryOperations]),
                }),
                message_extension: None,
            },
        )],
    }
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_kmip_endpoints() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug,hyper=info,actix_web=info"));
    let request_message = build_query_request(2, 1);

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

/// Tests that the JSON `/kmip` endpoint rejects KMIP versions other than 2.1 and 1.4.
/// The binary `/kmip` endpoint accepts all 1.x versions, but the JSON path explicitly
/// only handles 2.1 and 1.4.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_kmip_json_rejects_old_versions() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));

    let fut = async {
        let app = test_utils::test_app(None, None).await;

        // These versions should be rejected by the JSON /kmip endpoint
        let rejected_versions = [(1, 0), (1, 1), (1, 2), (1, 3)];

        for (major, minor) in rejected_versions {
            let request_message = build_query_request(major, minor);
            let response_ttlv: TTLV =
                test_utils::post_json_with_uri(&app, to_ttlv(&request_message)?, "/kmip").await?;

            // The response is always HTTP 200 but contains OperationFailed in the TTLV
            let response_json = serde_json::to_string(&response_ttlv)?;
            assert!(
                response_json.contains("OperationFailed"),
                "KMIP {major}.{minor} should be rejected by /kmip JSON endpoint, got: {response_json}"
            );
            assert!(
                response_json.contains("only accepts KMIP 2.1 or 1.4"),
                "KMIP {major}.{minor} rejection should mention accepted versions, got: {response_json}"
            );
        }

        // These versions should be accepted
        let accepted_versions = [(1, 4), (2, 1)];

        for (major, minor) in accepted_versions {
            let request_message = build_query_request(major, minor);
            let response_ttlv: TTLV =
                test_utils::post_json_with_uri(&app, to_ttlv(&request_message)?, "/kmip").await?;

            let response_json = serde_json::to_string(&response_ttlv)?;
            assert!(
                !response_json.contains("only accepts KMIP 2.1 or 1.4"),
                "KMIP {major}.{minor} should be accepted by /kmip JSON endpoint, got: {response_json}"
            );
        }

        Ok::<(), KmsError>(())
    };

    Box::pin(fut).await?;
    Ok(())
}
