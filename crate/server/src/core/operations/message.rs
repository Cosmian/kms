use std::sync::Arc;

use cosmian_kmip::{
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, ResponseMessage,
            ResponseMessageBatchItemVersioned, ResponseMessageHeader,
        },
        kmip_types::{ErrorReason, ResultStatusEnumeration},
    },
    kmip_2_1,
    kmip_2_1::{kmip_messages::ResponseMessageBatchItem, kmip_operations::Operation},
    ttlv::KmipFlavor,
};
use cosmian_kms_interfaces::SessionParams;
use time::OffsetDateTime;
use tracing::trace;

use crate::{core::KMS, error::KmsError, result::KResult};

/// Processing of an input KMIP Message
///
/// Process every item from the message request.
/// Each batch item contains an operation to process.
///
/// The items are processed sequentially.
/// Each item may fail, but a response is still sent back.
pub(crate) async fn message(
    kms: &KMS,
    request: RequestMessage,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<ResponseMessage> {
    trace!("Entering message KMIP operation: {request:?}");

    let mut response_items = Vec::new();
    for versioned_batch_item in request.batch_item {
        let (batch_item, kmip_version) = match versioned_batch_item {
            RequestMessageBatchItemVersioned::V14(item_request) => (
                kmip_2_1::kmip_messages::RequestMessageBatchItem::from(item_request.into()),
                KmipFlavor::Kmip1,
            ),
            RequestMessageBatchItemVersioned::V21(item_request) => {
                (item_request, KmipFlavor::Kmip2)
            }
        };

        let request_operation = batch_item.request_payload;

        // conversion for `dispatch` call convenience

        let (result_status, result_reason, result_message, response_payload) =
            match process_operation(kms, user, params.clone(), request_operation).await {
                Ok(operation) => (
                    ResultStatusEnumeration::Success,
                    None,
                    None,
                    Some(operation),
                ),
                Err(KmsError::Kmip21Error(reason, error_message)) => (
                    ResultStatusEnumeration::OperationFailed,
                    Some(reason),
                    Some(error_message),
                    None,
                ),
                Err(err) => (
                    ResultStatusEnumeration::OperationFailed,
                    Some(ErrorReason::Operation_Not_Supported),
                    Some(err.to_string()),
                    None,
                ),
            };

        let response_message_batch_item = ResponseMessageBatchItem {
            operation: Some(batch_item.operation),
            unique_batch_item_id: batch_item.unique_batch_item_id,
            result_status,
            result_reason,
            result_message,
            asynchronous_correlation_value: None,
            response_payload,
            message_extension: None,
        };

        let response_message_batch_item = match kmip_version {
            KmipFlavor::Kmip1 => {
                ResponseMessageBatchItemVersioned::V14(response_message_batch_item.into())
            }
            KmipFlavor::Kmip2 => {
                ResponseMessageBatchItemVersioned::V21(response_message_batch_item)
            }
        };

        response_items.push(response_message_batch_item);
    }

    let response_message = ResponseMessage {
        response_header: ResponseMessageHeader {
            protocol_version: request.request_header.protocol_version,
            batch_count: i32::try_from(response_items.len())?,
            client_correlation_value: None,
            server_correlation_value: None,
            attestation_type: None,
            time_stamp: OffsetDateTime::now_utc().unix_timestamp(),
            nonce: None,
            server_hashed_password: None,
        },
        batch_item: response_items,
    };

    Ok(response_message)
}

async fn process_operation(
    kms: &KMS,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
    request_operation: Operation,
) -> Result<Operation, KmsError> {
    Ok(match request_operation {
        Operation::Import(kmip_request) => {
            Operation::ImportResponse(kms.import(kmip_request, user, params).await?)
        }
        Operation::Locate(kmip_request) => {
            Operation::LocateResponse(kms.locate(kmip_request, user, params).await?)
        }
        Operation::Get(kmip_request) => {
            Operation::GetResponse(kms.get(kmip_request, user, params).await?)
        }
        Operation::GetAttributes(kmip_request) => {
            Operation::GetAttributesResponse(kms.get_attributes(kmip_request, user, params).await?)
        }
        Operation::SetAttribute(kmip_request) => {
            Operation::SetAttributeResponse(kms.set_attribute(kmip_request, user, params).await?)
        }
        Operation::DeleteAttribute(kmip_request) => Operation::DeleteAttributeResponse(
            kms.delete_attribute(kmip_request, user, params).await?,
        ),

        Operation::ReKey(kmip_request) => {
            Operation::ReKeyResponse(kms.rekey(kmip_request, user, params).await?)
        }
        Operation::ReKeyKeyPair(kmip_request) => {
            Operation::ReKeyKeyPairResponse(kms.rekey_keypair(kmip_request, user, params).await?)
        }
        Operation::Create(kmip_request) => {
            Operation::CreateResponse(kms.create(kmip_request, user, params).await?)
        }
        Operation::CreateKeyPair(kmip_request) => {
            Operation::CreateKeyPairResponse(kms.create_key_pair(kmip_request, user, params).await?)
        }
        Operation::Certify(kmip_request) => {
            Operation::CertifyResponse(kms.certify(kmip_request, user, params).await?)
        }
        Operation::Destroy(kmip_request) => {
            Operation::DestroyResponse(kms.destroy(kmip_request, user, params).await?)
        }
        Operation::Encrypt(kmip_request) => {
            Operation::EncryptResponse(kms.encrypt(kmip_request, user, params).await?)
        }
        Operation::Decrypt(kmip_request) => {
            Operation::DecryptResponse(kms.decrypt(kmip_request, user, params).await?)
        }
        Operation::Export(kmip_request) => {
            Operation::ExportResponse(kms.export(kmip_request, user, params).await?)
        }
        Operation::DiscoverVersions(kmip_request) => Operation::DiscoverVersionsResponse(
            kms.discover_versions(kmip_request, user, params).await,
        ),
        Operation::Validate(kmip_request) => {
            Operation::ValidateResponse(kms.validate(kmip_request, user, params).await?)
        }
        Operation::ImportResponse(_)
        | Operation::CertifyResponse(_)
        | Operation::CreateResponse(_)
        | Operation::CreateKeyPairResponse(_)
        | Operation::DiscoverVersionsResponse(_)
        | Operation::ExportResponse(_)
        | Operation::GetResponse(_)
        | Operation::GetAttributesResponse(_)
        | Operation::SetAttributeResponse(_)
        | Operation::DeleteAttributeResponse(_)
        | Operation::EncryptResponse(_)
        | Operation::DecryptResponse(_)
        | Operation::LocateResponse(_)
        | Operation::Query(_)
        | Operation::QueryResponse(_)
        | Operation::Revoke(_)
        | Operation::RevokeResponse(_)
        | Operation::ReKeyResponse(_)
        | Operation::ReKeyKeyPairResponse(_)
        | Operation::DestroyResponse(_)
        | Operation::ValidateResponse(_) => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Operation_Not_Supported,
                format!("Operation: {request_operation} not supported"),
            ));
        }
    })
}
