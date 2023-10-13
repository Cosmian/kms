/// The messages in the protocol consist of a message header,
/// one or more batch items (which contain OPTIONAL message payloads),
/// and OPTIONAL message extensions. The message headers contain fields whose
/// presence is determined by the protocol features used (e.g., asynchronous responses).
/// The field contents are also determined by whether the message is a request or a response.
/// The message payload is determined by the specific operation being
/// requested or to which is being replied.
///
/// The message headers are structures that contain some of the following objects.
///
/// Messages contain the following objects and fields.
/// All fields SHALL appear in the order specified.
///
/// If the client is capable of accepting asynchronous responses,
/// then it MAY set the Asynchronous
///
/// Indicator in the header of a batched request.
/// The batched responses MAY contain a mixture of synchronous and
/// asynchronous responses only if the Asynchronous Indicator is present in the header.
use serde::Serialize;

use super::{
    kmip_operations::ErrorReason,
    kmip_types::{
        AsynchronousIndicator, AttestationType, BatchErrorContinuationOption, Credential,
        MessageExtension, Nonce, OperationEnumeration, ProtocolVersion, ResultStatusEnumeration,
    },
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RequestMessage {
    /// Header of the request
    pub header: RequestHeader,
    /// Batch items of the request
    pub items: Vec<RequestBatchItem>,
}

/// Header of the request
///
/// Contains fields whose presence is determined by the protocol features used.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RequestHeader {
    pub protocol_version: ProtocolVersion,
    /// This is an OPTIONAL field contained in a request message,
    /// and is used to indicate the maximum size of a response, in bytes,
    /// that the requester SHALL be able to handle.
    ///
    /// It SHOULD only be sent in requests that possibly return large replies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_response_size: Option<u32>,
    /// The Client Correlation Value is a string that MAY be added to messages by clients
    /// to provide additional information to the server. It need not be unique.
    /// The server SHOULD log this information.
    ///
    /// For client to server operations, the Client Correlation Value is provided in the request.
    /// For server to client operations, the Client Correlation Value is provided in the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_correlation_value: Option<String>,
    /// The Server Correlation Value SHOULD be provided by the server and
    /// SHOULD be globally unique, and SHOULD be logged by the server with each request.
    ///
    /// For client to server operations, the Server Correlation Value is provided in the response.
    /// For server to client operations, the Server Correlation Value is provided in the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_correlation_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asynchronous_indicator: Option<AsynchronousIndicator>,
    /// Indicates whether the client is able to create
    /// an Attestation Credential Object.
    ///
    /// If not present, the value `false` is assumed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_capable_indicator: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_type: Option<Vec<AttestationType>>,
    /// Used to authenticate the requester
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Credential>>,
    /// If omitted, then `Stop` is assumed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_error_continuation_option: Option<BatchErrorContinuationOption>,
    /// If omitted, then `true` is assumed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_order_option: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>, // epoch millis
    /// This field contains the number of Batch Items in a message and is REQUIRED.
    ///
    /// If only a single operation is being requested, then the batch count SHALL be set to 1.
    /// The Message Payload, which follows the Message Header, contains one or more batch items.
    pub batch_count: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RequestBatchItem {
    operation: OperationEnumeration,
    /// Indicates that the Data output of the operation should not
    /// be returned to the client
    ephemeral: Option<bool>,
    /// Required if `batch_count` > 1
    unique_batch_item_id: Option<u32>,
    /// Depends on the Operation
    request_payload: Vec<u8>,
    message_extension: Option<Vec<MessageExtension>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResponseMessage {
    /// Header of the response
    pub header: ResponseHeader,
    /// Batch items of the response
    pub items: Vec<ResponseBatchItem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResponseHeader {
    pub protocol_version: ProtocolVersion,
    pub timestamp: u64, // epoch millis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Nonce>,
    /// Mandatory only if Hashed Password credential was used
    ///
    /// Hash(Timestamp || S1 || Hash(S2)), where S1, S2 and
    /// the Hash algorithm are defined in the Hashed Password credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_hashed_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_type: Option<Vec<AttestationType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_correlation_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_correlation_value: Option<String>,
    /// This field contains the number of Batch Items in a message and is REQUIRED.
    ///
    /// If only a single operation is being requested, then the batch count SHALL be set to 1.
    /// The Message Payload, which follows the Message Header, contains one or more batch items.
    pub batch_count: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResponseBatchItem {
    /// Required if present in Request Batch Item
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationEnumeration>,
    /// Required if present in Request Batch Item
    pub unique_batch_item_id: Option<u32>,
    /// Indicates the success or failure of a request
    pub result_status: ResultStatusEnumeration,
    /// Indicates a reason for failure or a modifier for a
    /// partially successful operation and SHALL be present in
    /// responses that return a Result Status of Failure.
    ///
    /// Required if `result_status` is `Failure`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_reason: Option<ErrorReason>,
    /// Contains a more descriptive error message,
    /// which MAY be provided to an end user or used for logging/auditing purposes.
    ///
    /// Required if `result_status` is NOT `Pending` or `Success`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_message: Option<String>,
    /// Returned in the immediate response to an operation that is pending and
    /// that requires asynchronous polling. Note: the server decides which
    /// operations are performed synchronously or asynchronously.
    ///
    /// A server-generated correlation value SHALL be specified in any subsequent
    /// Poll or Cancel operations that pertain to the original operation.
    ///
    /// Required if `result_status` is `Pending`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asynchronous_correlation_value: Option<Vec<u8>>,
    /// Mandatory if a success, `None` in case of failure.
    ///
    /// Content depends on Operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_payload: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_extension: Option<MessageExtension>,
}
