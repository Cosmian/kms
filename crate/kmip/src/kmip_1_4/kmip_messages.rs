use std::fmt::{self, Display, Formatter};

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
use serde::{
    de::{self, MapAccess, Visitor},
    ser::{self, SerializeStruct},
    Deserialize, Serialize,
};

use super::{kmip_operations::Operation, kmip_types::OperationEnumeration};
use crate::{
    kmip_0::kmip_types::{Direction, ErrorReason, MessageExtension, ResultStatusEnumeration},
    kmip_2_1, KmipError, KmipResultHelper,
};

/// Batch item for a message request
///
/// `request_payload` depends on the request
#[derive(PartialEq, Eq, Debug)]
pub struct RequestMessageBatchItem {
    /// Type of the KMIP operation
    pub operation: OperationEnumeration,

    /// Indicates that the Data output of the operation should not
    /// be returned to the client
    pub ephemeral: Option<bool>,

    /// This is an OPTIONAL field contained in a request,
    /// and is used for correlation between requests and responses.
    ///
    /// If a request has a Unique Batch Item ID, then responses to
    /// that request SHALL have the same Unique Batch Item ID.
    pub unique_batch_item_id: Option<Vec<u8>>,

    /// The KMIP request, which depends on the KMIP Operation
    pub request_payload: Operation,

    pub message_extension: Option<Vec<MessageExtension>>,
}

impl Display for RequestMessageBatchItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MessageBatchItem {{ operation: {:?}, ephemeral: {:?}, unique_batch_item_id: {:?}, \
             request_payload: {}, message_extension: {:?} }}",
            self.operation,
            self.ephemeral,
            self.unique_batch_item_id,
            self.request_payload,
            self.message_extension
        )
    }
}
impl RequestMessageBatchItem {
    #[must_use]
    pub const fn new(request: Operation) -> Self {
        Self {
            operation: request.operation_enum(),
            ephemeral: None,
            unique_batch_item_id: None,
            request_payload: request,
            message_extension: None,
        }
    }
}

impl Serialize for RequestMessageBatchItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.operation != self.request_payload.operation_enum() {
            return Err(ser::Error::custom(format!(
                "operation enum (`{}`) doesn't correspond to request payload (`{}`)",
                self.operation,
                self.request_payload.operation_enum()
            )));
        }
        if self.request_payload.direction() != Direction::Request {
            return Err(ser::Error::custom(format!(
                "request payload operation is not a request type operation (`{:?}`)",
                self.request_payload.direction()
            )));
        }

        let mut st = serializer.serialize_struct("MessageBatchItem", 5)?;
        st.serialize_field("Operation", &self.operation)?;
        if let Some(ephemeral) = &self.ephemeral {
            st.serialize_field("Ephemeral", ephemeral)?;
        }
        if let Some(unique_batch_item_id) = &self.unique_batch_item_id {
            st.serialize_field("UniqueBatchItemID", unique_batch_item_id)?;
        }
        st.serialize_field("RequestPayload", &self.request_payload)?;
        if let Some(message_extension) = &self.message_extension {
            st.serialize_field("MessageExtension", &message_extension)?;
        }
        st.end()
    }
}

/// The `RequestMessageBatchItem` deserializer
/// This deserializer needs to be implemented by hand, because the request Payload
/// contains an untagged enum `Operation` which must be selected based on the
/// `OperationEnumeration` field value.
impl<'de> Deserialize<'de> for RequestMessageBatchItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(field_identifier)]
        enum Field {
            Operation,
            Ephemeral,
            UniqueBatchItemID,
            RequestPayload,
            MessageExtension,
        }

        struct RequestMessageBatchItemVisitor;

        impl<'de> Visitor<'de> for RequestMessageBatchItemVisitor {
            type Value = RequestMessageBatchItem;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("struct RequestMessageBatchItem")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut operation: Option<OperationEnumeration> = None;
                let mut ephemeral: Option<bool> = None;
                let mut unique_batch_item_id: Option<Vec<u8>> = None;
                let mut request_payload: Option<Operation> = None;
                let mut message_extension: Option<Vec<MessageExtension>> = None;
                // we need to parse all the fields
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Operation => {
                            if operation.is_some() {
                                return Err(de::Error::duplicate_field("Operation"));
                            }
                            operation = Some(map.next_value()?);
                        }
                        Field::Ephemeral => {
                            if ephemeral.is_some() {
                                return Err(de::Error::duplicate_field("Ephemeral"));
                            }
                            ephemeral = Some(map.next_value()?);
                        }
                        Field::UniqueBatchItemID => {
                            if unique_batch_item_id.is_some() {
                                return Err(de::Error::duplicate_field("UniqueBatchItemID"));
                            }
                            unique_batch_item_id = Some(map.next_value()?);
                        }
                        Field::MessageExtension => {
                            if message_extension.is_some() {
                                return Err(de::Error::duplicate_field("MessageExtension"));
                            }
                            message_extension = Some(map.next_value()?);
                        }
                        Field::RequestPayload => {
                            if request_payload.is_some() {
                                return Err(de::Error::duplicate_field("RequestPayload"));
                            }
                            // we must have parsed the `operation` field before
                            // TODO: handle the case where the keys are not in right order
                            let Some(operation) = &operation else {
                                return Err(de::Error::missing_field("operation"))
                            };
                            // recover by hand the proper type of `request_payload`
                            // the default derived deserializer does not have enough
                            // information to properly recover which type has been
                            // serialized, we need to do the job by hand,
                            // using the `operation` enum.
                            request_payload = Some(match operation {
                                OperationEnumeration::Encrypt => {
                                    Operation::Encrypt(map.next_value()?)
                                }
                                OperationEnumeration::Create => {
                                    Operation::Create(map.next_value()?)
                                }
                                OperationEnumeration::CreateKeyPair => {
                                    Operation::CreateKeyPair(map.next_value()?)
                                }
                                OperationEnumeration::Certify => {
                                    Operation::Certify(map.next_value()?)
                                }
                                OperationEnumeration::Locate => {
                                    Operation::Locate(map.next_value()?)
                                }
                                OperationEnumeration::Get => Operation::Get(map.next_value()?),
                                OperationEnumeration::GetAttributes => {
                                    Operation::GetAttributes(map.next_value()?)
                                }
                                OperationEnumeration::Revoke => {
                                    Operation::Revoke(map.next_value()?)
                                }
                                OperationEnumeration::Destroy => {
                                    Operation::Destroy(map.next_value()?)
                                }
                                OperationEnumeration::Decrypt => {
                                    Operation::Decrypt(map.next_value()?)
                                }
                                OperationEnumeration::Import => {
                                    Operation::Import(map.next_value()?)
                                }
                                OperationEnumeration::Export => {
                                    Operation::Export(map.next_value()?)
                                }
                                OperationEnumeration::Query => Operation::Query(map.next_value()?),
                                OperationEnumeration::DiscoverVersions => {
                                    Operation::DiscoverVersions(map.next_value()?)
                                }
                                x => {
                                    return Err(de::Error::custom(format!(
                                        "unsupported KMIP 1 operation: {x:?}"
                                    )))
                                }
                            });
                        }
                    }
                }
                let operation = operation.ok_or_else(|| de::Error::missing_field("Operation"))?;
                tracing::trace!("MessageBatchItem operation: {operation:?}");

                let request_payload =
                    request_payload.ok_or_else(|| de::Error::missing_field("request_payload"))?;
                tracing::trace!("MessageBatchItem request payload: {request_payload}");

                if operation != request_payload.operation_enum() {
                    return Err(de::Error::custom(format!(
                        "operation enum (`{}`) doesn't correspond to request payload (`{}`)",
                        operation,
                        request_payload.operation_enum()
                    )));
                }

                Ok(RequestMessageBatchItem {
                    operation,
                    ephemeral,
                    unique_batch_item_id,
                    request_payload,
                    message_extension,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "Operation",
            "Ephemeral",
            "UniqueBatchItemID",
            "RequestPayload",
            "MessageExtension",
        ];
        deserializer.deserialize_struct(
            "RequestMessageBatchItem",
            FIELDS,
            RequestMessageBatchItemVisitor,
        )
    }
}

impl TryFrom<RequestMessageBatchItem> for kmip_2_1::kmip_messages::RequestMessageBatchItem {
    type Error = KmipError;

    fn try_from(item: RequestMessageBatchItem) -> Result<Self, Self::Error> {
        Ok(Self {
            operation: item.operation.into(),
            ephemeral: item.ephemeral,
            unique_batch_item_id: item.unique_batch_item_id,
            request_payload: item.request_payload.try_into()?,
            message_extension: item.message_extension,
        })
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct ResponseMessageBatchItem {
    /// Required if present in request Batch Item
    pub operation: Option<OperationEnumeration>,

    /// Required if present in request Batch Item
    pub unique_batch_item_id: Option<Vec<u8>>,

    /// Indicates the success or failure of a request
    pub result_status: ResultStatusEnumeration,

    /// Indicates a reason for failure or a modifier for a
    /// partially successful operation and SHALL be present in
    /// responses that return a Result Status of Failure.
    ///
    /// Required if `result_status` is `Failure`
    pub result_reason: Option<ErrorReason>,

    /// Contains a more descriptive error message,
    /// which MAY be provided to an end user or used for logging/auditing purposes.
    ///
    /// Required if `result_status` is NOT `Pending` or `Success`
    pub result_message: Option<String>,

    /// Returned in the immediate response to an operation that is pending and
    /// that requires asynchronous polling. Note: the server decides which
    /// operations are performed synchronously or asynchronously.
    ///
    /// A server-generated correlation value SHALL be specified in any subsequent
    /// Poll or Cancel operations that pertain to the original operation.
    ///
    /// Required if `result_status` is `Pending`
    pub asynchronous_correlation_value: Option<String>,

    /// The KMIP response, which depends on the KMIP Operation
    ///
    /// Mandatory if a success, `None` in case of failure.
    ///
    /// Content depends on Operation.
    pub response_payload: Option<Operation>,

    pub message_extension: Option<MessageExtension>,
}

impl ResponseMessageBatchItem {
    #[must_use]
    pub const fn new(result_status: ResultStatusEnumeration) -> Self {
        Self {
            result_status,
            operation: None,
            unique_batch_item_id: None,
            result_reason: None,
            result_message: None,
            asynchronous_correlation_value: None,
            response_payload: None,
            message_extension: None,
        }
    }

    #[must_use]
    pub const fn new_with_response(
        result_status: ResultStatusEnumeration,
        response: Operation,
    ) -> Self {
        Self {
            result_status,
            operation: Some(response.operation_enum()),
            response_payload: Some(response),
            unique_batch_item_id: None,
            result_reason: None,
            result_message: None,
            asynchronous_correlation_value: None,
            message_extension: None,
        }
    }
}

impl Serialize for ResponseMessageBatchItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.result_status {
            ResultStatusEnumeration::OperationFailed if self.result_reason.is_none() => {
                return Err(ser::Error::custom(
                    "missing `ResultReason` with failed status (`ResultStatus` is set to \
                     `OperationFailed`)",
                ))
            }
            ResultStatusEnumeration::OperationFailed | ResultStatusEnumeration::OperationUndone
                if self.result_message.is_none() =>
            {
                return Err(ser::Error::custom(
                    "missing `ResultMessage` with unsuccessful status (`ResultStatus` is set to \
                     either `OperationFailed` or `OperationUndone`)",
                ))
            }
            ResultStatusEnumeration::OperationPending
                if self.asynchronous_correlation_value.is_none() =>
            {
                return Err(ser::Error::custom(
                    "missing `AsynchronousCorrelationValue` with pending status (`ResultStatus` \
                     is set to `OperationPending`)",
                ))
            }
            _ => (),
        }

        let mut st = serializer.serialize_struct("MessageResponseBatchItem", 5)?;
        if let Some(operation) = &self.operation {
            if let Some(response_payload) = &self.response_payload {
                if operation != &response_payload.operation_enum() {
                    return Err(ser::Error::custom(format!(
                        "operation enum (`{}`) doesn't correspond to response payload (`{}`)",
                        operation,
                        response_payload.operation_enum()
                    )));
                }

                if response_payload.direction() != Direction::Response {
                    return Err(ser::Error::custom(format!(
                        "response payload operation is not a response type operation (`{:?}`)",
                        response_payload.direction()
                    )));
                }
            }

            st.serialize_field("Operation", &self.operation)?;
        }
        if let Some(unique_batch_item_id) = &self.unique_batch_item_id {
            st.serialize_field("UniqueBatchItemID", unique_batch_item_id)?;
        }
        st.serialize_field("ResultStatus", &self.result_status)?;
        if let Some(result_reason) = &self.result_reason {
            st.serialize_field("ResultReason", result_reason)?;
        }
        if let Some(result_message) = &self.result_message {
            st.serialize_field("ResultMessage", result_message)?;
        }
        if let Some(acv) = &self.asynchronous_correlation_value {
            st.serialize_field("AsynchronousCorrelationValue", &acv)?;
        }
        if let Some(response_payload) = &self.response_payload {
            st.serialize_field("ResponsePayload", &response_payload)?;
        }
        if let Some(message_extension) = &self.message_extension {
            st.serialize_field("MessageExtension", &message_extension)?;
        }
        st.end()
    }
}

impl<'de> Deserialize<'de> for ResponseMessageBatchItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            Operation,
            UniqueBatchItemID,
            ResultStatus,
            ResultReason,
            ResultMessage,
            AsynchronousCorrelationValue,
            ResponsePayload,
            MessageExtension,
        }

        struct MessageResponseBatchItemVisitor;

        impl<'de> Visitor<'de> for MessageResponseBatchItemVisitor {
            type Value = ResponseMessageBatchItem;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct MessageResponseBatchItem")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut operation: Option<OperationEnumeration> = None;
                let mut unique_batch_item_id: Option<Vec<u8>> = None;
                let mut result_status: Option<ResultStatusEnumeration> = None;
                let mut result_reason: Option<ErrorReason> = None;
                let mut result_message: Option<String> = None;
                let mut asynchronous_correlation_value: Option<String> = None;
                let mut response_payload: Option<Operation> = None;
                let mut message_extension: Option<MessageExtension> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Operation => {
                            if operation.is_some() {
                                return Err(de::Error::duplicate_field("operation"));
                            }
                            operation = Some(map.next_value()?);
                        }
                        Field::UniqueBatchItemID => {
                            if unique_batch_item_id.is_some() {
                                return Err(de::Error::duplicate_field("unique_batch_item_id"));
                            }
                            unique_batch_item_id = Some(map.next_value()?);
                        }
                        Field::MessageExtension => {
                            if message_extension.is_some() {
                                return Err(de::Error::duplicate_field("message_extension"));
                            }
                            message_extension = Some(map.next_value()?);
                        }
                        Field::ResultStatus => {
                            if result_status.is_some() {
                                return Err(de::Error::duplicate_field("result_status"));
                            }
                            result_status = Some(map.next_value()?);
                        }
                        Field::ResultReason => {
                            if result_reason.is_some() {
                                return Err(de::Error::duplicate_field("result_reason"));
                            }
                            result_reason = Some(map.next_value()?);
                        }
                        Field::ResultMessage => {
                            if result_message.is_some() {
                                return Err(de::Error::duplicate_field("result_message"));
                            }
                            result_message = Some(map.next_value()?);
                        }
                        Field::AsynchronousCorrelationValue => {
                            if asynchronous_correlation_value.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "asynchronous_correlation_value",
                                ));
                            }
                            asynchronous_correlation_value = Some(map.next_value()?);
                        }
                        Field::ResponsePayload => {
                            if response_payload.is_some() {
                                return Err(de::Error::duplicate_field("response_payload"));
                            }
                            // we must have parsed the `operation` field before
                            // TODO: handle the case where the keys are not in right order
                            let Some(operation) = &operation else {
                                return Err(de::Error::missing_field("operation"))
                            };
                            // recover by hand the proper type of `response_payload`
                            // the default derived deserializer does not have enough
                            // information to properly recover which type has been
                            // serialized, we need to do the job by hand,
                            // using the `operation` enum.
                            response_payload = Some(match operation {
                                OperationEnumeration::Encrypt => {
                                    Operation::EncryptResponse(map.next_value()?)
                                }
                                OperationEnumeration::Create => {
                                    Operation::CreateResponse(map.next_value()?)
                                }
                                OperationEnumeration::CreateKeyPair => {
                                    Operation::CreateKeyPairResponse(map.next_value()?)
                                }
                                OperationEnumeration::Certify => {
                                    Operation::CertifyResponse(map.next_value()?)
                                }
                                OperationEnumeration::Locate => {
                                    Operation::LocateResponse(map.next_value()?)
                                }
                                OperationEnumeration::Get => {
                                    Operation::GetResponse(map.next_value()?)
                                }
                                OperationEnumeration::GetAttributes => {
                                    Operation::GetAttributesResponse(map.next_value()?)
                                }
                                OperationEnumeration::Revoke => {
                                    Operation::RevokeResponse(map.next_value()?)
                                }
                                OperationEnumeration::Destroy => {
                                    Operation::DestroyResponse(map.next_value()?)
                                }
                                OperationEnumeration::Decrypt => {
                                    Operation::DecryptResponse(map.next_value()?)
                                }
                                OperationEnumeration::Import => {
                                    Operation::ImportResponse(map.next_value()?)
                                }
                                OperationEnumeration::Export => {
                                    Operation::ExportResponse(map.next_value()?)
                                }
                                OperationEnumeration::Register => {
                                    Operation::RegisterResponse(map.next_value()?)
                                }
                                OperationEnumeration::ReKey => {
                                    Operation::ReKeyResponse(map.next_value()?)
                                }
                                OperationEnumeration::DeriveKey => {
                                    Operation::DeriveKeyResponse(map.next_value()?)
                                }
                                OperationEnumeration::ReCertify => {
                                    Operation::ReCertifyResponse(map.next_value()?)
                                }
                                OperationEnumeration::Check => {
                                    Operation::CheckResponse(map.next_value()?)
                                }
                                OperationEnumeration::GetAttributeList => {
                                    Operation::GetAttributeListResponse(map.next_value()?)
                                }
                                OperationEnumeration::AddAttribute => {
                                    Operation::AddAttributeResponse(map.next_value()?)
                                }
                                OperationEnumeration::ModifyAttribute => {
                                    Operation::ModifyAttributeResponse(map.next_value()?)
                                }
                                OperationEnumeration::DeleteAttribute => {
                                    Operation::DeleteAttributeResponse(map.next_value()?)
                                }
                                OperationEnumeration::ObtainLease => {
                                    Operation::ObtainLeaseResponse(map.next_value()?)
                                }
                                OperationEnumeration::GetUsageAllocation => {
                                    Operation::GetUsageAllocationResponse(map.next_value()?)
                                }
                                OperationEnumeration::Activate => {
                                    Operation::ActivateResponse(map.next_value()?)
                                }
                                OperationEnumeration::Archive => {
                                    Operation::ArchiveResponse(map.next_value()?)
                                }
                                OperationEnumeration::Recover => {
                                    Operation::RecoverResponse(map.next_value()?)
                                }
                                OperationEnumeration::Validate => {
                                    Operation::ValidateResponse(map.next_value()?)
                                }
                                OperationEnumeration::Query => {
                                    Operation::QueryResponse(map.next_value()?)
                                }
                                OperationEnumeration::Cancel => {
                                    Operation::CancelResponse(map.next_value()?)
                                }
                                OperationEnumeration::Poll => {
                                    Operation::PollResponse(map.next_value()?)
                                }
                                OperationEnumeration::Notify => {
                                    return Err(de::Error::custom(
                                        "Notify operation is not supported in response",
                                    ))
                                }
                                OperationEnumeration::Put => {
                                    return Err(de::Error::custom(
                                        "Put operation is not supported in response",
                                    ))
                                }
                                OperationEnumeration::ReKeyKeyPair => {
                                    Operation::ReKeyKeyPairResponse(map.next_value()?)
                                }
                                OperationEnumeration::DiscoverVersions => {
                                    Operation::DiscoverVersionsResponse(map.next_value()?)
                                }
                                OperationEnumeration::Sign => {
                                    Operation::SignResponse(map.next_value()?)
                                }
                                OperationEnumeration::SignatureVerify => {
                                    Operation::SignatureVerifyResponse(map.next_value()?)
                                }
                                OperationEnumeration::MAC => {
                                    Operation::MACResponse(map.next_value()?)
                                }
                                OperationEnumeration::MACVerify => {
                                    Operation::MACVerifyResponse(map.next_value()?)
                                }
                                OperationEnumeration::RNGRetrieve => {
                                    Operation::RNGRetrieveResponse(map.next_value()?)
                                }
                                OperationEnumeration::RNGSeed => {
                                    Operation::RNGSeedResponse(map.next_value()?)
                                }
                                OperationEnumeration::Hash => {
                                    Operation::HashResponse(map.next_value()?)
                                }
                                OperationEnumeration::CreateSplitKey => {
                                    Operation::CreateSplitKeyResponse(map.next_value()?)
                                }
                                OperationEnumeration::JoinSplitKey => {
                                    Operation::JoinSplitKeyResponse(map.next_value()?)
                                }
                            });
                        }
                    }
                }

                tracing::trace!("MessageResponseBatchItem operation: {operation:?}");
                if let Some(response_payload) = &response_payload {
                    tracing::trace!(
                        "MessageResponseBatchItem response payload: {response_payload}"
                    );
                }

                let result_status =
                    result_status.ok_or_else(|| de::Error::missing_field("result_status"))?;

                match result_status {
                    ResultStatusEnumeration::OperationFailed if result_reason.is_none() => {
                        // missing `ResultReason` with failed status
                        return Err(de::Error::missing_field("result_reason"))
                    }
                    ResultStatusEnumeration::OperationFailed
                    | ResultStatusEnumeration::OperationUndone
                        if result_message.is_none() =>
                    {
                        // missing `ResultMessage` with unsuccessful status
                        return Err(de::Error::missing_field("result_message"))
                    }
                    ResultStatusEnumeration::OperationPending
                        if asynchronous_correlation_value.is_none() =>
                    {
                        // missing `ResultMessage` with unsuccessful status
                        return Err(de::Error::missing_field("asynchronous_correlation_value"))
                    }
                    _ => (),
                }

                Ok(ResponseMessageBatchItem {
                    operation,
                    unique_batch_item_id,
                    result_status,
                    result_reason,
                    result_message,
                    asynchronous_correlation_value,
                    response_payload,
                    message_extension,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "operation",
            "unique_batch_item_id",
            "result_status",
            "result_reason",
            "result_message",
            "asynchronous_correlation_value",
            "response_payload",
            "message_extension",
        ];
        deserializer.deserialize_struct(
            "MessageResponseBatchItem",
            FIELDS,
            MessageResponseBatchItemVisitor,
        )
    }
}

impl TryFrom<kmip_2_1::kmip_messages::ResponseMessageBatchItem> for ResponseMessageBatchItem {
    type Error = KmipError;

    fn try_from(
        value: kmip_2_1::kmip_messages::ResponseMessageBatchItem,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            operation: value
                .operation
                .map(TryInto::try_into)
                .transpose()
                .context("ResponseMessageBatchItem->Operation")?,
            unique_batch_item_id: value.unique_batch_item_id,
            result_status: value.result_status,
            result_reason: value.result_reason,
            result_message: value.result_message,
            asynchronous_correlation_value: value.asynchronous_correlation_value,
            response_payload: value
                .response_payload
                .map(TryInto::try_into)
                .transpose()
                .context("ResponseMessageBatchItem->ResponsePayload")?,
            message_extension: value.message_extension,
        })
    }
}
