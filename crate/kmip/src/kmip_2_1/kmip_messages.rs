use std::fmt::{self, Display, Formatter};

use cosmian_logger::trace;
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
    Deserialize, Serialize,
    de::{self, MapAccess, Visitor},
    ser::{self, SerializeStruct},
};

use super::{kmip_operations::Operation, kmip_types::OperationEnumeration};
use crate::{
    KmipError,
    error::result::KmipResult,
    kmip_0::{
        kmip_messages::{ResponseMessage, ResponseMessageBatchItemVersioned},
        kmip_types::{Direction, ErrorReason, MessageExtension, ResultStatusEnumeration},
    },
};

impl ResponseMessage {
    pub fn extract_items_data(&self) -> KmipResult<Vec<Vec<u8>>> {
        self.batch_item
            .iter()
            .map(|item| {
                let ResponseMessageBatchItemVersioned::V21(payload) = item else {
                    return Err(KmipError::Default(
                        "Unsupported response message version".to_owned(),
                    ));
                };
                let response_payload = payload.response_payload.as_ref().ok_or_else(|| {
                    KmipError::Default("Missing operation in Message Response".to_owned())
                })?;
                match response_payload {
                    Operation::DecryptResponse(response) => response
                        .data
                        .as_ref()
                        .map(|data| data.to_vec())
                        .ok_or_else(|| {
                            KmipError::Default("Missing data in Decrypt Response".to_owned())
                        }),
                    Operation::EncryptResponse(response) => response
                        .data
                        .as_ref()
                        .ok_or_else(|| {
                            KmipError::Default("Missing data in Encrypt Response".to_owned())
                        })
                        .cloned(),
                    Operation::HashResponse(response) => response
                        .data
                        .as_ref()
                        .ok_or_else(|| {
                            KmipError::Default("Missing data in Hash Response".to_owned())
                        })
                        .cloned(),
                    Operation::MACResponse(response) => response
                        .mac_data
                        .as_ref()
                        .ok_or_else(|| {
                            KmipError::Default("Missing data in Mac Response".to_owned())
                        })
                        .cloned(),
                    unexpected_operation => Err(KmipError::Default(format!(
                        "Unexpected operation in Message Response: {unexpected_operation}"
                    ))),
                }
            })
            .collect()
    }
}

/// Batch item for a message request
///
/// `request_payload` depends on the request
#[derive(PartialEq, Eq, Clone, Debug)]
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
        writeln!(f, "  RequestMessageBatchItem {{")?;
        writeln!(f, "    operation: {},", self.operation)?;
        if let Some(ephemeral) = self.ephemeral {
            writeln!(f, "    ephemeral: {ephemeral},")?;
        }
        if let Some(id) = self.unique_batch_item_id.as_ref() {
            writeln!(f, "    unique_batch_item_id: {id:?},")?;
        }
        writeln!(f, "    request_payload: {},", self.request_payload)?;
        if let Some(ext) = self.message_extension.as_ref() {
            for ext in ext {
                writeln!(f, "      extension: {ext},")?;
            }
        }
        write!(f, "}}")
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
                "request payload operation is not a request type operation (`{}`)",
                match self.request_payload.direction() {
                    Direction::Request => "Request",
                    Direction::Response => "Response",
                }
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
                            let Some(operation) = operation else {
                                return Err(de::Error::missing_field("operation"));
                            };
                            // recover by hand the proper type of `request_payload`
                            // the default derived deserializer does not have enough
                            // information to properly recover which type has been
                            // serialized, we need to do the job by hand,
                            // using the `operation` enum.
                            request_payload = Some(match operation {
                                OperationEnumeration::AddAttribute => {
                                    Operation::AddAttribute(map.next_value()?)
                                }
                                OperationEnumeration::Certify => {
                                    Operation::Certify(map.next_value()?)
                                }
                                OperationEnumeration::Create => {
                                    Operation::Create(map.next_value()?)
                                }
                                OperationEnumeration::CreateKeyPair => {
                                    Operation::CreateKeyPair(map.next_value()?)
                                }
                                OperationEnumeration::Decrypt => {
                                    Operation::Decrypt(map.next_value()?)
                                }
                                OperationEnumeration::Destroy => {
                                    Operation::Destroy(map.next_value()?)
                                }
                                OperationEnumeration::DiscoverVersions => {
                                    Operation::DiscoverVersions(map.next_value()?)
                                }
                                OperationEnumeration::Encrypt => {
                                    Operation::Encrypt(map.next_value()?)
                                }
                                OperationEnumeration::Export => {
                                    Operation::Export(map.next_value()?)
                                }
                                OperationEnumeration::Get => Operation::Get(map.next_value()?),
                                OperationEnumeration::GetAttributes => {
                                    Operation::GetAttributes(map.next_value()?)
                                }
                                OperationEnumeration::GetAttributeList => {
                                    Operation::GetAttributeList(map.next_value()?)
                                }
                                OperationEnumeration::Import => {
                                    Operation::Import(map.next_value()?)
                                }
                                OperationEnumeration::Hash => Operation::Hash(map.next_value()?),
                                OperationEnumeration::Locate => {
                                    Operation::Locate(map.next_value()?)
                                }
                                OperationEnumeration::MAC => Operation::MAC(map.next_value()?),
                                OperationEnumeration::MACVerify => {
                                    Operation::MACVerify(map.next_value()?)
                                }
                                OperationEnumeration::Sign => Operation::Sign(map.next_value()?),
                                OperationEnumeration::SignatureVerify => {
                                    Operation::SignatureVerify(map.next_value()?)
                                }
                                OperationEnumeration::Query => Operation::Query(map.next_value()?),
                                OperationEnumeration::Revoke => {
                                    Operation::Revoke(map.next_value()?)
                                }
                                OperationEnumeration::Register => {
                                    Operation::Register(map.next_value()?)
                                }
                                OperationEnumeration::Activate => {
                                    Operation::Activate(map.next_value()?)
                                }
                                OperationEnumeration::ModifyAttribute => {
                                    Operation::ModifyAttribute(map.next_value()?)
                                }
                                OperationEnumeration::Check => Operation::Check(map.next_value()?),
                                #[cfg(feature = "interop")]
                                OperationEnumeration::Interop => {
                                    Operation::Interop(map.next_value()?)
                                }
                                OperationEnumeration::Log => Operation::Log(map.next_value()?),
                                OperationEnumeration::PKCS11 => {
                                    Operation::PKCS11(map.next_value()?)
                                }
                                OperationEnumeration::RNGRetrieve => {
                                    Operation::RNGRetrieve(map.next_value()?)
                                }
                                OperationEnumeration::RNGSeed => {
                                    Operation::RNGSeed(map.next_value()?)
                                }
                                OperationEnumeration::DeleteAttribute => {
                                    Operation::DeleteAttribute(map.next_value()?)
                                }
                                x => {
                                    return Err(de::Error::custom(format!(
                                        "Request Message Batch Item: unsupported operation: {x:?}"
                                    )));
                                }
                            });
                        }
                    }
                }
                let operation = operation.ok_or_else(|| de::Error::missing_field("Operation"))?;
                trace!("MessageBatchItem operation: {operation:?}");

                let request_payload =
                    request_payload.ok_or_else(|| de::Error::missing_field("request_payload"))?;
                trace!("MessageBatchItem request payload: {request_payload}");

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
            "operation",
            "ephemeral",
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

impl Display for ResponseMessageBatchItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "  ResponseMessageBatchItem {{")?;
        if let Some(operation) = self.operation {
            writeln!(f, "    operation: {operation},")?;
        }
        if let Some(id) = self.unique_batch_item_id.as_ref() {
            writeln!(f, "    unique_batch_item_id: {id:?},")?;
        }
        writeln!(f, "    result_status: {},", self.result_status)?;
        if let Some(reason) = self.result_reason.as_ref() {
            writeln!(f, "    result_reason: {reason},")?;
        }
        if let Some(msg) = self.result_message.as_ref() {
            writeln!(f, "    result_message: {msg:?},")?;
        }
        if let Some(acv) = self.asynchronous_correlation_value.as_ref() {
            writeln!(f, "    asynchronous_correlation_value: {acv:?},")?;
        }
        if let Some(payload) = self.response_payload.as_ref() {
            writeln!(f, "    response_payload: {payload},")?;
        }
        if let Some(ext) = self.message_extension.as_ref() {
            writeln!(f, "    message_extension: {ext},")?;
        }
        write!(f, "}}")
    }
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
                ));
            }
            // Cosmian strict XML interop: allow missing ResultMessage for failure/undone (vectors omit it)
            ResultStatusEnumeration::OperationFailed | ResultStatusEnumeration::OperationUndone => {
            }
            ResultStatusEnumeration::OperationPending
                if self.asynchronous_correlation_value.is_none() =>
            {
                return Err(ser::Error::custom(
                    "missing `AsynchronousCorrelationValue` with pending status (`ResultStatus` \
                     is set to `OperationPending`)",
                ));
            }
            _ => (),
        }

        let mut st = serializer.serialize_struct("MessageResponseBatchItem", 5)?;
        if let Some(operation) = self.operation {
            if let Some(response_payload) = &self.response_payload {
                if operation != response_payload.operation_enum() {
                    return Err(ser::Error::custom(format!(
                        "operation enum (`{}`) doesn't correspond to response payload (`{}`)",
                        operation,
                        response_payload.operation_enum()
                    )));
                }

                if response_payload.direction() != Direction::Response {
                    return Err(ser::Error::custom(format!(
                        "response payload operation is not a response type operation (`{}`)",
                        match response_payload.direction() {
                            Direction::Request => "Request",
                            Direction::Response => "Response",
                        }
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
                            let Some(operation) = operation else {
                                return Err(de::Error::missing_field("operation"));
                            };
                            // recover by hand the proper type of `response_payload`
                            // the default derived deserializer does not have enough
                            // information to properly recover which type has been
                            // serialized, we need to do the job by hand,
                            // using the `operation` enum.
                            response_payload = Some(match operation {
                                OperationEnumeration::AddAttribute => {
                                    Operation::AddAttributeResponse(map.next_value()?)
                                }
                                OperationEnumeration::Certify => {
                                    Operation::CertifyResponse(map.next_value()?)
                                }
                                OperationEnumeration::Create => {
                                    Operation::CreateResponse(map.next_value()?)
                                }
                                OperationEnumeration::CreateKeyPair => {
                                    Operation::CreateKeyPairResponse(map.next_value()?)
                                }
                                OperationEnumeration::Decrypt => {
                                    Operation::DecryptResponse(map.next_value()?)
                                }
                                OperationEnumeration::Destroy => {
                                    Operation::DestroyResponse(map.next_value()?)
                                }
                                OperationEnumeration::DiscoverVersions => {
                                    Operation::DiscoverVersionsResponse(map.next_value()?)
                                }
                                OperationEnumeration::Encrypt => {
                                    Operation::EncryptResponse(map.next_value()?)
                                }
                                OperationEnumeration::Export => {
                                    Operation::ExportResponse(map.next_value()?)
                                }
                                OperationEnumeration::Get => {
                                    Operation::GetResponse(map.next_value()?)
                                }
                                OperationEnumeration::GetAttributes => {
                                    Operation::GetAttributesResponse(map.next_value()?)
                                }
                                OperationEnumeration::GetAttributeList => {
                                    Operation::GetAttributeListResponse(map.next_value()?)
                                }
                                OperationEnumeration::Import => {
                                    Operation::ImportResponse(map.next_value()?)
                                }
                                OperationEnumeration::Hash => {
                                    Operation::HashResponse(map.next_value()?)
                                }
                                OperationEnumeration::Locate => {
                                    Operation::LocateResponse(map.next_value()?)
                                }
                                OperationEnumeration::MAC => {
                                    Operation::MACResponse(map.next_value()?)
                                }
                                OperationEnumeration::MACVerify => {
                                    Operation::MACVerifyResponse(map.next_value()?)
                                }
                                OperationEnumeration::Sign => {
                                    Operation::SignResponse(map.next_value()?)
                                }
                                OperationEnumeration::SignatureVerify => {
                                    Operation::SignatureVerifyResponse(map.next_value()?)
                                }
                                OperationEnumeration::Query => {
                                    Operation::QueryResponse(map.next_value()?)
                                }
                                OperationEnumeration::Revoke => {
                                    Operation::RevokeResponse(map.next_value()?)
                                }
                                OperationEnumeration::Register => {
                                    Operation::RegisterResponse(map.next_value()?)
                                }
                                OperationEnumeration::Activate => {
                                    Operation::ActivateResponse(map.next_value()?)
                                }
                                OperationEnumeration::ModifyAttribute => {
                                    Operation::ModifyAttributeResponse(map.next_value()?)
                                }
                                OperationEnumeration::Check => {
                                    Operation::CheckResponse(map.next_value()?)
                                }
                                OperationEnumeration::DeleteAttribute => {
                                    Operation::DeleteAttributeResponse(map.next_value()?)
                                }
                                #[cfg(feature = "interop")]
                                OperationEnumeration::Interop => {
                                    Operation::InteropResponse(map.next_value()?)
                                }
                                OperationEnumeration::Log => {
                                    Operation::LogResponse(map.next_value()?)
                                }
                                OperationEnumeration::PKCS11 => {
                                    Operation::PKCS11Response(map.next_value()?)
                                }
                                OperationEnumeration::RNGRetrieve => {
                                    Operation::RNGRetrieveResponse(map.next_value()?)
                                }
                                OperationEnumeration::RNGSeed => {
                                    Operation::RNGSeedResponse(map.next_value()?)
                                }
                                x => {
                                    return Err(de::Error::custom(format!(
                                        "KMIP 2 response message payload: unsupported operation: \
                                         {x:?}"
                                    )));
                                }
                            });
                        }
                    }
                }

                trace!("MessageResponseBatchItem operation: {operation:?}");
                if let Some(response_payload) = &response_payload {
                    trace!("MessageResponseBatchItem response payload: {response_payload}");
                }

                let result_status =
                    result_status.ok_or_else(|| de::Error::missing_field("result_status"))?;

                match result_status {
                    ResultStatusEnumeration::OperationFailed if result_reason.is_none() => {
                        // missing `ResultReason` with failed status
                        return Err(de::Error::missing_field("result_reason"));
                    }
                    ResultStatusEnumeration::OperationFailed
                    | ResultStatusEnumeration::OperationUndone => { /* allow missing result_message */
                    }
                    ResultStatusEnumeration::OperationPending
                        if asynchronous_correlation_value.is_none() =>
                    {
                        // missing `ResultMessage` with unsuccessful status
                        return Err(de::Error::missing_field("asynchronous_correlation_value"));
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
