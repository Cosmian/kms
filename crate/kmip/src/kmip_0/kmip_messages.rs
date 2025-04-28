use std::fmt::{self, Formatter};

use serde::de::DeserializeSeed;
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
    Deserialize, Serialize, de,
    de::{MapAccess, Visitor},
    ser::{self, SerializeStruct},
};

use super::kmip_types::{
    AsynchronousIndicator, AttestationType, BatchErrorContinuationOption, Credential, Nonce,
    ProtocolVersion,
};
enum KmipVersion {
    V14,
    V21,
}

#[derive(PartialEq, Eq, Debug, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum RequestMessageBatchItemVersioned {
    V14(crate::kmip_1_4::kmip_messages::RequestMessageBatchItem),
    V21(crate::kmip_2_1::kmip_messages::RequestMessageBatchItem),
}

impl RequestMessageBatchItemVersioned {}

struct RequestMessageBatchItemVersionedDeserializer {
    kmip_version: KmipVersion,
}

impl<'de> DeserializeSeed<'de> for &mut RequestMessageBatchItemVersionedDeserializer {
    type Value = RequestMessageBatchItemVersioned;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match self.kmip_version {
            KmipVersion::V14 => Ok(RequestMessageBatchItemVersioned::V14(
                crate::kmip_1_4::kmip_messages::RequestMessageBatchItem::deserialize(deserializer)?,
            )),
            KmipVersion::V21 => Ok(RequestMessageBatchItemVersioned::V21(
                crate::kmip_2_1::kmip_messages::RequestMessageBatchItem::deserialize(deserializer)?,
            )),
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct RequestMessage {
    /// Header of the request
    pub request_header: RequestMessageHeader,
    /// Batch items of the request
    pub batch_item: Vec<RequestMessageBatchItemVersioned>,
}

impl Serialize for RequestMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let header_batch_count = usize::try_from(self.request_header.batch_count)
            .map_err(|err| ser::Error::custom(format!("failed to convert batch count: {err:?}")))?;
        // check batch item count
        let num_items = self.batch_item.len();
        if num_items == 0 {
            return Err(ser::Error::custom(
                "A request message must contain at least one batch item",
            ));
        }
        if header_batch_count != num_items {
            return Err(ser::Error::custom(format!(
                "mismatch count of batch items between header (`{}`) and actual items count (`{}`)",
                self.request_header.batch_count, num_items
            )));
        }
        let mut st = serializer.serialize_struct("RequestMessage", 2)?;
        st.serialize_field("RequestHeader", &self.request_header)?;
        st.serialize_field("BatchItem", &self.batch_item)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for RequestMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            RequestHeader,
            BatchItem,
        }

        struct RequestMessageVisitor;

        impl<'de> Visitor<'de> for RequestMessageVisitor {
            type Value = RequestMessage;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("struct RequestMessage")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut request_header: Option<RequestMessageHeader> = None;
                let mut items = vec![];

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::RequestHeader => {
                            if request_header.is_some() {
                                return Err(de::Error::duplicate_field("RequestHeader"));
                            }
                            request_header = Some(map.next_value()?);
                        }
                        Field::BatchItem => {
                            // determine kmip version from the header
                            let kmip_version = match request_header
                                .as_ref()
                                .map_or(0, |header| header.protocol_version.protocol_version_major)
                            {
                                1 => KmipVersion::V14,
                                2 => KmipVersion::V21,
                                x => {
                                    return Err(de::Error::custom(format!(
                                        "unsupported protocol version: {x}"
                                    )))
                                }
                            };
                            // deserialize using the RequestMessageBatchItemVersionedDeserializer
                            let mut deserializer =
                                RequestMessageBatchItemVersionedDeserializer { kmip_version };

                            let batch_item = map.next_value_seed(&mut deserializer)?;
                            items.push(batch_item);
                        }
                    }
                }
                let request_header =
                    request_header.ok_or_else(|| de::Error::missing_field("RequestHeader"))?;

                Ok(RequestMessage {
                    request_header,
                    batch_item: items,
                })
            }
        }

        const FIELDS: &[&str] = &["RequestHeader", "BatchItem"];
        deserializer.deserialize_struct("RequestMessage", FIELDS, RequestMessageVisitor)
    }
}

/// Header of the request
///
/// Contains fields whose presence is determined by the protocol features used.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RequestMessageHeader {
    /// The KMIP protocol version used in this message
    pub protocol_version: ProtocolVersion,

    /// This is an OPTIONAL field contained in a request message,
    /// and is used to indicate the maximum size of a response, in bytes,
    /// that the requester SHALL be able to handle.
    ///
    /// It SHOULD only be sent in requests that possibly return large replies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_response_size: Option<i32>,

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
    pub time_stamp: Option<u64>, // epoch millis

    /// This field contains the number of Batch Items in a message and is REQUIRED.
    ///
    /// If only a single operation is being requested, then the batch count SHALL be set to 1.
    /// The Message Payload, which follows the Message Header, contains one or more batch items.
    pub batch_count: i32,
}

impl Default for RequestMessageHeader {
    fn default() -> Self {
        Self {
            protocol_version: ProtocolVersion {
                protocol_version_major: 2,
                protocol_version_minor: 1,
            },
            maximum_response_size: Some(1024 * 1024),
            client_correlation_value: None,
            server_correlation_value: None,
            asynchronous_indicator: None,
            attestation_capable_indicator: None,
            attestation_type: None,
            authentication: None,
            batch_error_continuation_option: None,
            batch_order_option: None,
            time_stamp: None,
            batch_count: 0,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ResponseMessageBatchItemVersioned {
    V14(crate::kmip_1_4::kmip_messages::ResponseMessageBatchItem),
    V21(crate::kmip_2_1::kmip_messages::ResponseMessageBatchItem),
}

struct ResponseMessageBatchItemVersionedDeserializer {
    kmip_version: KmipVersion,
}

impl<'de> DeserializeSeed<'de> for &mut ResponseMessageBatchItemVersionedDeserializer {
    type Value = ResponseMessageBatchItemVersioned;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match self.kmip_version {
            KmipVersion::V14 => Ok(ResponseMessageBatchItemVersioned::V14(
                crate::kmip_1_4::kmip_messages::ResponseMessageBatchItem::deserialize(
                    deserializer,
                )?,
            )),
            KmipVersion::V21 => Ok(ResponseMessageBatchItemVersioned::V21(
                crate::kmip_2_1::kmip_messages::ResponseMessageBatchItem::deserialize(
                    deserializer,
                )?,
            )),
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct ResponseMessage {
    /// Header of the response
    pub response_header: ResponseMessageHeader,
    /// Batch items of the response
    pub batch_item: Vec<ResponseMessageBatchItemVersioned>,
}

impl Serialize for ResponseMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let header_batch_count = usize::try_from(self.response_header.batch_count)
            .map_err(|err| ser::Error::custom(format!("failed to convert batch count: {err:?}")))?;

        let num_items = self.batch_item.len();
        // check batch item count
        if header_batch_count != num_items {
            return Err(ser::Error::custom(format!(
                "mismatch number of batch items between header (`{}`) and items list (`{}`)",
                self.response_header.batch_count, num_items
            )));
        }
        let mut st = serializer.serialize_struct("ResponseMessage", 2)?;
        st.serialize_field("ResponseHeader", &self.response_header)?;
        st.serialize_field("BatchItem", &self.batch_item)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for ResponseMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            ResponseHeader,
            BatchItem,
        }

        struct ResponseMessageVisitor;

        impl<'de> Visitor<'de> for ResponseMessageVisitor {
            type Value = ResponseMessage;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("struct ResponseMessage")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut response_header: Option<ResponseMessageHeader> = None;
                let mut items = vec![];

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::ResponseHeader => {
                            if response_header.is_some() {
                                return Err(de::Error::duplicate_field("ResponseHeader"));
                            }
                            response_header = Some(map.next_value()?);
                        }
                        Field::BatchItem => {
                            // determine kmip version from the header
                            let kmip_version = match response_header
                                .as_ref()
                                .map_or(0, |header| header.protocol_version.protocol_version_major)
                            {
                                1 => KmipVersion::V14,
                                2 => KmipVersion::V21,
                                x => {
                                    return Err(de::Error::custom(format!(
                                        "unsupported protocol version: {x}"
                                    )))
                                }
                            };
                            // deserialize using the RequestMessageBatchItemVersionedDeserializer
                            let mut deserializer =
                                ResponseMessageBatchItemVersionedDeserializer { kmip_version };
                            let batch_item = map.next_value_seed(&mut deserializer)?;
                            items.push(batch_item);
                        }
                    }
                }
                let response_header =
                    response_header.ok_or_else(|| de::Error::missing_field("ResponseHeader"))?;
                Ok(ResponseMessage {
                    response_header,
                    batch_item: items,
                })
            }
        }
        const FIELDS: &[&str] = &["ResponseHeader", "BatchItem"];
        deserializer.deserialize_struct("ResponseMessage", FIELDS, ResponseMessageVisitor)
    }
}

/// The `ResponseHeader` contains protocol version information and other
/// metadata about the response.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ResponseMessageHeader {
    /// The KMIP protocol version used in this response
    pub protocol_version: ProtocolVersion,

    /// The time stamp when the response was created
    pub time_stamp: i64,

    /// The nonce provided by the server if the operation is asynchronous
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Nonce>,

    /// Server extensions that may be specified for the response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_hashed_password: Option<Vec<u8>>,

    /// REQUIRED in Attestation.
    /// Required error message if client set Attestation Capable Indicator to True in the request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_type: Option<Vec<AttestationType>>,

    /// The client's KMIP version used for sending this request (echoed back)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_correlation_value: Option<String>,

    /// The asynchronous correlation value for the request (echoed back)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_correlation_value: Option<String>,

    /// This field contains the number of Batch Items in a message and is REQUIRED.
    ///
    /// If only a single operation is being requested, then the batch count SHALL be set to 1.
    /// The Message Payload, which follows the Message Header, contains one or more batch items.
    pub batch_count: i32,
}

impl Default for ResponseMessageHeader {
    fn default() -> Self {
        Self {
            protocol_version: ProtocolVersion {
                protocol_version_major: 0,
                protocol_version_minor: 0,
            },
            time_stamp: 0,
            nonce: None,
            server_hashed_password: None,
            attestation_type: None,
            client_correlation_value: None,
            server_correlation_value: None,
            batch_count: 0,
        }
    }
}
