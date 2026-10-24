use cosmian_kms_server_database::reexport::cosmian_kmip::{
    KmipResultHelper,
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
            ResponseMessage, ResponseMessageBatchItemVersioned, ResponseMessageHeader,
        },
        kmip_types::{
            BatchErrorContinuationOption, CredentialValue, ErrorReason, MessageExtension,
            ProtocolVersion, ResultStatusEnumeration,
        },
    },
    kmip_1_4::kmip_types::OperationEnumeration as Kmip14OperationEnumeration,
    kmip_2_1::{
        extra::tagging::VENDOR_ATTR_TAG,
        kmip_messages::{
            RequestMessageBatchItem as V21RequestMessageBatchItem, ResponseMessageBatchItem,
            UNSUPPORTED_OPERATION,
        },
        kmip_operations::{Log, LogResponse, Operation, PingResponse},
        kmip_types::{OperationEnumeration, UniqueIdentifier, UniqueIdentifierEnumeration},
    },
    time_normalize,
    ttlv::{KmipFlavor, TTLV, TTLValue, TtlvDeserializer, TtlvError, to_ttlv},
};
use cosmian_logger::{error, info, trace};
use serde::{Deserialize, de::DeserializeOwned};
use strum::IntoEnumIterator;

use super::{batch_undo, modify_attribute};
use crate::{core::KMS, error::KmsError, middlewares::UserId, result::KResult};

/// Maximum number of batch items processed from one `RequestMessage`: items run
/// sequentially, so an unbounded batch would monopolise a worker and DB connections.
pub(crate) const MAX_BATCH_ITEMS: usize = 10_000;

/// Lazily formats the operations of the first batch items as a list (same output as a
/// `Vec<OperationEnumeration>` debug print, without allocating the `Vec`).
struct BatchOperations<'a>(&'a [BatchItemInput]);

impl std::fmt::Debug for BatchOperations<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(BatchItemInput::operation))
            .finish()
    }
}
/// Maps internal operation failures to the KMIP result reason and message returned to clients.
pub(crate) fn kmip_error_response_fields(error: &KmsError) -> (ErrorReason, String) {
    match error {
        KmsError::Kmip21Error(reason, error_message) => (*reason, error_message.clone()),
        KmsError::ItemNotFound(error_message) => {
            (ErrorReason::Item_Not_Found, error_message.clone())
        }
        KmsError::CryptographicError(error_message) => {
            (ErrorReason::Cryptographic_Failure, error_message.clone())
        }
        KmsError::Unauthorized(error_message) => {
            (ErrorReason::Permission_Denied, error_message.clone())
        }
        KmsError::Kmip14Error(reason, error_message) => ((*reason).into(), error_message.clone()),
        KmsError::RouteNotFound(_) => (ErrorReason::Operation_Not_Supported, error.to_string()),
        KmsError::ConversionError(_) => (ErrorReason::Codec_Error, error.to_string()),
        KmsError::InvalidRequest(_) | KmsError::InconsistentOperation(_) => {
            (ErrorReason::Invalid_Field, error.to_string())
        }
        KmsError::UnsupportedPlaceholder => (ErrorReason::Invalid_Message, error.to_string()),
        KmsError::NotSupported(_)
        | KmsError::UnsupportedAlgorithm(_)
        | KmsError::UnsupportedProtectionMasks => {
            (ErrorReason::Feature_Not_Supported, error.to_string())
        }
        _ => (ErrorReason::General_Failure, error.to_string()),
    }
}

/// KMIP 2.0 lists no Wrong Key Lifecycle State for the attribute operations (2.0 Tables 154,
/// 157, 189, 249, 298 list Permission Denied); KMIP 2.1 added it. Other versions: unchanged.
fn result_reason_for_version(
    reason: ErrorReason,
    operation: OperationEnumeration,
    version: ProtocolVersion,
) -> ErrorReason {
    let attribute_operation = matches!(
        operation,
        OperationEnumeration::AddAttribute
            | OperationEnumeration::AdjustAttribute
            | OperationEnumeration::DeleteAttribute
            | OperationEnumeration::ModifyAttribute
            | OperationEnumeration::SetAttribute
    );
    if reason == ErrorReason::Wrong_Key_Lifecycle_State
        && attribute_operation
        && version.protocol_version_major == 2
        && version.protocol_version_minor == 0
    {
        ErrorReason::Permission_Denied
    } else {
        reason
    }
}

/// A request batch item, or the per-item failure that replaces an item the server cannot run.
pub(crate) enum BatchItemInput {
    /// A decoded batch item
    Item(Box<RequestMessageBatchItemVersioned>),
    /// An item whose operation the server does not implement. It is answered with
    /// `Operation Not Supported` while the other items run (KMIP 2.1 §11.42).
    Unsupported {
        operation: OperationEnumeration,
        unique_batch_item_id: Option<Vec<u8>>,
        message_extension: Option<Vec<MessageExtension>>,
        flavor: KmipFlavor,
        message: String,
    },
}

impl BatchItemInput {
    fn operation(&self) -> OperationEnumeration {
        match self {
            Self::Item(item) => match &**item {
                RequestMessageBatchItemVersioned::V14(item) => item.operation.into(),
                RequestMessageBatchItemVersioned::V21(item) => item.operation,
            },
            Self::Unsupported { operation, .. } => *operation,
        }
    }

    fn unique_batch_item_id(&self) -> Option<&Vec<u8>> {
        match self {
            Self::Item(item) => match &**item {
                RequestMessageBatchItemVersioned::V14(item) => item.unique_batch_item_id.as_ref(),
                RequestMessageBatchItemVersioned::V21(item) => item.unique_batch_item_id.as_ref(),
            },
            Self::Unsupported {
                unique_batch_item_id,
                ..
            } => unique_batch_item_id.as_ref(),
        }
    }

    fn message_extension(&self) -> Option<&Vec<MessageExtension>> {
        match self {
            Self::Item(item) => match &**item {
                RequestMessageBatchItemVersioned::V14(item) => item.message_extension.as_ref(),
                RequestMessageBatchItemVersioned::V21(item) => item.message_extension.as_ref(),
            },
            Self::Unsupported {
                message_extension, ..
            } => message_extension.as_ref(),
        }
    }

    fn flavor(&self) -> KmipFlavor {
        match self {
            Self::Item(item) => match &**item {
                RequestMessageBatchItemVersioned::V14(_) => KmipFlavor::Kmip1,
                RequestMessageBatchItemVersioned::V21(_) => KmipFlavor::Kmip2,
            },
            Self::Unsupported { flavor, .. } => *flavor,
        }
    }
}

/// A Request Message whose batch items were decoded one by one.
pub(crate) struct DecodedRequestMessage {
    pub(crate) request_header: RequestMessageHeader,
    pub(crate) batch_item: Vec<BatchItemInput>,
}

impl From<RequestMessage> for DecodedRequestMessage {
    fn from(request: RequestMessage) -> Self {
        Self {
            request_header: request.request_header,
            batch_item: request
                .batch_item
                .into_iter()
                .map(|item| BatchItemInput::Item(Box::new(item)))
                .collect(),
        }
    }
}

/// The fields of a batch item that a response echoes, decoded without its payload.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BatchItemHead<O> {
    operation: O,
    #[serde(rename = "UniqueBatchItemID")]
    unique_batch_item_id: Option<Vec<u8>>,
    message_extension: Option<Vec<MessageExtension>>,
}

fn decode<T: DeserializeOwned>(ttlv: &TTLV) -> Result<T, TtlvError> {
    T::deserialize(&mut TtlvDeserializer::from_ttlv(ttlv))
}

/// Decodes a Request Message TTLV item by item, so that an item whose operation the server
/// does not implement fails alone with `Operation Not Supported` instead of failing the
/// whole message. Any other decoding error fails the message.
pub(crate) fn decode_request_message(ttlv: &TTLV) -> Result<DecodedRequestMessage, TtlvError> {
    let TTLValue::Structure(children) = &ttlv.value else {
        return Err(TtlvError::from("a Request Message must be a Structure"));
    };
    if ttlv.tag != "RequestMessage" {
        return Err(TtlvError::from(format!(
            "expected a RequestMessage, got {}",
            ttlv.tag
        )));
    }
    let mut children = children.iter();
    let request_header: RequestMessageHeader = match children.next() {
        Some(header) if header.tag == "RequestHeader" => decode(header)?,
        _ => {
            return Err(TtlvError::from(
                "the Request Header must be the first field of a Request Message",
            ));
        }
    };
    let major = request_header.protocol_version.protocol_version_major;
    let batch_item = children
        .map(|item| {
            if item.tag != "BatchItem" {
                return Err(TtlvError::from(format!(
                    "unexpected field in a Request Message: {}",
                    item.tag
                )));
            }
            let decoded = match major {
                1 => decode(item).map(RequestMessageBatchItemVersioned::V14),
                2 => decode(item).map(RequestMessageBatchItemVersioned::V21),
                x => {
                    return Err(TtlvError::from(format!(
                        "unsupported protocol version: {x}"
                    )));
                }
            };
            match decoded {
                Ok(item) => Ok(BatchItemInput::Item(Box::new(item))),
                Err(error) if error.to_string().contains(UNSUPPORTED_OPERATION) => {
                    let (operation, unique_batch_item_id, message_extension, flavor) = if major == 1
                    {
                        let head: BatchItemHead<Kmip14OperationEnumeration> = decode(item)?;
                        (
                            head.operation.into(),
                            head.unique_batch_item_id,
                            head.message_extension,
                            KmipFlavor::Kmip1,
                        )
                    } else {
                        let head: BatchItemHead<OperationEnumeration> = decode(item)?;
                        (
                            head.operation,
                            head.unique_batch_item_id,
                            head.message_extension,
                            KmipFlavor::Kmip2,
                        )
                    };
                    Ok(BatchItemInput::Unsupported {
                        operation,
                        unique_batch_item_id,
                        message_extension,
                        flavor,
                        message: format!("Operation not supported by this server: {operation}"),
                    })
                }
                Err(error) => Err(error),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DecodedRequestMessage {
        request_header,
        batch_item,
    })
}

fn critical_extension_vendor(request: &DecodedRequestMessage) -> Option<&str> {
    request.batch_item.iter().find_map(|batch_item| {
        batch_item
            .message_extension()
            .and_then(|extensions| {
                extensions
                    .iter()
                    .find(|extension| extension.criticality_indicator)
            })
            .map(|extension| extension.vendor_identification.as_str())
    })
}

/// Builds a failed response item, converted to the item's protocol flavor.
fn failed_item(
    operation: OperationEnumeration,
    unique_batch_item_id: Option<Vec<u8>>,
    flavor: KmipFlavor,
    reason: ErrorReason,
    message: String,
) -> KResult<ResponseMessageBatchItemVersioned> {
    to_versioned(
        ResponseMessageBatchItem {
            operation: Some(operation),
            unique_batch_item_id,
            result_status: ResultStatusEnumeration::OperationFailed,
            result_reason: Some(reason),
            result_message: Some(message),
            asynchronous_correlation_value: None,
            response_payload: None,
            message_extension: None,
        },
        flavor,
    )
}

fn to_versioned(
    item: ResponseMessageBatchItem,
    flavor: KmipFlavor,
) -> KResult<ResponseMessageBatchItemVersioned> {
    Ok(match flavor {
        KmipFlavor::Kmip1 => ResponseMessageBatchItemVersioned::V14(
            item.try_into().context("conversion to KMIP 1 failed")?,
        ),
        KmipFlavor::Kmip2 => ResponseMessageBatchItemVersioned::V21(item),
    })
}

fn response_header(request_header: &RequestMessageHeader) -> KResult<ResponseMessageHeader> {
    Ok(ResponseMessageHeader {
        protocol_version: request_header.protocol_version,
        batch_count: 0,
        client_correlation_value: request_header.client_correlation_value.clone(),
        server_correlation_value: None,
        attestation_type: None,
        time_stamp: time_normalize()?,
        nonce: None,
        server_hashed_password: None,
    })
}

fn reject_critical_extensions(request: &DecodedRequestMessage) -> KResult<Option<ResponseMessage>> {
    let Some(vendor_identification) = critical_extension_vendor(request) else {
        return Ok(None);
    };
    let result_message = format!(
        "critical message extension from vendor '{vendor_identification}' is not supported"
    );
    let response_items = request
        .batch_item
        .iter()
        .map(|batch_item| {
            failed_item(
                batch_item.operation(),
                batch_item.unique_batch_item_id().cloned(),
                batch_item.flavor(),
                ErrorReason::Unknown_Message_Extension,
                result_message.clone(),
            )
        })
        .collect::<KResult<Vec<_>>>()?;
    let mut response_header = response_header(&request.request_header)?;
    response_header.batch_count = i32::try_from(response_items.len())?;
    Ok(Some(ResponseMessage {
        response_header,
        batch_item: response_items,
    }))
}

/// The server cannot verify a Hashed Password credential: it holds no client password, so it
/// can neither check the credential nor compute the Server Hashed Password that KMIP 2.1
/// Table 398 requires in the response. Such messages are rejected.
fn reject_hashed_password(request_header: &RequestMessageHeader) -> KResult<()> {
    let hashed_password = request_header
        .authentication
        .as_ref()
        .is_some_and(|authentication| {
            authentication.credential.iter().any(|credential| {
                matches!(
                    credential.credential_value,
                    CredentialValue::HashedPassword { .. }
                )
            })
        });
    if hashed_password {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Feature_Not_Supported,
            "Hashed Password credentials are not supported: the server cannot compute the \
             Server Hashed Password"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Size in bytes of the TTLV encoding of a response header (with the 8-byte Response Message
/// envelope) or of a response batch item, as sent in `flavor`.
fn encoded_size(
    header: Option<&ResponseMessageHeader>,
    item: Option<&ResponseMessageBatchItemVersioned>,
    flavor: KmipFlavor,
) -> Option<usize> {
    #[derive(serde::Serialize)]
    #[serde(rename = "ResponseMessage")]
    struct Envelope<'a> {
        #[serde(rename = "ResponseHeader", skip_serializing_if = "Option::is_none")]
        header: Option<&'a ResponseMessageHeader>,
        #[serde(rename = "BatchItem", skip_serializing_if = "Option::is_none")]
        item: Option<&'a ResponseMessageBatchItemVersioned>,
    }
    let bytes = to_ttlv(&Envelope { header, item })
        .ok()?
        .to_bytes(flavor)
        .ok()?;
    Some(if item.is_some() {
        bytes.len().saturating_sub(8)
    } else {
        bytes.len()
    })
}

const fn status_of(item: &ResponseMessageBatchItemVersioned) -> ResultStatusEnumeration {
    match item {
        ResponseMessageBatchItemVersioned::V14(item) => item.result_status,
        ResponseMessageBatchItemVersioned::V21(item) => item.result_status,
    }
}

/// Processing of an input KMIP Message
///
/// Process every item from the message request.
/// Each batch item contains an operation to process.
///
/// The items are processed sequentially.
/// Each item may fail, but a response is still sent back.
#[cfg(test)]
pub(crate) async fn message(
    kms: &KMS,
    request: RequestMessage,
    user: &UserId,
) -> KResult<ResponseMessage> {
    Box::pin(process_message(kms, request.into(), user)).await
}

/// Processes a Request Message decoded by [`decode_request_message`].
pub(crate) async fn process_message(
    kms: &KMS,
    request: DecodedRequestMessage,
    user: &UserId,
) -> KResult<ResponseMessage> {
    info!(
        user = user.as_str(),
        "KMIP Request message with {} operation(s): {:?}",
        request.batch_item.len(),
        BatchOperations(
            request
                .batch_item
                .get(..request.batch_item.len().min(10))
                .unwrap_or(&[])
        ),
    );
    if request.batch_item.is_empty()
        || request.request_header.batch_count != i32::try_from(request.batch_item.len())?
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Message,
            "BatchCount must match the number of BatchItem values".to_owned(),
        ));
    }
    if request.batch_item.len() > MAX_BATCH_ITEMS {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Message,
            format!(
                "KMIP request message has {} batch items; the maximum is {MAX_BATCH_ITEMS}",
                request.batch_item.len()
            ),
        ));
    }
    if request.request_header.batch_error_continuation_option
        == Some(BatchErrorContinuationOption::Undo)
        && request.batch_item.len() > batch_undo::MAX_UNDO_BATCH_ITEMS
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Server_Limit_Exceeded,
            format!(
                "KMIP request message has {} batch items; with the Undo batch error \
                 continuation option the maximum is {}",
                request.batch_item.len(),
                batch_undo::MAX_UNDO_BATCH_ITEMS
            ),
        ));
    }
    reject_hashed_password(&request.request_header)?;
    super::login::redeem_ticket_credentials(kms, &request.request_header, user)?;
    if let Some(response) = reject_critical_extensions(&request)? {
        return Ok(response);
    }
    // The Unique Batch Item ID is REQUIRED from clients when Batch Count > 1 (KMIP 2.1
    // Table 396); the server tolerates its absence and echoes it when present.

    let DecodedRequestMessage {
        request_header,
        batch_item: request_items,
    } = request;
    let mut response_header = response_header(&request_header)?;
    let message_flavor = if request_header.protocol_version.protocol_version_major == 1 {
        KmipFlavor::Kmip1
    } else {
        KmipFlavor::Kmip2
    };
    let maximum_response_size = request_header
        .maximum_response_size
        .map(usize::try_from)
        .transpose()
        .map_err(|_error| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Field,
                "MaximumResponseSize must be non-negative".to_owned(),
            )
        })?;
    // Maximum Response Size bounds the whole encoded response (KMIP 2.1 §9.12)
    let mut response_size = match maximum_response_size {
        Some(_) => encoded_size(Some(&response_header), None, message_flavor).unwrap_or(0),
        None => 0,
    };
    let batch_error_mode = request_header
        .batch_error_continuation_option
        .unwrap_or(BatchErrorContinuationOption::Stop);
    let undo_mode = batch_error_mode == BatchErrorContinuationOption::Undo;
    let mut undo_triggered = false;
    let mut undo_records = Vec::new();
    let mut undo_snapshot_budget = batch_undo::MAX_UNDO_SNAPSHOTS;

    let mut response_items = Vec::with_capacity(request_items.len());
    // The ID Placeholder lasts for this RequestMessage only. Operations that create or
    // select one object update it; a following operation may omit its Unique Identifier.
    let mut id_placeholder: Option<UniqueIdentifier> = None;

    for input in request_items {
        let item_index = response_items.len();
        let kmip_version = input.flavor();
        let batch_item = match input {
            BatchItemInput::Item(item) => match *item {
                RequestMessageBatchItemVersioned::V21(item) => Ok(item),
                RequestMessageBatchItemVersioned::V14(item) => {
                    let operation = item.operation.into();
                    let unique_batch_item_id = item.unique_batch_item_id.clone();
                    V21RequestMessageBatchItem::try_from(item)
                        .map_err(|e| (operation, unique_batch_item_id, KmsError::from(e)))
                }
            },
            BatchItemInput::Unsupported {
                operation,
                unique_batch_item_id,
                message,
                ..
            } => Err((
                operation,
                unique_batch_item_id,
                KmsError::Kmip21Error(ErrorReason::Operation_Not_Supported, message),
            )),
        };

        let (
            operation,
            unique_batch_item_id,
            response_operation,
            get_attrs_explicit_refs,
            pre_state,
        ) = match batch_item {
            Ok(batch_item) => {
                let ephemeral = batch_item.ephemeral == Some(true);
                let mut request_operation = batch_item.request_payload;

                // 1) Resolve ID placeholder across operations in the batch
                resolve_id_placeholder_for_operation(&mut request_operation, &id_placeholder);

                // Capture whether this batch item explicitly requested attributes (used for KMIP 1.x shaping)
                let get_attrs_explicit_refs = get_attrs_has_explicit_refs(&request_operation);

                // 2) Expand KMIP 2.1 GetAttributes with empty AttributeReference into the full explicit list
                expand_kmip2_get_attributes_request(&mut request_operation, kmip_version);

                // 3) With Undo, snapshot what the operation may change before running it
                let pre_state = if undo_mode {
                    Some(
                        batch_undo::capture(
                            kms,
                            user,
                            &request_operation,
                            &mut undo_snapshot_budget,
                        )
                        .await,
                    )
                } else {
                    None
                };

                let mut response_operation = Box::pin(process_operation(
                    kms,
                    user,
                    request_operation,
                    Some(request_header.protocol_version),
                ))
                .await;

                if ephemeral {
                    if let Ok(payload) = &mut response_operation {
                        clear_ephemeral_response(payload);
                    }
                }
                (
                    batch_item.operation,
                    batch_item.unique_batch_item_id,
                    response_operation,
                    get_attrs_explicit_refs,
                    pre_state,
                )
            }
            Err((operation, unique_batch_item_id, error)) => {
                (operation, unique_batch_item_id, Err(error), false, None)
            }
        };

        if let Err(error) = &response_operation {
            error!(target: "kmip", "Operation processing failed: {error}");
        }

        let (result_status, result_reason, result_message, response_payload) =
            match response_operation {
                Ok(payload) => (ResultStatusEnumeration::Success, None, None, Some(payload)),
                Err(error) => {
                    let (reason, message) = kmip_error_response_fields(&error);
                    let reason = result_reason_for_version(
                        reason,
                        operation,
                        request_header.protocol_version,
                    );
                    (
                        ResultStatusEnumeration::OperationFailed,
                        Some(reason),
                        Some(message),
                        None,
                    )
                }
            };

        let mut response_message_batch_item = ResponseMessageBatchItem {
            operation: Some(operation),
            unique_batch_item_id: unique_batch_item_id.clone(),
            result_status,
            result_reason,
            result_message,
            asynchronous_correlation_value: None,
            response_payload,
            message_extension: None,
        };

        // KMIP 1.x specific response shaping for GetAttributes defaults:
        // - Remove AlwaysSensitive, Extractable, Sensitive, NeverExtractable,
        //   ShortUniqueIdentifier, KeyFormatType from default responses (when client did not explicitly request them)
        // - Filter vendor attributes to only include vendor_identification == "x" and remove internal Cosmian tag
        // 4) Apply KMIP 1.x response shaping for GetAttributes
        shape_kmip1_get_attributes_response(
            kmip_version,
            &mut response_message_batch_item,
            get_attrs_explicit_refs,
            kms.vendor_id(),
        );

        // An executed operation is reverted on Undo even if its response is then replaced
        if let Some(pre_state) = pre_state {
            if result_status == ResultStatusEnumeration::Success {
                if let Some(record) = batch_undo::record(
                    kms,
                    item_index,
                    pre_state,
                    response_message_batch_item.response_payload.as_ref(),
                )
                .await
                {
                    undo_records.push(record);
                }
            }
        }
        let mut next_placeholder = id_placeholder.clone();
        update_id_placeholder_from_response(&mut next_placeholder, &response_message_batch_item);

        let mut response_item = to_versioned(response_message_batch_item, kmip_version)?;

        if let Some(maximum_response_size) = maximum_response_size {
            let mut item_size = encoded_size(None, Some(&response_item), kmip_version).unwrap_or(0);
            if response_size.saturating_add(item_size) > maximum_response_size
                && status_of(&response_item) == ResultStatusEnumeration::Success
            {
                response_item = failed_item(
                    operation,
                    unique_batch_item_id,
                    kmip_version,
                    ErrorReason::Response_Too_Large,
                    "TOO_LARGE".to_owned(),
                )?;
                item_size = encoded_size(None, Some(&response_item), kmip_version).unwrap_or(0);
            }
            response_size = response_size.saturating_add(item_size);
        }

        let failed = status_of(&response_item) == ResultStatusEnumeration::OperationFailed;
        if !failed {
            id_placeholder = next_placeholder;
        } else if operation == OperationEnumeration::Check {
            // A failed Check empties the ID Placeholder (KMIP 2.1 §6.1.7)
            id_placeholder = None;
        }
        response_items.push(response_item);

        if failed {
            undo_triggered = undo_mode;
            // Stop and Undo neither process nor return the following items (KMIP 2.1 Table 434)
            if batch_error_mode != BatchErrorContinuationOption::Continue {
                break;
            }
        }
    }

    if undo_triggered {
        for record in undo_records.iter().rev() {
            if batch_undo::revert(kms, user, record).await {
                if let Some(item) = response_items.get_mut(record.item_index) {
                    mark_undone(item);
                }
            }
        }
    }

    response_header.batch_count = i32::try_from(response_items.len())?;
    Ok(ResponseMessage {
        response_header,
        batch_item: response_items,
    })
}

#[cfg(feature = "interop")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the feature-disabled implementation returns Operation_Not_Supported"
)]
pub(super) const fn process_interop_operation() -> KResult<Operation> {
    Ok(Operation::InteropResponse(
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::InteropResponse,
    ))
}

#[cfg(not(feature = "interop"))]
pub(super) fn process_interop_operation() -> KResult<Operation> {
    Err(KmsError::Kmip21Error(
        ErrorReason::Operation_Not_Supported,
        "Interop is disabled".to_owned(),
    ))
}

/// Executes the Log operation (KMIP 2.1 §6.1.29): writes the client message to the server log.
/// The message is `{:?}`-formatted so control characters cannot forge log lines.
pub(super) fn process_log_operation(request: Log, user: &UserId) -> KResult<Operation> {
    let message = request.log_message.ok_or_else(|| {
        KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            "Log: the Log Message is required".to_owned(),
        )
    })?;
    info!("KMIP Log operation from user {user:?}: {message:?}");
    Ok(Operation::LogResponse(LogResponse { log_message: None }))
}

async fn process_operation(
    kms: &KMS,
    user: &UserId,

    request_operation: Operation,
    protocol_version: Option<ProtocolVersion>,
) -> Result<Operation, KmsError> {
    // The KMIP operation enumeration drives both the role check and the metrics label
    let operation = request_operation.operation_enum();
    let operation_name: &'static str = operation.into();
    trace!("Processing KMIP operation: {operation_name} with user: {user:?}");

    // Only capture start time when metrics are enabled to avoid unconditional syscall overhead.
    let start_time = kms.metrics.as_ref().map(|_| std::time::Instant::now());

    // Enforce role-based access control for the RequestMessage path.
    // This mirrors the check in dispatch_inner() for the single-operation TTLV path.
    super::dispatch::check_role_permission(kms, user, operation, &kms.params.crypto_officer)
        .await?;
    // Request-time algorithm policy, as on the single-operation TTLV path.
    super::algorithm_policy::enforce_kmip_algorithm_policy_for_request(
        &kms.params,
        &request_operation,
    )?;

    // Process the operation and capture the result
    let result: Result<Operation, KmsError> = Box::pin(async {
        Ok(match request_operation {
        // New operations currently unsupported server-side: return explicit not supported errors
        Operation::PKCS11Response(_) // response variants unsupported as requests
        | Operation::CheckResponse(_)
        | Operation::InteropResponse(_)
        | Operation::LogResponse(_)
        | Operation::RNGRetrieveResponse(_)
        | Operation::RNGSeedResponse(_)
        | Operation::GetAttributeListResponse(_)
        | Operation::LoginResponse(_)
        | Operation::LogoutResponse(_)
        | Operation::SetConstraintsResponse(_)
        | Operation::PingResponse(_)
        | Operation::GetConstraintsResponse(_) => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Operation_Not_Supported,
                "Operation not supported by server".to_owned(),
            ));
        }
        Operation::RNGRetrieve(kmip_request) => {
            let resp = kms
                .rng_retrieve(kmip_request, user, )
                .await?;
            Operation::RNGRetrieveResponse(resp)
        }
        Operation::RNGSeed(kmip_request) => {
            // Delegate to KMS method for consistent policy enforcement
            let resp = kms
                .rng_seed(kmip_request, user)
                .await?;
            Operation::RNGSeedResponse(resp)
        }
        Operation::PKCS11(pkcs_req) => {
            let resp = kms.pkcs11(pkcs_req, user).await?;
            Operation::PKCS11Response(resp)
        }
        Operation::Interop(_) => process_interop_operation()?,
        Operation::Log(kmip_request) => process_log_operation(kmip_request, user)?,
        Operation::Login(kmip_request) => {
            Operation::LoginResponse(super::login::login(kms, &kmip_request, user)?)
        }
        Operation::Logout(kmip_request) => {
            Operation::LogoutResponse(super::login::logout(kms, &kmip_request, user)?)
        }
        Operation::SetConstraints(kmip_request) => Operation::SetConstraintsResponse(
            super::constraints::set_constraints(kms, kmip_request, user)?,
        ),
        Operation::Ping(_) => Operation::PingResponse(PingResponse),
        Operation::GetConstraints(_) => {
            Operation::GetConstraintsResponse(super::constraints::get_constraints(kms))
        }
        Operation::GetAttributeList(kmip_request) => Operation::GetAttributeListResponse(
            crate::core::operations::attributes::get_attribute_list_with_protocol_version(
                kms,
                kmip_request,
                user,
                protocol_version,
            )
            .await?,
        ),
            Operation::Activate(activate) => {
                Operation::ActivateResponse(kms.activate(activate, user).await?)
            }
            Operation::AddAttribute(add_attribute) => Operation::AddAttributeResponse(
                kms.add_attribute(add_attribute, user).await?,
            ),
        Operation::ModifyAttribute(kmip_request) => {
            let echoed_attribute = Some(kmip_request.new_attribute.clone());
            let mut resp = modify_attribute(kms, kmip_request, user).await?;
            resp.echoed_attribute = echoed_attribute;
            Operation::ModifyAttributeResponse(resp)
        }
        Operation::Check(kmip_request) => {
            use crate::core::operations::check;
            Operation::CheckResponse(check(kms, kmip_request, user).await?)
        }
            Operation::Certify(kmip_request) => Operation::CertifyResponse(
                kms.certify(*kmip_request, user)
                    .await?,
            ),
            Operation::Create(kmip_request) => Operation::CreateResponse(
                kms.create(kmip_request, user)
                    .await?,
            ),
            Operation::CreateKeyPair(kmip_request) => Operation::CreateKeyPairResponse(
                kms.create_key_pair(*kmip_request, user)
                    .await?,
            ),
            Operation::Decrypt(kmip_request) => {
                Operation::DecryptResponse(
                    crate::core::operations::decrypt(kms, *kmip_request, user).await?,
                )
            }
            Operation::DeleteAttribute(kmip_request) => Operation::DeleteAttributeResponse(
                kms.delete_attribute(kmip_request, user).await?,
            ),
            Operation::DeriveKey(kmip_request) => Operation::DeriveKeyResponse(
                Box::pin(kms.derive_key(kmip_request, user)).await?,
            ),
            Operation::Destroy(kmip_request) => {
                Operation::DestroyResponse(kms.destroy(kmip_request, user).await?)
            }
            Operation::DiscoverVersions(kmip_request) => Operation::DiscoverVersionsResponse(
                kms.discover_versions(kmip_request, user).await,
            ),
            Operation::Encrypt(kmip_request) => {
                Operation::EncryptResponse(
                    Box::pin(crate::core::operations::encrypt(kms, *kmip_request, user))
                        .await?,
                )
            }
            Operation::Export(kmip_request) => {
                Operation::ExportResponse(Box::new(kms.export(kmip_request, user).await?))
            }
            Operation::Get(kmip_request) => {
                Operation::GetResponse(kms.get(kmip_request, user).await?)
            }
            Operation::GetAttributes(kmip_request) => Operation::GetAttributesResponse(Box::new(
                kms.get_attributes(kmip_request, user).await?,
            )),
            Operation::Hash(kmip_request) => {
                Operation::HashResponse(kms.hash(kmip_request, user).await?)
            }
            Operation::Import(kmip_request) => Operation::ImportResponse(
                kms.import(*kmip_request, user)
                    .await?,
            ),
            Operation::Locate(kmip_request) => {
                Operation::LocateResponse(kms.locate(*kmip_request, user).await?)
            }
            Operation::MAC(kmip_request) => {
                Operation::MACResponse(
                    crate::core::operations::mac(kms, kmip_request, user).await?,
                )
            }
        Operation::MACVerify(kmip_request) => {
            Operation::MACVerifyResponse(
                crate::core::operations::mac_verify(kms, kmip_request, user).await?,
            )
        }
            Operation::Query(kmip_request) => {
                Operation::QueryResponse(Box::new(kms.query(kmip_request).await?))
            }
            Operation::Register(kmip_request) => Operation::RegisterResponse(
                kms.register(*kmip_request, user)
                    .await?,
            ),
            Operation::ReCertify(kmip_request) => Operation::ReCertifyResponse(
                kms.recertify(*kmip_request, user)
                    .await?,
            ),
            Operation::ReKey(kmip_request) => {
                Operation::ReKeyResponse(kms.rekey(kmip_request, user).await?)
            }
            Operation::ReKeyKeyPair(kmip_request) => Operation::ReKeyKeyPairResponse(
                kms.rekey_keypair(*kmip_request, user)
                    .await?,
            ),
            Operation::Revoke(kmip_request) => {
                Operation::RevokeResponse(kms.revoke(kmip_request, user).await?)
            }
            Operation::SetAttribute(kmip_request) => Operation::SetAttributeResponse(
                kms.set_attribute(kmip_request, user).await?,
            ),
            Operation::Sign(kmip_request) => {
                Operation::SignResponse(
                    crate::core::operations::sign(kms, kmip_request, user).await?,
                )
            }
            Operation::SignatureVerify(kmip_request) => {
                Operation::SignatureVerifyResponse(
                    crate::core::operations::signature_verify(kms, kmip_request, user).await?,
                )
            }
            Operation::Validate(kmip_request) => {
                Operation::ValidateResponse(kms.validate(kmip_request, user).await?)
            }
        Operation::ModifyAttributeResponse(r) => Operation::ModifyAttributeResponse(r),
            Operation::ActivateResponse(_)
            | Operation::AddAttributeResponse(_)
            | Operation::CertifyResponse(_)
            | Operation::CreateKeyPairResponse(_)
            | Operation::CreateResponse(_)
            | Operation::DecryptResponse(_)
            | Operation::DeleteAttributeResponse(_)
            | Operation::DeriveKeyResponse(_)
            | Operation::DestroyResponse(_)
            | Operation::DiscoverVersionsResponse(_)
            | Operation::EncryptResponse(_)
            | Operation::ExportResponse(_)
            | Operation::GetAttributesResponse(_)
            | Operation::GetResponse(_)
            | Operation::HashResponse(_)
            | Operation::ImportResponse(_)
            | Operation::LocateResponse(_)
            | Operation::MACResponse(_)
        | Operation::MACVerifyResponse(_)
            | Operation::QueryResponse(_)
            | Operation::ReCertifyResponse(_)
            | Operation::RegisterResponse(_)
            | Operation::ReKeyKeyPairResponse(_)
            | Operation::ReKeyResponse(_)
            | Operation::RevokeResponse(_)
            | Operation::SetAttributeResponse(_)
            | Operation::SignResponse(_)
            | Operation::SignatureVerifyResponse(_)
            | Operation::ValidateResponse(_)
            | Operation::CreateSplitKeyResponse(_)
            | Operation::JoinSplitKeyResponse(_) => {
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Operation_Not_Supported,
                    format!("Operation: {request_operation} not supported"),
                ));
            }
            Operation::CreateSplitKey(req) => {
                Operation::CreateSplitKeyResponse(Box::pin(kms.create_split_key(req, user)).await?)
            }
            Operation::JoinSplitKey(req) => {
                Operation::JoinSplitKeyResponse(Box::pin(kms.join_split_key(req, user)).await?)
            }
        })
    })
    .await;

    // Record metrics if enabled
    if let (Some(metrics), Some(start)) = (kms.metrics.as_ref(), start_time) {
        let duration = start.elapsed().as_secs_f64();
        metrics.record_kmip_operation(operation_name, user);
        metrics.record_kmip_operation_duration(operation_name, duration);

        // Record error if operation failed
        if result.is_err() {
            metrics.record_error(operation_name);
        }
    }

    result
}

// --- helper functions extracted from message() to improve readability and maintainability ---
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_messages::ResponseMessageBatchItem as V21ResponseMessageBatchItem, kmip_types as v21types,
};

fn resolve_id_placeholder_for_operation(
    operation: &mut Operation,
    id_placeholder: &Option<v21types::UniqueIdentifier>,
) {
    match operation {
        Operation::Activate(request) => {
            resolve_required_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::AddAttribute(request) => {
            resolve_required_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::Check(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::Certify(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::Decrypt(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::DeleteAttribute(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::Destroy(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::Encrypt(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::Export(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::Get(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::GetAttributeList(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::GetAttributes(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::MAC(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::MACVerify(request) => {
            resolve_required_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::ModifyAttribute(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::ReCertify(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::ReKey(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::ReKeyKeyPair(request) => {
            resolve_optional_id_placeholder(
                &mut request.private_key_unique_identifier,
                id_placeholder,
            );
        }
        Operation::Revoke(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::SetAttribute(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::Sign(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        Operation::SignatureVerify(request) => {
            resolve_optional_id_placeholder(&mut request.unique_identifier, id_placeholder);
        }
        _ => {}
    }
}

fn resolve_optional_id_placeholder(
    unique_identifier: &mut Option<v21types::UniqueIdentifier>,
    id_placeholder: &Option<v21types::UniqueIdentifier>,
) {
    if unique_identifier.as_ref().is_none_or(|unique_identifier| {
        matches!(
            unique_identifier,
            v21types::UniqueIdentifier::Enumeration(UniqueIdentifierEnumeration::IDPlaceholder)
        )
    }) {
        unique_identifier.clone_from(id_placeholder);
    }
}

fn resolve_required_id_placeholder(
    unique_identifier: &mut v21types::UniqueIdentifier,
    id_placeholder: &Option<v21types::UniqueIdentifier>,
) {
    if matches!(
        unique_identifier,
        v21types::UniqueIdentifier::Enumeration(UniqueIdentifierEnumeration::IDPlaceholder)
    ) {
        if let Some(id_placeholder) = id_placeholder {
            *unique_identifier = id_placeholder.clone();
        }
    }
}

/// Whether this batch item is a `GetAttributes` request that explicitly lists attribute references.
fn get_attrs_has_explicit_refs(op: &Operation) -> bool {
    matches!(op, Operation::GetAttributes(ga) if ga.attribute_reference.as_ref().is_some_and(|v| !v.is_empty()))
}

fn clear_ephemeral_response(response: &mut Operation) {
    match response {
        Operation::EncryptResponse(response) => response.data = None,
        Operation::DecryptResponse(response) => response.data = None,
        Operation::SignResponse(response) => response.signature_data = None,
        Operation::MACResponse(response) => response.mac_data = None,
        Operation::HashResponse(response) => response.data = None,
        Operation::RNGRetrieveResponse(response) => response.data.clear(),
        _ => {}
    }
}

fn expand_kmip2_get_attributes_request(op: &mut Operation, kmip_version: KmipFlavor) {
    if !matches!(kmip_version, KmipFlavor::Kmip2) {
        return;
    }
    if let Operation::GetAttributes(ga) = op {
        if ga
            .attribute_reference
            .as_ref()
            .is_none_or(std::vec::Vec::is_empty)
        {
            use v21types::{AttributeReference, Tag};
            let mut refs: Vec<AttributeReference> = Vec::new();
            for tag in Tag::iter() {
                if tag != Tag::Tag {
                    refs.push(AttributeReference::Standard(tag));
                }
            }
            ga.attribute_reference = Some(refs);
        }
    }
}

fn shape_kmip1_get_attributes_response(
    kmip_version: KmipFlavor,
    item: &mut V21ResponseMessageBatchItem,
    explicit_request: bool,
    vendor_id: &str,
) {
    if !matches!(kmip_version, KmipFlavor::Kmip1)
        || item.result_status != ResultStatusEnumeration::Success
    {
        return;
    }
    let Some(Operation::GetAttributesResponse(ref mut gar)) = item.response_payload else {
        return;
    };
    let attrs = &mut gar.attributes;

    // A KMIP 1.x `GetAttributes` carrying no attribute name returns the TL profile set.
    // Per the OASIS mandatory test vector `TL-M-3-14.xml`, that set excludes `Sensitive`,
    // `Always Sensitive`, `Extractable` and `Never Extractable` even for KMIP 1.4 — they
    // are only returned when explicitly requested (they remain advertised by
    // `GetAttributeList`, as the same vector shows). `Short Unique Identifier` has no
    // KMIP 1.x counterpart and `Key Format Type` belongs to the Key Block, not the
    // attribute list.
    //
    // Version gating of attributes that a pre-1.4 client cannot decode is applied later,
    // for both explicit and default requests, by `strip_kmip1_version_unsupported_attrs`.
    if !explicit_request {
        attrs.always_sensitive = None;
        attrs.extractable = None;
        attrs.sensitive = None;
        attrs.never_extractable = None;
        attrs.short_unique_identifier = None;
        attrs.key_format_type = None;
    }

    // The Cosmian-internal tagging vendor attribute is never part of a KMIP response.
    // All other vendor attributes (e.g. `KMIP1:__Operation Policy Name__`) are preserved.
    if let Some(vas) = attrs.vendor_attributes.as_mut() {
        vas.retain(|va| {
            !(va.vendor_identification == vendor_id && va.attribute_name == VENDOR_ATTR_TAG)
        });
        if vas.is_empty() {
            attrs.vendor_attributes = None;
        }
    }
}

fn update_id_placeholder_from_response(
    id_placeholder: &mut Option<v21types::UniqueIdentifier>,
    item: &V21ResponseMessageBatchItem,
) {
    match &item.response_payload {
        Some(Operation::CertifyResponse(response)) => {
            *id_placeholder = Some(response.unique_identifier.clone());
        }
        Some(Operation::CreateResponse(response)) => {
            *id_placeholder = Some(response.unique_identifier.clone());
        }
        Some(Operation::CreateKeyPairResponse(response)) => {
            *id_placeholder = Some(response.private_key_unique_identifier.clone());
        }
        Some(Operation::CreateSplitKeyResponse(response)) => {
            *id_placeholder = response.unique_identifier.first().cloned();
        }
        Some(Operation::DeriveKeyResponse(response)) => {
            *id_placeholder = Some(response.unique_identifier.clone());
        }
        Some(Operation::ExportResponse(response)) => {
            *id_placeholder = Some(response.unique_identifier.clone());
        }
        Some(Operation::ImportResponse(response)) => {
            *id_placeholder = Some(response.unique_identifier.clone());
        }
        Some(Operation::JoinSplitKeyResponse(response)) => {
            *id_placeholder = Some(response.unique_identifier.clone());
        }
        Some(Operation::LocateResponse(response)) => {
            *id_placeholder = match response.unique_identifier.as_deref() {
                Some([unique_identifier]) => Some(unique_identifier.clone()),
                _ => None,
            };
        }
        Some(Operation::ReCertifyResponse(response)) => {
            *id_placeholder = Some(response.unique_identifier.clone());
        }
        Some(Operation::ReKeyResponse(response)) => {
            *id_placeholder = Some(response.unique_identifier.clone());
        }
        Some(Operation::ReKeyKeyPairResponse(response)) => {
            *id_placeholder = Some(response.private_key_unique_identifier.clone());
        }
        Some(Operation::RegisterResponse(response)) => {
            *id_placeholder = Some(response.unique_identifier.clone());
        }
        _ => {}
    }
}

/// Marks a successful item as `Operation Undone` once its effects were reverted. The payload
/// is kept, as in the OASIS test case BL-M-2-21.
fn mark_undone(item: &mut ResponseMessageBatchItemVersioned) {
    match item {
        ResponseMessageBatchItemVersioned::V21(batch_item)
            if batch_item.result_status == ResultStatusEnumeration::Success =>
        {
            batch_item.result_status = ResultStatusEnumeration::OperationUndone;
        }
        ResponseMessageBatchItemVersioned::V14(batch_item)
            if batch_item.result_status == ResultStatusEnumeration::Success =>
        {
            batch_item.result_status = ResultStatusEnumeration::OperationUndone;
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kms_bail;

    #[test]
    fn marks_only_successes_undone() {
        let item = |result_status| {
            ResponseMessageBatchItemVersioned::V21(ResponseMessageBatchItem {
                operation: None,
                unique_batch_item_id: None,
                result_status,
                result_reason: None,
                result_message: None,
                asynchronous_correlation_value: None,
                response_payload: None,
                message_extension: None,
            })
        };
        let mut success = item(ResultStatusEnumeration::Success);
        let mut failed = item(ResultStatusEnumeration::OperationFailed);

        mark_undone(&mut success);
        mark_undone(&mut failed);

        assert_eq!(
            status_of(&success),
            ResultStatusEnumeration::OperationUndone
        );
        assert_eq!(status_of(&failed), ResultStatusEnumeration::OperationFailed);
    }

    #[test]
    fn maps_transport_visible_errors_to_exact_reasons() {
        assert_eq!(
            kmip_error_response_fields(&KmsError::RouteNotFound("unknown".to_owned())).0,
            ErrorReason::Operation_Not_Supported
        );
        assert_eq!(
            kmip_error_response_fields(&KmsError::ConversionError("invalid TTLV".to_owned())).0,
            ErrorReason::Codec_Error
        );
        assert_eq!(
            kmip_error_response_fields(&KmsError::ServerError("serialization failed".to_owned())).0,
            ErrorReason::General_Failure
        );
        assert_eq!(
            kmip_error_response_fields(&KmsError::Kmip21Error(
                ErrorReason::Unknown_Message_Extension,
                "unknown critical extension".to_owned(),
            ))
            .0,
            ErrorReason::Unknown_Message_Extension
        );
        assert_eq!(
            kmip_error_response_fields(&KmsError::UnsupportedPlaceholder).0,
            ErrorReason::Invalid_Message
        );
    }

    #[test]
    fn kmip_2_0_attribute_operations_report_permission_denied() {
        let version = |minor| ProtocolVersion {
            protocol_version_major: 2,
            protocol_version_minor: minor,
        };
        let wkls = ErrorReason::Wrong_Key_Lifecycle_State;
        assert_eq!(
            result_reason_for_version(wkls, OperationEnumeration::ModifyAttribute, version(0)),
            ErrorReason::Permission_Denied
        );
        assert_eq!(
            result_reason_for_version(wkls, OperationEnumeration::ModifyAttribute, version(1)),
            wkls
        );
        // KMIP 2.0 Destroy Errors list Wrong Key Lifecycle State
        assert_eq!(
            result_reason_for_version(wkls, OperationEnumeration::Destroy, version(0)),
            wkls
        );
    }

    #[cfg(not(feature = "interop"))]
    #[test]
    fn interop_is_explicitly_unsupported_without_feature() {
        assert!(matches!(
            process_interop_operation(),
            Err(KmsError::Kmip21Error(
                ErrorReason::Operation_Not_Supported,
                message
            )) if message == "Interop is disabled"
        ));
    }

    #[test]
    fn join_split_key_response_updates_placeholder() {
        let joined = UniqueIdentifier::TextString("joined-key".to_owned());
        let item = ResponseMessageBatchItem {
            operation: None,
            unique_batch_item_id: None,
            result_status: ResultStatusEnumeration::Success,
            result_reason: None,
            result_message: None,
            asynchronous_correlation_value: None,
            response_payload: Some(Operation::JoinSplitKeyResponse(
                cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::JoinSplitKeyResponse {
                    unique_identifier: joined.clone(),
                },
            )),
            message_extension: None,
        };
        let mut placeholder = None;

        update_id_placeholder_from_response(&mut placeholder, &item);

        assert_eq!(placeholder, Some(joined));
    }

    /// The header size plus the item sizes equal the size of the encoded Response Message,
    /// so Maximum Response Size bounds the bytes actually sent, in both protocol flavors.
    #[test]
    fn response_size_counts_the_whole_response() -> KResult<()> {
        for (flavor, major, minor) in [(KmipFlavor::Kmip1, 1, 4), (KmipFlavor::Kmip2, 2, 1)] {
            let item = to_versioned(
                ResponseMessageBatchItem {
                    operation: Some(OperationEnumeration::RNGRetrieve),
                    unique_batch_item_id: Some(vec![1, 2, 3]),
                    result_status: ResultStatusEnumeration::Success,
                    result_reason: None,
                    result_message: None,
                    asynchronous_correlation_value: None,
                    response_payload: Some(Operation::RNGRetrieveResponse(
                        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::RNGRetrieveResponse {
                            data: vec![0; 32],
                        },
                    )),
                    message_extension: None,
                },
                flavor,
            )?;
            let mut header = response_header(&RequestMessageHeader {
                protocol_version: ProtocolVersion {
                    protocol_version_major: major,
                    protocol_version_minor: minor,
                },
                batch_count: 1,
                ..Default::default()
            })?;
            header.batch_count = 1;
            let header_size = encoded_size(Some(&header), None, flavor);
            let item_size = encoded_size(None, Some(&item), flavor);
            let message = to_ttlv(&ResponseMessage {
                response_header: header,
                batch_item: vec![item],
            })?
            .to_bytes(flavor)?;
            let expected = header_size.zip(item_size).map(|(h, i)| h + i);
            if expected != Some(message.len()) {
                kms_bail!(
                    "{flavor:?}: header + item sizes {expected:?} != message size {}",
                    message.len()
                );
            }
        }
        Ok(())
    }

    /// An operation the server does not implement fails its own item; the next item decodes.
    #[test]
    fn unsupported_operation_fails_its_item_only() -> KResult<()> {
        let ttlv = |operation: &str| {
            TTLV {
            tag: "BatchItem".into(),
            value: TTLValue::Structure(vec![
                TTLV {
                    tag: "Operation".into(),
                    value: TTLValue::Enumeration(
                        cosmian_kms_server_database::reexport::cosmian_kmip::ttlv::KmipEnumerationVariant {
                            value: 0,
                            name: operation.to_owned().into(),
                        },
                    ),
                },
                TTLV {
                    tag: "UniqueBatchItemID".into(),
                    value: TTLValue::ByteString(vec![7]),
                },
                TTLV {
                    tag: "RequestPayload".into(),
                    value: TTLValue::Structure(vec![]),
                },
            ]),
        }
        };
        let mut header = to_ttlv(&RequestMessageHeader {
            batch_count: 2,
            ..Default::default()
        })?;
        header.tag = "RequestHeader".into();
        let request = TTLV {
            tag: "RequestMessage".into(),
            value: TTLValue::Structure(vec![header, ttlv("Poll"), ttlv("Query")]),
        };
        let decoded = decode_request_message(&request)?;
        let [
            BatchItemInput::Unsupported {
                operation: OperationEnumeration::Poll,
                unique_batch_item_id: Some(id),
                ..
            },
            BatchItemInput::Item(item),
        ] = decoded.batch_item.as_slice()
        else {
            kms_bail!("unexpected decoded batch items");
        };
        if id != &vec![7] || !matches!(**item, RequestMessageBatchItemVersioned::V21(_)) {
            kms_bail!("unexpected decoded batch items");
        }
        Ok(())
    }
}
