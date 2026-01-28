use cosmian_kms_server_database::reexport::cosmian_kmip::{
    KmipResultHelper,
    kmip_0::{
        kmip_messages::{
            RequestMessage, RequestMessageBatchItemVersioned, ResponseMessage,
            ResponseMessageBatchItemVersioned, ResponseMessageHeader,
        },
        kmip_types::{
            BatchErrorContinuationOption, ErrorReason, ProtocolVersion, ResultStatusEnumeration,
            State,
        },
    },
    kmip_2_1::{
        extra::{VENDOR_ID_COSMIAN, tagging::VENDOR_ATTR_TAG},
        kmip_messages::ResponseMessageBatchItem,
        kmip_operations::{InteropResponse, LogResponse, Operation},
        kmip_types::{OperationEnumeration, UniqueIdentifier, UniqueIdentifierEnumeration},
    },
    time_normalize,
    ttlv::KmipFlavor,
};
use cosmian_logger::{info, trace};
use strum::IntoEnumIterator;

use super::modify_attribute;
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
) -> KResult<ResponseMessage> {
    info!(
        user = user,
        "KMIP Request message with {} operation(s): {:?}",
        request.batch_item.len(),
        request
            .batch_item
            .get(..request.batch_item.len().min(10))
            .unwrap_or(&[])
            .iter()
            .map(|bi| match bi {
                RequestMessageBatchItemVersioned::V14(item) => item.operation.into(),
                RequestMessageBatchItemVersioned::V21(item) => item.operation,
            })
            .collect::<Vec<OperationEnumeration>>(),
    );
    trace!("Entering message KMIP operation: {request}");

    let mut response_items = Vec::new();
    // Track the KMIP ID Placeholder within this RequestMessage. Multiple operations set
    // or clear it (e.g., Create, Register, CreateKeyPair, DeriveKey, Export set it; Locate
    // sets it iff exactly one UID is returned, otherwise clears it). Subsequent operations
    // that omit the UniqueIdentifier, or explicitly use the placeholder (uid-0 / IDPlaceholder),
    // implicitly target this value.
    //
    // This provides minimal batch-scoped placeholder support for operations like Get
    // that don't specify a unique_identifier, allowing them to reference the most recently
    // created object within the same batch. This enables KMIP test vectors like AX-M-1-14
    // to work correctly without implementing full session-persistent placeholder support.
    let mut id_placeholder: Option<UniqueIdentifier> = None;
    // Capture maximum_response_size from request header if present; apply uniformly to all batch items.
    let remaining_max_response_size = request.request_header.maximum_response_size;
    // Capture batch error continuation option (same location in 1.4 / 2.1 header structures after normalization)
    let batch_error_mode = request.request_header.batch_error_continuation_option;
    // Stash original successful indices so we can undo them if needed
    let mut success_indices: Vec<usize> = Vec::new();
    // When in Undo mode, once a failure occurs we mark all prior successes as OperationUndone
    let mut undo_triggered: Option<(ErrorReason, String)> = None;

    // Track successful Activate responses so we can revert side-effects if UNDO is triggered
    let mut undo_activate_uids: Vec<String> = Vec::new();

    for versioned_batch_item in request.batch_item {
        let (batch_item, kmip_version) = match versioned_batch_item {
            RequestMessageBatchItemVersioned::V14(item_request) => {
                (item_request.try_into()?, KmipFlavor::Kmip1)
            }
            RequestMessageBatchItemVersioned::V21(item_request) => {
                (item_request, KmipFlavor::Kmip2)
            }
        };

        let mut request_operation = batch_item.request_payload;

        // 1) Resolve ID placeholder across operations in the batch
        resolve_id_placeholder_for_operation(&mut request_operation, &id_placeholder);

        // Capture whether this batch item explicitly requested attributes (used for KMIP 1.x shaping)
        let get_attrs_requested_refs = extract_get_attrs_requested_refs(&request_operation);

        // 2) Expand KMIP 2.1 GetAttributes with empty AttributeReference into the full explicit list
        expand_kmip2_get_attributes_request(&mut request_operation, kmip_version);

        let response_operation = Box::pin(process_operation(
            kms,
            user,
            request_operation,
            Some(request.request_header.protocol_version),
        ))
        .await;
        // 3) Optionally enforce MaximumResponseSize for Query
        let forced_size_error =
            enforce_max_response_size_for_query(&response_operation, remaining_max_response_size)?;

        match response_operation {
            Ok(ref op) => trace!("Operation processed successfully: {op}"),
            Err(ref e) => trace!("Operation processing failed: {e}"),
        }

        let (result_status, result_reason, result_message, response_payload) =
            if let Some((rs, rr, msg)) = forced_size_error {
                (rs, Some(rr), Some(msg), None)
            } else {
                match response_operation {
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
                }
            };

        let mut response_message_batch_item = ResponseMessageBatchItem {
            operation: Some(batch_item.operation),
            unique_batch_item_id: batch_item.unique_batch_item_id,
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
            get_attrs_requested_refs
                .as_ref()
                .is_some_and(|v| !v.is_empty()),
        );

        // Update ID placeholder after successful operations that yield a clear target UID.
        // This enables intra-batch references where a following operation omits the
        // UniqueIdentifier and expects the server to use the latest placeholder.
        if response_message_batch_item.result_status == ResultStatusEnumeration::Success {
            update_id_placeholder_from_response(&mut id_placeholder, &response_message_batch_item);
        }

        // Record Activate successes for potential UNDO side-effect revert
        if response_message_batch_item.result_status == ResultStatusEnumeration::Success {
            if let Some(Operation::ActivateResponse(ar)) =
                &response_message_batch_item.response_payload
            {
                if let UniqueIdentifier::TextString(uid) = &ar.unique_identifier {
                    undo_activate_uids.push(uid.clone());
                }
            }
        }

        // Record successes (before potential undo handling)
        if response_message_batch_item.result_status == ResultStatusEnumeration::Success {
            success_indices.push(response_items.len());
        } else if response_message_batch_item.result_status
            == ResultStatusEnumeration::OperationFailed
        {
            // On first failure, if Undo selected, capture reason/message
            if undo_triggered.is_none()
                && matches!(batch_error_mode, Some(BatchErrorContinuationOption::Undo))
            {
                let reason = response_message_batch_item
                    .result_reason
                    .unwrap_or(ErrorReason::General_Failure);
                let msg = response_message_batch_item
                    .result_message
                    .clone()
                    .unwrap_or_else(|| "UNDONE".to_owned());
                undo_triggered = Some((reason, msg));
            }
        }

        if let Some((_reason, ref _msg)) = undo_triggered {
            // If undo is active and this item was earlier marked success, convert to OperationUndone
            if response_message_batch_item.result_status == ResultStatusEnumeration::Success {
                response_message_batch_item.result_status =
                    ResultStatusEnumeration::OperationUndone;
                // Per BL-M-2-21 expectations, keep the original payload and omit reason/message
                response_message_batch_item.result_reason = None;
                response_message_batch_item.result_message = None;
            }
        }

        let response_message_batch_item = match kmip_version {
            KmipFlavor::Kmip1 => ResponseMessageBatchItemVersioned::V14(
                response_message_batch_item
                    .try_into()
                    .context("conversion to KMIP 1 failed")?,
            ),
            KmipFlavor::Kmip2 => {
                ResponseMessageBatchItemVersioned::V21(response_message_batch_item)
            }
        };

        response_items.push(response_message_batch_item);
        // If undo triggered at or before this item, retroactively mutate all recorded successes
        if let Some((_reason, ref _msg)) = undo_triggered {
            mark_successes_undone(&mut response_items, &success_indices)?;
        }
    }

    // If UNDO mode was triggered, revert side-effects for operations that had already mutated state.
    if undo_triggered.is_some() {
        for uid in undo_activate_uids {
            Box::pin(revert_activation_to_preactive(kms, &uid, user)).await?;
        }
    }

    let response_message = ResponseMessage {
        response_header: ResponseMessageHeader {
            protocol_version: request.request_header.protocol_version,
            batch_count: i32::try_from(response_items.len())?,
            client_correlation_value: None,
            server_correlation_value: None,
            attestation_type: None,
            time_stamp: time_normalize()?,
            nonce: None,
            server_hashed_password: None,
        },
        batch_item: response_items,
    };

    trace!("Response message: {response_message}");

    Ok(response_message)
}

/// Revert an Activate operation by setting the object's state back to `PreActive` and clearing
/// the `activation_date`. This is a best-effort revert used when batch UNDO is triggered.
async fn revert_activation_to_preactive(kms: &KMS, uid: &str, user: &str) -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::KmipOperation;

    use crate::core::retrieve_object_utils::retrieve_object_for_operation;

    let mut owm = Box::pin(retrieve_object_for_operation(
        uid,
        KmipOperation::GetAttributes,
        kms,
        user,
    ))
    .await?;

    // Reset internal attributes
    if let Ok(attrs) = owm.object_mut().attributes_mut() {
        attrs.state = Some(State::PreActive);
        attrs.activation_date = None;
    }
    // Reset external attributes
    owm.attributes_mut().state = Some(State::PreActive);
    owm.attributes_mut().activation_date = None;

    kms.database
        .update_object(owm.id(), owm.object(), owm.attributes(), None)
        .await?;

    // Update the state in the database (separate column)
    kms.database
        .update_state(owm.id(), State::PreActive)
        .await?;

    Ok(())
}

/// Helper function to get the operation name from an Operation enum variant
#[allow(clippy::missing_const_for_fn)]
fn get_operation_name(operation: &Operation) -> &'static str {
    match operation {
        Operation::Activate(_) => "Activate",
        Operation::AddAttribute(_) => "AddAttribute",
        Operation::Certify(_) => "Certify",
        Operation::Create(_) => "Create",
        Operation::CreateKeyPair(_) => "CreateKeyPair",
        Operation::Decrypt(_) => "Decrypt",
        Operation::DeleteAttribute(_) => "DeleteAttribute",
        Operation::DeriveKey(_) => "DeriveKey",
        Operation::Destroy(_) => "Destroy",
        Operation::DiscoverVersions(_) => "DiscoverVersions",
        Operation::Encrypt(_) => "Encrypt",
        Operation::Export(_) => "Export",
        Operation::Get(_) => "Get",
        Operation::GetAttributes(_) => "GetAttributes",
        Operation::Hash(_) => "Hash",
        Operation::Import(_) => "Import",
        Operation::Locate(_) => "Locate",
        Operation::MAC(_) => "MAC",
        Operation::Query(_) => "Query",
        Operation::Register(_) => "Register",
        Operation::ReKey(_) => "ReKey",
        Operation::ReKeyKeyPair(_) => "ReKeyKeyPair",
        Operation::Revoke(_) => "Revoke",
        Operation::SetAttribute(_) => "SetAttribute",
        Operation::Sign(_) => "Sign",
        Operation::SignatureVerify(_) => "SignatureVerify",
        Operation::Validate(_) => "Validate",
        _ => "Unknown",
    }
}

async fn process_operation(
    kms: &KMS,
    user: &str,

    request_operation: Operation,
    protocol_version: Option<ProtocolVersion>,
) -> Result<Operation, KmsError> {
    // Get operation name for metrics
    let operation_name = get_operation_name(&request_operation);
    trace!("Processing KMIP operation: {operation_name} with user: {user:?}");

    let start_time = std::time::Instant::now();

    let privileged_users = kms.params.privileged_users.clone();

    // Process the operation and capture the result
    let result: Result<Operation, KmsError> = async {
        Ok(match request_operation {
        // New operations currently unsupported server-side: return explicit not supported errors
    Operation::PKCS11Response(_) // response variants unsupported as requests
    | Operation::CheckResponse(_)
    | Operation::LogResponse(_)
        | Operation::RNGRetrieveResponse(_)
        | Operation::RNGSeedResponse(_)
        | Operation::GetAttributeListResponse(_) => {
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
        Operation::Interop(_kmip_request) => {
            // Minimal interoperability operation implementation: always succeed with empty response
            Operation::InteropResponse(InteropResponse)
        }
        Operation::Log(kmip_request) => {
            // Minimal Log operation implementation: accept and return empty success payload.
            // KMIP BL-M-1-21 vector expects LogResponse with no LogMessage in the response.
            drop(kmip_request); // message accepted but not echoed back
            Operation::LogResponse(LogResponse { log_message: None })
        }
        Operation::InteropResponse(r) => Operation::InteropResponse(r),
        Operation::GetAttributeList(kmip_request) => Operation::GetAttributeListResponse(
            crate::core::operations::get_attribute_list::get_attribute_list_with_protocol_version(
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
        Operation::ModifyAttribute(kmip_request) => Operation::ModifyAttributeResponse(
            modify_attribute(kms, kmip_request, user).await?,
        ),
        Operation::Check(kmip_request) => {
            use crate::core::operations::check;
            Operation::CheckResponse(check(kms, kmip_request, user).await?)
        }
            Operation::Certify(kmip_request) => Operation::CertifyResponse(
                kms.certify(*kmip_request, user, privileged_users)
                    .await?,
            ),
            Operation::Create(kmip_request) => Operation::CreateResponse(
                kms.create(kmip_request, user, privileged_users)
                    .await?,
            ),
            Operation::CreateKeyPair(kmip_request) => Operation::CreateKeyPairResponse(
                kms.create_key_pair(*kmip_request, user, privileged_users)
                    .await?,
            ),
            Operation::Decrypt(kmip_request) => {
                Operation::DecryptResponse(kms.decrypt(*kmip_request, user).await?)
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
                Operation::EncryptResponse(kms.encrypt(*kmip_request, user).await?)
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
                kms.import(*kmip_request, user, privileged_users)
                    .await?,
            ),
            Operation::Locate(kmip_request) => {
                Operation::LocateResponse(kms.locate(*kmip_request, user).await?)
            }
            Operation::MAC(kmip_request) => {
                Operation::MACResponse(kms.mac(kmip_request, user).await?)
            }
        Operation::MACVerify(kmip_request) => Operation::MACVerifyResponse(
            crate::core::operations::mac::mac_verify(kms, kmip_request, user).await?,
        ),
            Operation::Query(kmip_request) => {
                Operation::QueryResponse(Box::new(kms.query(kmip_request).await?))
            }
            Operation::Register(kmip_request) => Operation::RegisterResponse(
                kms.register(*kmip_request, user, privileged_users)
                    .await?,
            ),
            Operation::ReKey(kmip_request) => {
                Operation::ReKeyResponse(kms.rekey(kmip_request, user).await?)
            }
            Operation::ReKeyKeyPair(kmip_request) => Operation::ReKeyKeyPairResponse(
                kms.rekey_keypair(*kmip_request, user, privileged_users)
                    .await?,
            ),
            Operation::Revoke(kmip_request) => {
                Operation::RevokeResponse(kms.revoke(kmip_request, user).await?)
            }
            Operation::SetAttribute(kmip_request) => Operation::SetAttributeResponse(
                kms.set_attribute(kmip_request, user).await?,
            ),
            Operation::Sign(kmip_request) => {
                Operation::SignResponse(kms.sign(kmip_request, user).await?)
            }
            Operation::SignatureVerify(kmip_request) => Operation::SignatureVerifyResponse(
                kms.signature_verify(kmip_request, user).await?,
            ),
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
            | Operation::RegisterResponse(_)
            | Operation::ReKeyKeyPairResponse(_)
            | Operation::ReKeyResponse(_)
            | Operation::RevokeResponse(_)
            | Operation::SetAttributeResponse(_)
            | Operation::SignResponse(_)
            | Operation::SignatureVerifyResponse(_)
            | Operation::ValidateResponse(_) => {
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Operation_Not_Supported,
                    format!("Operation: {request_operation} not supported"),
                ));
            }
        })
    }
    .await;

    // Record metrics if enabled
    if let Some(ref metrics) = kms.metrics {
        let duration = start_time.elapsed().as_secs_f64();
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
    op: &mut Operation,
    id_placeholder: &Option<v21types::UniqueIdentifier>,
) {
    match op {
        Operation::Get(get_request) => match &get_request.unique_identifier {
            None
            | Some(v21types::UniqueIdentifier::Enumeration(
                UniqueIdentifierEnumeration::IDPlaceholder,
            )) => {
                if let Some(uid) = id_placeholder {
                    get_request.unique_identifier = Some(uid.clone());
                }
            }
            _ => {}
        },
        Operation::GetAttributes(get_attrs_request) => match &get_attrs_request.unique_identifier {
            None
            | Some(v21types::UniqueIdentifier::Enumeration(
                UniqueIdentifierEnumeration::IDPlaceholder,
            )) => {
                if let Some(uid) = id_placeholder {
                    get_attrs_request.unique_identifier = Some(uid.clone());
                }
            }
            _ => {}
        },
        Operation::GetAttributeList(gal_request) => match &gal_request.unique_identifier {
            None
            | Some(v21types::UniqueIdentifier::Enumeration(
                UniqueIdentifierEnumeration::IDPlaceholder,
            )) => {
                if let Some(uid) = id_placeholder {
                    gal_request.unique_identifier = Some(uid.clone());
                }
            }
            _ => {}
        },
        Operation::ModifyAttribute(mod_attr_request) => match &mod_attr_request.unique_identifier {
            None
            | Some(v21types::UniqueIdentifier::Enumeration(
                UniqueIdentifierEnumeration::IDPlaceholder,
            )) => {
                if let Some(uid) = id_placeholder {
                    mod_attr_request.unique_identifier = Some(uid.clone());
                }
            }
            _ => {}
        },
        _ => {}
    }
}

fn extract_get_attrs_requested_refs(op: &Operation) -> Option<Vec<v21types::AttributeReference>> {
    if let Operation::GetAttributes(ga) = op {
        return ga.attribute_reference.clone();
    }
    None
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

fn enforce_max_response_size_for_query(
    response_operation: &Result<Operation, KmsError>,
    remaining_max_response_size: Option<i32>,
) -> KResult<Option<(ResultStatusEnumeration, ErrorReason, String)>> {
    // For QueryResponse, enforce MaximumResponseSize from header if set.
    // Use serialized JSON payload length as a pragmatic proxy for response size.
    if let Ok(Operation::QueryResponse(resp)) = response_operation {
        if let Some(max_total) = remaining_max_response_size {
            if let Ok(payload_json) = serde_json::to_string(resp) {
                let payload_len = i32::try_from(payload_json.len())?;
                let approx_total = payload_len.saturating_add(128);
                if approx_total > max_total {
                    return Ok(Some((
                        ResultStatusEnumeration::OperationFailed,
                        ErrorReason::Response_Too_Large,
                        "TOO_LARGE".to_owned(),
                    )));
                }
            }
        }
    }
    Ok(None)
}

fn shape_kmip1_get_attributes_response(
    kmip_version: KmipFlavor,
    item: &mut V21ResponseMessageBatchItem,
    explicit_request: bool,
) {
    if !matches!(kmip_version, KmipFlavor::Kmip1)
        || item.result_status != ResultStatusEnumeration::Success
    {
        return;
    }
    if let Some(Operation::GetAttributesResponse(ref mut gar)) = item.response_payload {
        let attrs = &mut gar.attributes;
        if explicit_request {
            // Still remove internal Cosmian tagging attribute if present
            if let Some(vas) = attrs.vendor_attributes.as_mut() {
                vas.retain(|va| {
                    !(va.vendor_identification == VENDOR_ID_COSMIAN
                        && va.attribute_name == VENDOR_ATTR_TAG)
                });
                if vas.is_empty() {
                    attrs.vendor_attributes = None;
                }
            }
        } else {
            // Drop TL-omitted standard attributes
            attrs.always_sensitive = None;
            attrs.extractable = None;
            attrs.sensitive = None;
            attrs.never_extractable = None;
            attrs.short_unique_identifier = None;
            attrs.key_format_type = None;

            // Filter vendor attributes to those intended for TL profiles.
            if let Some(vas) = attrs.vendor_attributes.as_mut() {
                vas.retain(|va| {
                    va.vendor_identification == "x"
                        && !(va.vendor_identification == VENDOR_ID_COSMIAN
                            && va.attribute_name == VENDOR_ATTR_TAG)
                });
                if vas.is_empty() {
                    attrs.vendor_attributes = None;
                }
            }
        }
    }
}

fn update_id_placeholder_from_response(
    id_placeholder: &mut Option<v21types::UniqueIdentifier>,
    item: &V21ResponseMessageBatchItem,
) {
    match &item.response_payload {
        // Create returns a single UniqueIdentifier
        Some(Operation::CreateResponse(cr)) => {
            *id_placeholder = Some(cr.unique_identifier.clone());
        }
        // Register returns a single UniqueIdentifier
        Some(Operation::RegisterResponse(rr)) => {
            *id_placeholder = Some(rr.unique_identifier.clone());
        }
        // CreateKeyPair returns public+private UIDs; prefer the private key as placeholder
        Some(Operation::CreateKeyPairResponse(ckpr)) => {
            *id_placeholder = Some(ckpr.private_key_unique_identifier.clone());
        }
        // Locate may return a list of UIDs; per KMIP ID Placeholder semantics we only
        // set the placeholder when exactly one UID is located. Otherwise, clear it.
        Some(Operation::LocateResponse(lr)) => {
            if let Some(list) = &lr.unique_identifier {
                if let Some(first) = list.first() {
                    *id_placeholder = Some(first.clone());
                } else {
                    *id_placeholder = None;
                }
            } else {
                *id_placeholder = None;
            }
        }
        _ => {}
    }
}

fn mark_successes_undone(
    response_items: &mut [ResponseMessageBatchItemVersioned],
    success_indices: &[usize],
) -> KResult<()> {
    for &idx in success_indices {
        let item = response_items
            .get_mut(idx)
            .ok_or(KmsError::UnsupportedPlaceholder)?;
        if let ResponseMessageBatchItemVersioned::V21(bi) = item {
            if bi.result_status == ResultStatusEnumeration::Success {
                bi.result_status = ResultStatusEnumeration::OperationUndone;
                bi.result_reason = None;
                bi.result_message = None;
            }
        } else if let ResponseMessageBatchItemVersioned::V14(bi) = item {
            if bi.result_status == ResultStatusEnumeration::Success {
                bi.result_status = ResultStatusEnumeration::OperationUndone;
                bi.result_reason = None;
                bi.result_message = None;
            }
        }
    }
    Ok(())
}
