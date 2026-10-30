use std::sync::Arc;

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
        extra::tagging::VENDOR_ATTR_TAG,
        kmip_messages::ResponseMessageBatchItem,
        kmip_operations::{InteropResponse, LogResponse, Operation},
        kmip_types::{UniqueIdentifier, UniqueIdentifierEnumeration},
    },
    time_normalize,
    ttlv::KmipFlavor,
};
use cosmian_logger::{error, info, trace};
use strum::IntoEnumIterator;

use super::modify_attribute;
use crate::{core::KMS, error::KmsError, middlewares::UserId, result::KResult};

/// Maximum number of batch items processed from one `RequestMessage`: items run
/// sequentially, so an unbounded batch would monopolise a worker and DB connections.
pub(crate) const MAX_BATCH_ITEMS: usize = 10_000;

/// Lazily formats the operations of the first batch items as a list (same output as a
/// `Vec<OperationEnumeration>` debug print, without allocating the `Vec`).
struct BatchOperations<'a>(&'a [RequestMessageBatchItemVersioned]);

impl std::fmt::Debug for BatchOperations<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|bi| match bi {
                RequestMessageBatchItemVersioned::V14(item) => item.operation.into(),
                RequestMessageBatchItemVersioned::V21(item) => item.operation,
            }))
            .finish()
    }
}

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
    if request.batch_item.len() > MAX_BATCH_ITEMS {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Message,
            format!(
                "KMIP request message has {} batch items; the maximum is {MAX_BATCH_ITEMS}",
                request.batch_item.len()
            ),
        ));
    }
    trace!("Entering message KMIP operation: {request}");

    let mut response_items = Vec::with_capacity(request.batch_item.len());
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
    let mut success_indices: Vec<usize> = Vec::with_capacity(request.batch_item.len());
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
        let get_attrs_explicit_refs = get_attrs_has_explicit_refs(&request_operation);

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

        match &response_operation {
            Ok(op) => trace!("Operation processed successfully: {op}"),
            Err(e) => error!(target: "kmip", "Operation processing failed: {e}"),
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
                    Err(KmsError::ItemNotFound(error_message)) => (
                        ResultStatusEnumeration::OperationFailed,
                        Some(ErrorReason::Item_Not_Found),
                        Some(error_message),
                        None,
                    ),
                    Err(KmsError::CryptographicError(error_message)) => (
                        ResultStatusEnumeration::OperationFailed,
                        Some(ErrorReason::Cryptographic_Failure),
                        Some(error_message),
                        None,
                    ),
                    Err(KmsError::Unauthorized(error_message)) => (
                        ResultStatusEnumeration::OperationFailed,
                        Some(ErrorReason::Permission_Denied),
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
            get_attrs_explicit_refs,
            kms.vendor_id(),
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
async fn revert_activation_to_preactive(kms: &KMS, uid: &str, user: &UserId) -> KResult<()> {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::KmipOperation;

    use crate::core::{
        retrieve_object_utils::retrieve_object_for_operation, uid_utils::ObjectHandle,
    };

    let mut owm = Arc::unwrap_or_clone(
        Box::pin(retrieve_object_for_operation(
            ObjectHandle::from(uid),
            KmipOperation::GetAttributes,
            kms,
            user,
        ))
        .await?,
    );

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

/// Fill a missing (or `IDPlaceholder`) Unique Identifier from the batch ID Placeholder.
fn fill_from_id_placeholder(
    unique_identifier: &mut Option<v21types::UniqueIdentifier>,
    id_placeholder: &Option<v21types::UniqueIdentifier>,
) {
    if matches!(
        unique_identifier,
        None | Some(v21types::UniqueIdentifier::Enumeration(
            UniqueIdentifierEnumeration::IDPlaceholder
        ))
    ) {
        if let Some(uid) = id_placeholder {
            *unique_identifier = Some(uid.clone());
        }
    }
}

fn resolve_id_placeholder_for_operation(
    op: &mut Operation,
    id_placeholder: &Option<v21types::UniqueIdentifier>,
) {
    match op {
        Operation::Get(get_request) => {
            fill_from_id_placeholder(&mut get_request.unique_identifier, id_placeholder);
        }
        Operation::GetAttributes(get_attrs_request) => {
            fill_from_id_placeholder(&mut get_attrs_request.unique_identifier, id_placeholder);
        }
        Operation::GetAttributeList(gal_request) => {
            fill_from_id_placeholder(&mut gal_request.unique_identifier, id_placeholder);
        }
        Operation::ModifyAttribute(mod_attr_request) => {
            fill_from_id_placeholder(&mut mod_attr_request.unique_identifier, id_placeholder);
        }
        // KMIP 1.4 §4.7 / 2.1 §6.1.6: an omitted public key UID is the ID Placeholder.
        // A Certify carrying a certificate request certifies that request's key instead.
        Operation::Certify(certify_request)
            if certify_request.certificate_request_value.is_none() =>
        {
            fill_from_id_placeholder(&mut certify_request.unique_identifier, id_placeholder);
        }
        // KMIP 1.4 §4.8: an omitted certificate UID is the ID Placeholder.
        Operation::ReCertify(recertify_request) => {
            fill_from_id_placeholder(&mut recertify_request.unique_identifier, id_placeholder);
        }
        _ => {}
    }
}

/// Whether this batch item is a `GetAttributes` request that explicitly lists attribute references.
fn get_attrs_has_explicit_refs(op: &Operation) -> bool {
    matches!(op, Operation::GetAttributes(ga) if ga.attribute_reference.as_ref().is_some_and(|v| !v.is_empty()))
}

/// `io::Write` sink that only counts the bytes written (no allocation).
struct ByteCounter(usize);

impl std::io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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

fn enforce_max_response_size_for_query(
    response_operation: &Result<Operation, KmsError>,
    remaining_max_response_size: Option<i32>,
) -> KResult<Option<(ResultStatusEnumeration, ErrorReason, String)>> {
    // For QueryResponse, enforce MaximumResponseSize from header if set.
    // Use serialized JSON payload length as a pragmatic proxy for response size.
    if let Ok(Operation::QueryResponse(resp)) = response_operation {
        if let Some(max_total) = remaining_max_response_size {
            let mut counter = ByteCounter(0);
            if serde_json::to_writer(&mut counter, resp).is_ok() {
                let payload_len = i32::try_from(counter.0)?;
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
        // Create returns a single UniqueIdentifier
        Some(Operation::CreateResponse(cr)) => {
            *id_placeholder = Some(cr.unique_identifier.clone());
        }
        // Register returns a single UniqueIdentifier
        Some(Operation::RegisterResponse(rr)) => {
            *id_placeholder = Some(rr.unique_identifier.clone());
        }
        // Certify / ReCertify: the new certificate (KMIP 1.4 §4.7, §4.8; 2.1 §6.1.6)
        Some(Operation::CertifyResponse(cr)) => {
            *id_placeholder = Some(cr.unique_identifier.clone());
        }
        Some(Operation::ReCertifyResponse(rr)) => {
            *id_placeholder = Some(rr.unique_identifier.clone());
        }
        // CreateKeyPair returns public+private UIDs; prefer the private key as placeholder
        Some(Operation::CreateKeyPairResponse(ckpr)) => {
            *id_placeholder = Some(ckpr.private_key_unique_identifier.clone());
        }
        // CreateSplitKey returns a list of split key part UIDs; per KMIP spec the ID
        // Placeholder SHALL be set to the Unique Identifier of the split whose Key Part
        // Identifier is 1 (i.e., the first entry in the list).
        Some(Operation::CreateSplitKeyResponse(cskr)) => {
            *id_placeholder = cskr.unique_identifier.first().cloned();
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

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // tests: a panic is the failure signal
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::{
            kmip_messages::{
                RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader,
                ResponseMessageBatchItemVersioned,
            },
            kmip_types::{CryptographicUsageMask, ProtocolVersion, ResultStatusEnumeration},
        },
        kmip_1_4,
        kmip_2_1::{
            extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
            kmip_attributes::Attributes,
            kmip_messages::RequestMessageBatchItem,
            kmip_objects::ObjectType,
            kmip_operations::{Certify, Get, GetAttributes, Operation, Register},
            kmip_types::{
                CertificateAttributes, LinkType, LinkedObjectIdentifier, RecommendedCurve,
                UniqueIdentifier,
            },
            requests::create_ec_key_pair_request,
        },
        time_normalize,
    };
    use openssl::{
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        x509::{X509NameBuilder, X509Req},
    };

    use super::message;
    use crate::{
        core::KMS, error::KmsError, middlewares::UserId, result::KResult,
        tests::test_utils::test_kms,
    };

    const OWNER: &str = "id_placeholder_owner";

    fn batch(
        major: i32,
        minor: i32,
        batch_item: Vec<RequestMessageBatchItemVersioned>,
    ) -> KResult<RequestMessage> {
        Ok(RequestMessage {
            request_header: RequestMessageHeader {
                protocol_version: ProtocolVersion {
                    protocol_version_major: major,
                    protocol_version_minor: minor,
                },
                batch_count: i32::try_from(batch_item.len())?,
                ..Default::default()
            },
            batch_item,
        })
    }

    fn subject(cn: &str) -> KResult<Attributes> {
        Ok(Attributes {
            certificate_attributes: Some(CertificateAttributes::parse_subject_line(cn)?),
            ..Attributes::default()
        })
    }

    /// An Active (able to sign) EC P-256 key pair: `(private key, public key)` UIDs.
    async fn key_pair(kms: &KMS, owner: &UserId) -> KResult<(UniqueIdentifier, UniqueIdentifier)> {
        let mut request = create_ec_key_pair_request(
            VENDOR_ID_COSMIAN,
            None,
            EMPTY_TAGS,
            RecommendedCurve::P256,
            false,
            None,
        )?;
        request
            .common_attributes
            .get_or_insert_default()
            .activation_date = Some(time_normalize()?);
        let response = kms.create_key_pair(request, owner).await?;
        Ok((
            response.private_key_unique_identifier,
            response.public_key_unique_identifier,
        ))
    }

    /// KMIP 2.1 §6.1.6: `Certify` without a Unique Identifier certifies the ID Placeholder
    /// public key, and the new certificate becomes the ID Placeholder.
    #[tokio::test]
    async fn certify_uses_and_sets_id_placeholder_2_1() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from(OWNER);
        let (sk_uid, pk_uid) = key_pair(&kms, &owner).await?;
        let public_key = kms
            .get(
                Get {
                    unique_identifier: Some(pk_uid),
                    ..Get::default()
                },
                &owner,
            )
            .await?
            .object;
        let mut attributes = Attributes::default();
        attributes.set_link(
            LinkType::PrivateKeyLink,
            LinkedObjectIdentifier::TextString(sk_uid.to_string()),
        );
        let items = [
            Operation::Register(Box::new(Register {
                object_type: ObjectType::PublicKey,
                attributes,
                object: public_key,
                protection_storage_masks: None,
            })),
            Operation::Certify(Box::new(Certify {
                attributes: Some(subject("CN=id-placeholder")?),
                ..Certify::default()
            })),
            Operation::Get(Get::default()),
        ]
        .map(|op| RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(op)));

        let response = message(&kms, batch(2, 1, items.into())?, &owner).await?;
        let [
            ResponseMessageBatchItemVersioned::V21(register),
            ResponseMessageBatchItemVersioned::V21(certify),
            ResponseMessageBatchItemVersioned::V21(get),
        ] = response.batch_item.as_slice()
        else {
            return Err(KmsError::ServerError(format!(
                "unexpected response: {response}"
            )));
        };
        for item in [register, certify, get] {
            assert_eq!(
                item.result_status,
                ResultStatusEnumeration::Success,
                "{:?}",
                item.result_message
            );
        }
        let (
            Some(Operation::RegisterResponse(register)),
            Some(Operation::CertifyResponse(certify)),
            Some(Operation::GetResponse(get)),
        ) = (
            &register.response_payload,
            &certify.response_payload,
            &get.response_payload,
        )
        else {
            return Err(KmsError::ServerError(format!(
                "unexpected payloads: {response}"
            )));
        };
        assert_eq!(get.object_type, ObjectType::Certificate);
        assert_eq!(get.unique_identifier, certify.unique_identifier);
        // The certificate is for the registered public key, not for a generated one.
        let certificate_attributes = kms
            .get_attributes(
                GetAttributes {
                    unique_identifier: Some(certify.unique_identifier.clone()),
                    attribute_reference: None,
                },
                &owner,
            )
            .await?
            .attributes;
        assert_eq!(
            certificate_attributes.get_link(LinkType::PublicKeyLink),
            Some(LinkedObjectIdentifier::TextString(
                register.unique_identifier.to_string()
            ))
        );
        Ok(())
    }

    /// After `CreateKeyPair` the ID Placeholder is the private key; a following `Certify`
    /// without a Unique Identifier certifies the public key of that pair.
    #[tokio::test]
    async fn certify_after_create_key_pair_certifies_its_public_key() -> KResult<()> {
        let kms = test_kms().await?;
        let owner = UserId::from(OWNER);
        let mut create_key_pair = create_ec_key_pair_request(
            VENDOR_ID_COSMIAN,
            None,
            EMPTY_TAGS,
            RecommendedCurve::P256,
            false,
            None,
        )?;
        create_key_pair
            .common_attributes
            .get_or_insert_default()
            .activation_date = Some(time_normalize()?);
        let items = [
            Operation::CreateKeyPair(Box::new(create_key_pair)),
            Operation::Certify(Box::new(Certify {
                attributes: Some(subject("CN=id-placeholder-key-pair")?),
                ..Certify::default()
            })),
            Operation::Get(Get::default()),
        ]
        .map(|op| RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem::new(op)));

        let response = message(&kms, batch(2, 1, items.into())?, &owner).await?;
        let [
            ResponseMessageBatchItemVersioned::V21(create_key_pair),
            ResponseMessageBatchItemVersioned::V21(certify),
            ResponseMessageBatchItemVersioned::V21(get),
        ] = response.batch_item.as_slice()
        else {
            return Err(KmsError::ServerError(format!(
                "unexpected response: {response}"
            )));
        };
        for item in [create_key_pair, certify, get] {
            assert_eq!(
                item.result_status,
                ResultStatusEnumeration::Success,
                "{:?}",
                item.result_message
            );
        }
        let (
            Some(Operation::CreateKeyPairResponse(create_key_pair)),
            Some(Operation::CertifyResponse(certify)),
            Some(Operation::GetResponse(get)),
        ) = (
            &create_key_pair.response_payload,
            &certify.response_payload,
            &get.response_payload,
        )
        else {
            return Err(KmsError::ServerError(format!(
                "unexpected payloads: {response}"
            )));
        };
        assert_eq!(get.object_type, ObjectType::Certificate);
        assert_eq!(get.unique_identifier, certify.unique_identifier);
        let certificate_attributes = kms
            .get_attributes(
                GetAttributes {
                    unique_identifier: Some(certify.unique_identifier.clone()),
                    attribute_reference: None,
                },
                &owner,
            )
            .await?
            .attributes;
        assert_eq!(
            certificate_attributes.get_link(LinkType::PublicKeyLink),
            Some(LinkedObjectIdentifier::TextString(
                create_key_pair.public_key_unique_identifier.to_string()
            ))
        );
        Ok(())
    }

    /// KMIP 1.4 §4.7: the certificate returned by `Certify` replaces the ID Placeholder, so a
    /// following `Get` without a Unique Identifier returns it. A KMIP 1.4 `Certify` cannot
    /// name the subject of a bare public key, hence the PKCS#10 request.
    #[tokio::test]
    async fn certify_sets_id_placeholder_1_4() -> KResult<()> {
        use kmip_1_4::{
            kmip_attributes::Attribute,
            kmip_data_structures::TemplateAttribute,
            kmip_messages::RequestMessageBatchItem as Item14,
            kmip_operations::{Certify as Certify14, Create, Get as Get14, Operation as Op14},
            kmip_types::{
                CertificateRequestType, CryptographicAlgorithm, Link, LinkType as LinkType14,
                ObjectType as ObjectType14, OperationEnumeration as OpEnum14,
            },
        };

        let kms = test_kms().await?;
        let owner = UserId::from(OWNER);
        let (sk_uid, pk_uid) = key_pair(&kms, &owner).await?;
        let issuer_certificate = kms
            .certify(
                Certify {
                    unique_identifier: Some(pk_uid),
                    attributes: Some(subject("CN=id-placeholder-issuer")?),
                    ..Certify::default()
                },
                &owner,
            )
            .await?
            .unique_identifier;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let csr_key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "id-placeholder-leaf")?;
        let mut csr = X509Req::builder()?;
        csr.set_subject_name(&name.build())?;
        csr.set_pubkey(&csr_key)?;
        csr.sign(&csr_key, MessageDigest::sha256())?;

        let item = |operation, request_payload| {
            RequestMessageBatchItemVersioned::V14(Item14 {
                operation,
                ephemeral: None,
                unique_batch_item_id: None,
                request_payload,
                message_extension: None,
            })
        };
        let items = vec![
            // Sets the ID Placeholder to a symmetric key.
            item(
                OpEnum14::Create,
                Op14::Create(Create {
                    object_type: ObjectType14::SymmetricKey,
                    template_attribute: TemplateAttribute {
                        attribute: Some(vec![
                            Attribute::CryptographicAlgorithm(CryptographicAlgorithm::AES),
                            Attribute::CryptographicLength(256),
                            Attribute::CryptographicUsageMask(CryptographicUsageMask::Encrypt),
                        ]),
                    },
                }),
            ),
            item(
                OpEnum14::Certify,
                Op14::Certify(Certify14 {
                    unique_identifier: None,
                    certificate_request_type: Some(CertificateRequestType::PKCS10),
                    certificate_request: Some(csr.build().to_der()?),
                    template_attribute: Some(TemplateAttribute {
                        attribute: Some(vec![
                            Attribute::Link(Link {
                                link_type: LinkType14::PrivateKeyLink,
                                linked_object_identifier: sk_uid.to_string(),
                            }),
                            Attribute::Link(Link {
                                link_type: LinkType14::CertificateLink,
                                linked_object_identifier: issuer_certificate.to_string(),
                            }),
                        ]),
                    }),
                }),
            ),
            item(
                OpEnum14::Get,
                Op14::Get(Get14 {
                    unique_identifier: None,
                    key_format_type: None,
                    key_compression_type: None,
                    key_wrapping_specification: None,
                }),
            ),
        ];

        let response = message(&kms, batch(1, 4, items)?, &owner).await?;
        let [
            ResponseMessageBatchItemVersioned::V14(create),
            ResponseMessageBatchItemVersioned::V14(certify),
            ResponseMessageBatchItemVersioned::V14(get),
        ] = response.batch_item.as_slice()
        else {
            return Err(KmsError::ServerError(format!(
                "unexpected response: {response}"
            )));
        };
        for item in [create, certify, get] {
            assert_eq!(
                item.result_status,
                ResultStatusEnumeration::Success,
                "{:?}",
                item.result_message
            );
        }
        let (Some(Op14::CertifyResponse(certify)), Some(Op14::GetResponse(get))) =
            (&certify.response_payload, &get.response_payload)
        else {
            return Err(KmsError::ServerError(format!(
                "unexpected payloads: {response}"
            )));
        };
        assert_eq!(get.object_type, ObjectType14::Certificate);
        assert_eq!(get.unique_identifier, certify.unique_identifier);
        Ok(())
    }
}
