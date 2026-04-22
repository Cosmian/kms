use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        KmipOperation,
        kmip_operations::{Check, CheckResponse},
        kmip_types::UniqueIdentifier,
    },
};
use cosmian_logger::trace;

use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation},
    error::KmsError,
    result::KResult,
};

/// Minimal implementation of the KMIP Check operation sufficient for BL-M-3-21:
/// - Retrieves the target object
/// - If a `cryptographic_usage_mask` is supplied, ensure all requested bits are permitted by object usage mask
/// - Succeeds (returns unique identifier) if compatible; otherwise returns `IncompatibleCryptographicUsageMask`
pub(crate) async fn check(kms: &KMS, request: Check, owner: &str) -> KResult<CheckResponse> {
    trace!("{request}");
    // Unique Identifier is optional per spec; use ID Placeholder if missing (not yet supported here).
    let uid = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // Retrieve the object (any state except Destroyed/Compromised accepted similar to Get)
    let uid_str = match &uid {
        UniqueIdentifier::TextString(s) => s.as_str(),
        other => {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Message,
                format!(
                    "Unsupported UID variant for Check: {}",
                    std::any::type_name_of_val(&other)
                ),
            ));
        }
    };
    let owm = Box::pin(retrieve_object_for_operation(
        uid_str,
        KmipOperation::Get,
        kms,
        owner,
    ))
    .await?;
    let attributes = owm
        .object()
        .attributes()
        .unwrap_or_else(|_| owm.attributes());

    if let Some(request_mask) = request.cryptographic_usage_mask {
        if !attributes.is_usage_authorized_for(request_mask)? {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Incompatible_Cryptographic_Usage_Mask,
                "Check Failed".to_owned(),
            ));
        }
    }

    Ok(CheckResponse {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_string())),
        // Per BL-M-2-21 expected responses, do not echo policy fields; only return UID.
        // Spec allows omitting these unless policy adjustments are returned.
        usage_limits_count: None,
        cryptographic_usage_mask: None,
        lease_time: None,
    })
}

// (no longer needed) mask comparison helper removed; we rely on Attributes::is_usage_authorized_for
