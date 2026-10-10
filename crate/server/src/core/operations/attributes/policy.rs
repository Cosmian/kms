use cosmian_kms_interfaces::ObjectWithMetadata;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{KmipOperation, attribute_policy::AttributeEditPolicy, kmip_attributes::Attribute},
};

use crate::{core::KMS, error::KmsError, middlewares::UserId, result::KResult};

/// Rejects attributes the server manages for this operation.
pub(crate) fn check_read_only(
    policy: AttributeEditPolicy,
    operation: KmipOperation,
) -> KResult<()> {
    if policy != AttributeEditPolicy::ServerManaged {
        return Ok(());
    }
    let verb = match operation {
        KmipOperation::AddAttribute => "added",
        KmipOperation::SetAttribute => "set",
        KmipOperation::DeleteAttribute => "deleted",
        _ => "modified",
    };
    Err(KmsError::Kmip21Error(
        ErrorReason::Attribute_Read_Only,
        format!("DENIED: this attribute is server-managed and cannot be {verb} by the user"),
    ))
}

/// Requires ownership or an explicit grant for attributes the policy marks `RequiresGrant`.
pub(crate) async fn check_grant(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    user: &UserId,
    operation: KmipOperation,
    attribute: &Attribute,
) -> KResult<()> {
    if attribute.edit_policy(operation) != AttributeEditPolicy::RequiresGrant
        || kms
            .user_can_perform_operation(owm, user, &operation)
            .await?
    {
        return Ok(());
    }
    let name = match attribute {
        Attribute::Extractable(_) => "Extractable",
        _ => "Sensitive",
    };
    let (verb, operation_name) = match operation {
        KmipOperation::AddAttribute => ("adding", "AddAttribute"),
        KmipOperation::SetAttribute => ("modifying", "SetAttribute"),
        _ => ("modifying", "ModifyAttribute"),
    };
    Err(KmsError::Kmip21Error(
        ErrorReason::Permission_Denied,
        format!(
            "DENIED: {verb} {name} attribute requires ownership or explicit {operation_name} grant"
        ),
    ))
}
