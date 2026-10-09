use cosmian_kms_interfaces::ObjectWithMetadata;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        KmipOperation, attribute_policy::AttributeEditPolicy, kmip_attributes::Attribute,
        kmip_types::Tag,
    },
};

use crate::{core::KMS, error::KmsError, middlewares::UserId, result::KResult};

const fn operation_denied_verb(operation: KmipOperation) -> &'static str {
    match operation {
        KmipOperation::AddAttribute => "added",
        KmipOperation::SetAttribute => "set",
        KmipOperation::DeleteAttribute => "deleted",
        _ => "modified",
    }
}

/// Rejects server-managed attributes before mutation.
pub(crate) fn check_attribute_read_only(
    attribute: &Attribute,
    operation: KmipOperation,
) -> KResult<()> {
    if attribute.edit_policy(operation) == Some(AttributeEditPolicy::ServerManaged) {
        let verb = operation_denied_verb(operation);
        return Err(KmsError::Kmip21Error(
            ErrorReason::Attribute_Read_Only,
            format!("DENIED: this attribute is server-managed and cannot be {verb} by the user"),
        ));
    }
    Ok(())
}

/// Rejects server-managed attribute tags before deletion.
pub(crate) fn check_tag_read_only(tag: Tag, operation: KmipOperation) -> KResult<()> {
    if tag.edit_policy(operation) == Some(AttributeEditPolicy::ServerManaged) {
        let verb = operation_denied_verb(operation);
        return Err(KmsError::Kmip21Error(
            ErrorReason::Attribute_Read_Only,
            format!("DENIED: this attribute is server-managed and cannot be {verb} by the user"),
        ));
    }
    Ok(())
}

/// Enforces explicit operation authorization for attributes marked [`AttributeEditPolicy::RequiresGrant`].
pub(crate) async fn check_attribute_grant(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    user: &UserId,
    operation: KmipOperation,
    attribute: &Attribute,
) -> KResult<()> {
    if attribute.edit_policy(operation) == Some(AttributeEditPolicy::RequiresGrant)
        && !kms
            .user_can_perform_operation(owm, user, &operation)
            .await?
    {
        let attr_name = match attribute {
            Attribute::Sensitive(_) => "Sensitive",
            Attribute::Extractable(_) => "Extractable",
            _ => "attribute",
        };
        let verb = match operation {
            KmipOperation::AddAttribute => "adding",
            _ => "modifying",
        };
        return Err(KmsError::Kmip21Error(
            ErrorReason::Permission_Denied,
            format!(
                "DENIED: {verb} {attr_name} attribute requires ownership or explicit {operation:?} grant"
            ),
        ));
    }
    Ok(())
}

/// Enforces explicit operation authorization for an attribute tag marked [`AttributeEditPolicy::RequiresGrant`].
pub(crate) async fn check_tag_grant(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    user: &UserId,
    operation: KmipOperation,
    tag: Tag,
) -> KResult<()> {
    if tag.edit_policy(operation) == Some(AttributeEditPolicy::RequiresGrant)
        && !kms
            .user_can_perform_operation(owm, user, &operation)
            .await?
    {
        let attr_name = match tag {
            Tag::Sensitive => "Sensitive",
            Tag::Extractable => "Extractable",
            _ => "attribute",
        };
        let verb = match operation {
            KmipOperation::DeleteAttribute => "deleting",
            _ => "modifying",
        };
        return Err(KmsError::Kmip21Error(
            ErrorReason::Permission_Denied,
            format!(
                "DENIED: {verb} {attr_name} attribute requires ownership or explicit {operation:?} grant"
            ),
        ));
    }
    Ok(())
}
