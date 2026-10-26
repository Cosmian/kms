use cosmian_kms_interfaces::ObjectWithMetadata;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        KmipOperation, attribute_policy::AttributeEditPolicy, kmip_attributes::Attribute,
        kmip_types::Tag,
    },
};

use crate::{core::KMS, error::KmsError, middlewares::UserId, result::KResult};

/// Error for an attribute the server manages for this operation.
pub(crate) fn read_only_error(operation: KmipOperation) -> KmsError {
    let verb = match operation {
        KmipOperation::AddAttribute => "added",
        KmipOperation::SetAttribute => "set",
        KmipOperation::DeleteAttribute => "deleted",
        _ => "modified",
    };
    KmsError::Kmip21Error(
        ErrorReason::Attribute_Read_Only,
        format!("DENIED: this attribute is server-managed and cannot be {verb} by the user"),
    )
}

/// Rejects attributes the server manages for this operation.
pub(crate) fn check_read_only(tag: Option<Tag>, operation: KmipOperation) -> KResult<()> {
    if tag.map(|tag| tag.edit_policy(operation)) == Some(AttributeEditPolicy::ServerManaged) {
        return Err(read_only_error(operation));
    }
    Ok(())
}

/// Rejects `rotate_name` values containing `@`, which is reserved for keyset versioning.
pub(crate) fn check_rotate_name(attribute: &Attribute, operation: &str) -> KResult<()> {
    match attribute {
        Attribute::RotateName(name) if name.contains('@') => {
            Err(KmsError::InvalidRequest(format!(
                "{operation}: rotate_name must not contain '@' (reserved for keyset versioning)"
            )))
        }
        _ => Ok(()),
    }
}

/// Requires ownership or an explicit grant for attributes the policy marks `RequiresGrant`.
pub(crate) async fn check_grant(
    kms: &KMS,
    owm: &ObjectWithMetadata,
    user: &UserId,
    operation: KmipOperation,
    attribute: &Attribute,
) -> KResult<()> {
    if attribute.tag().map(|tag| tag.edit_policy(operation))
        != Some(AttributeEditPolicy::RequiresGrant)
        || kms
            .user_can_perform_operation(owm, user, &operation)
            .await?
    {
        return Ok(());
    }
    let (verb, operation_name) = match operation {
        KmipOperation::AddAttribute => ("adding", "AddAttribute"),
        KmipOperation::SetAttribute => ("modifying", "SetAttribute"),
        _ => ("modifying", "ModifyAttribute"),
    };
    Err(KmsError::Kmip21Error(
        ErrorReason::Permission_Denied,
        format!(
            "DENIED: {verb} {attribute} attribute requires ownership or explicit {operation_name} grant"
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_labels_exclude_values() {
        for (attribute, expected) in [
            (Attribute::Sensitive(true), "Sensitive"),
            (Attribute::Extractable(false), "Extractable"),
            (Attribute::Comment("private value".to_owned()), "Comment"),
        ] {
            assert_eq!(attribute.to_string(), expected);
        }
    }
}
