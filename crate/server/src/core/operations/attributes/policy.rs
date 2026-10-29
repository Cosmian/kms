use cosmian_kms_interfaces::ObjectWithMetadata;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        KmipOperation, attribute_policy::AttributeEditPolicy, kmip_attributes::Attribute,
        kmip_types::Tag,
    },
};

use crate::{
    core::{KMS, uid_utils::ObjectHandle},
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

/// Error for an attribute the server manages for this operation.
///
/// KMIP 2.1 names two result reasons: Add and Set Attribute return `Read Only Attribute`
/// (§6.1.2.1 Table 169, §6.1.51.1 Table 324); Modify and Delete Attribute return
/// `Attribute Read Only` (§6.1.34.1 Table 267, §6.1.13.1 Table 204).
pub(crate) fn read_only_error(operation: KmipOperation) -> KmsError {
    let (verb, reason) = match operation {
        KmipOperation::AddAttribute => ("added", ErrorReason::Read_Only_Attribute),
        KmipOperation::SetAttribute => ("set", ErrorReason::Read_Only_Attribute),
        KmipOperation::DeleteAttribute => ("deleted", ErrorReason::Attribute_Read_Only),
        _ => ("modified", ErrorReason::Attribute_Read_Only),
    };
    KmsError::Kmip21Error(
        reason,
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

/// For SQL (non-HSM) objects, requires `rotate_name` to equal the object's UID.
///
/// This enforces the gen-0 UID = keyset name invariant for deterministic `@N` addressing.
/// `noun` names the object in the error ("key" or "object").
pub(crate) fn check_sql_rotate_name(
    uid: &str,
    attribute: &Attribute,
    operation: &str,
    noun: &str,
) -> KResult<()> {
    match attribute {
        Attribute::RotateName(name) if !ObjectHandle::from(uid).is_hsm() && name != uid => {
            Err(KmsError::InvalidRequest(format!(
                "{operation}: rotate_name ('{name}') must equal the {noun}'s UID ('{uid}') — \
                 create the {noun} with the keyset name as its ID"
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

    #[test]
    fn read_only_reason_follows_operation() {
        for (operation, expected) in [
            (
                KmipOperation::AddAttribute,
                ErrorReason::Read_Only_Attribute,
            ),
            (
                KmipOperation::SetAttribute,
                ErrorReason::Read_Only_Attribute,
            ),
            (
                KmipOperation::ModifyAttribute,
                ErrorReason::Attribute_Read_Only,
            ),
            (
                KmipOperation::DeleteAttribute,
                ErrorReason::Attribute_Read_Only,
            ),
        ] {
            assert!(
                matches!(read_only_error(operation), KmsError::Kmip21Error(reason, _) if reason == expected),
                "{operation:?}"
            );
        }
    }
}
