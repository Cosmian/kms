use cosmian_kms_interfaces::ObjectWithMetadata;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        KmipOperation,
        attribute_policy::AttributeEditPolicy,
        kmip_attributes::{Attribute, Attributes},
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

/// Reject rotation attributes in an HSM `Create` / `CreateKeyPair` request.
///
/// HSM keys get keyset membership and a rotation schedule only through `SetAttribute`
/// after creation (`CKA_LABEL`, `CKA_START_DATE`/`CKA_END_DATE`); a creation request
/// carrying them would otherwise be accepted and silently ignored.
pub(crate) fn reject_hsm_rotation_attributes(
    operation: &str,
    attributes: &Attributes,
) -> KResult<()> {
    if attributes.rotate_name.is_some()
        || attributes.rotate_interval.is_some()
        || attributes.rotate_offset.is_some()
        || attributes.rotate_automatic.is_some()
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Feature_Not_Supported,
            format!(
                "{operation}: rotation attributes are not supported when creating an HSM key; \
                 set the rotation policy with SetAttribute after creation"
            ),
        ));
    }
    Ok(())
}

/// Error for adding a second instance of a single-valued attribute (KMIP 2.1 §6.1.2).
pub(crate) fn single_valued(message: &str) -> KmsError {
    KmsError::Kmip21Error(ErrorReason::Attribute_Single_Valued, message.to_owned())
}

/// Whether a custom attribute is server-owned (KMIP 1.x `y-` names, KMIP 2.1 §4.46).
pub(crate) fn is_server_vendor_attribute(
    vendor_identification: &str,
    attribute_name: &str,
) -> bool {
    vendor_identification == "KMIP1" && attribute_name.starts_with("y-")
}

/// Rejects client writes to server-owned custom attributes (KMIP 1.x `y-` names, KMIP 2.1 §4.46).
pub(crate) fn check_vendor_attribute(
    attribute: &Attribute,
    operation: KmipOperation,
) -> KResult<()> {
    match attribute {
        Attribute::VendorAttribute(va)
            if is_server_vendor_attribute(&va.vendor_identification, &va.attribute_name) =>
        {
            Err(read_only_error(operation))
        }
        _ => Ok(()),
    }
}

/// Rejects attributes the server manages for this operation.
pub(crate) fn check_read_only(tag: Option<Tag>, operation: KmipOperation) -> KResult<()> {
    if tag.map(|tag| tag.edit_policy(operation)) == Some(AttributeEditPolicy::ServerManaged) {
        return Err(read_only_error(operation));
    }
    Ok(())
}

/// Validates client-written rotation attributes: `rotate_name` must not contain `@`
/// (reserved for keyset versioning); Rotate Interval / Rotate Offset are KMIP Interval
/// values (unsigned 32-bit seconds, `ttlv::Interval(u32)`): larger or negative values
/// overflow the auto-rotation date arithmetic.
pub(crate) fn check_rotation_attribute(attribute: &Attribute, operation: &str) -> KResult<()> {
    match attribute {
        Attribute::RotateName(name) if name.contains('@') => {
            Err(KmsError::InvalidRequest(format!(
                "{operation}: rotate_name must not contain '@' (reserved for keyset versioning)"
            )))
        }
        Attribute::RotateInterval(secs) | Attribute::RotateOffset(secs)
            if u32::try_from(*secs).is_err() =>
        {
            Err(KmsError::Kmip21Error(
                ErrorReason::Invalid_Attribute_Value,
                format!(
                    "{operation}: {attribute} must be between 0 and {} seconds, got {secs}",
                    u32::MAX
                ),
            ))
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
    tag: Option<Tag>,
) -> KResult<()> {
    let Some(tag) =
        tag.filter(|tag| tag.edit_policy(operation) == AttributeEditPolicy::RequiresGrant)
    else {
        return Ok(());
    };
    if kms
        .user_can_perform_operation(owm, user, &operation)
        .await?
    {
        return Ok(());
    }
    let (verb, operation_name) = match operation {
        KmipOperation::AddAttribute => ("adding", "AddAttribute"),
        KmipOperation::SetAttribute => ("modifying", "SetAttribute"),
        KmipOperation::DeleteAttribute => ("deleting", "DeleteAttribute"),
        _ => ("modifying", "ModifyAttribute"),
    };
    Err(KmsError::Kmip21Error(
        ErrorReason::Permission_Denied,
        format!(
            "DENIED: {verb} {tag} attribute requires ownership or explicit {operation_name} grant"
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

    #[test]
    fn rotation_interval_and_offset_are_kmip_intervals() {
        for attribute in [
            Attribute::RotateInterval(i64::MAX),
            Attribute::RotateInterval(-1),
            Attribute::RotateOffset(i64::MIN),
            Attribute::RotateOffset(i64::from(u32::MAX) + 1),
        ] {
            assert!(
                matches!(
                    check_rotation_attribute(&attribute, "SetAttribute"),
                    Err(KmsError::Kmip21Error(
                        ErrorReason::Invalid_Attribute_Value,
                        _
                    ))
                ),
                "{attribute:?}"
            );
        }
        for attribute in [
            Attribute::RotateInterval(0),
            Attribute::RotateInterval(i64::from(u32::MAX)),
            Attribute::RotateOffset(0),
        ] {
            assert!(
                check_rotation_attribute(&attribute, "SetAttribute").is_ok(),
                "{attribute:?}"
            );
        }
    }
}
