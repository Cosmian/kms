use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{ErrorReason, State},
    kmip_2_1::{
        KmipOperation,
        kmip_attributes::{Attribute, Attributes},
        kmip_objects::ObjectType,
        kmip_operations::{ModifyAttribute, ModifyAttributeResponse},
        kmip_types::UniqueIdentifier,
    },
    time_normalize,
};
use cosmian_logger::{debug, trace};

use super::policy::{
    check_extractable_latch, check_grant, check_read_only, check_rotate_name,
    check_vendor_attribute, read_only_error,
};
use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation, uid_utils::from_request},
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

/// KMIP 2.1 §6.1.34: only existing attributes may be modified; with several instances the
/// Current Attribute must select one. Attributes the server defaults or schedules are exempt.
fn check_modify_target(
    attributes: &Attributes,
    new: &Attribute,
    current: Option<&Attribute>,
) -> KResult<()> {
    let exists = match new {
        // Name: Synology DSM sets the first Name through Modify (see test_modify_attribute).
        Attribute::Name(_)
        | Attribute::Sensitive(_)
        | Attribute::Extractable(_)
        | Attribute::ActivationDate(_)
        | Attribute::AttributeIndex(_)
        | Attribute::RotateAutomatic(_)
        | Attribute::RotateInterval(_)
        | Attribute::RotateName(_)
        | Attribute::RotateOffset(_) => true,
        Attribute::VendorAttribute(va) => attributes
            .get_vendor_attribute_value(&va.vendor_identification, &va.attribute_name)
            .is_some(),
        Attribute::Link(link) => attributes.get_link(link.link_type).is_some(),
        other => other.tag().is_none_or(|tag| {
            Vec::<Attribute>::from(attributes.clone())
                .iter()
                .any(|a| a.tag() == Some(tag))
        }),
    };
    if !exists {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Attribute_Not_Found,
            format!("ModifyAttribute: attribute {new} is not set on the object"),
        ));
    }
    if let Attribute::Name(_) = new {
        let count = attributes.name.as_ref().map_or(0, Vec::len);
        match current {
            Some(Attribute::Name(c)) => {
                if !attributes.name.as_ref().is_some_and(|n| n.contains(c)) {
                    return Err(KmsError::Kmip21Error(
                        ErrorReason::Attribute_Instance_Not_Found,
                        "ModifyAttribute: Current Attribute matches no Name instance".to_owned(),
                    ));
                }
            }
            _ if count > 1 => {
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Invalid_Field,
                    "ModifyAttribute: Name has several instances; a Current Attribute is required"
                        .to_owned(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// KMIP 2.1 `ModifyAttribute` operation.
///
/// Modifies or sets a single attribute on an existing managed object, enforcing
/// all KMIP lifecycle rules:
///
/// - Read-only attributes (`State`, `CertificateLength`) are rejected.
/// - Modifying `ActivationDate` is only allowed on objects in the **Pre-Active** state,
///   per KMIP spec §3.22. If the new date is in the past or present the object
///   automatically transitions to the **Active** state.
/// - All other attributes are applied and persisted immediately.
///
/// Permission checks and uid/tags resolution are performed via
/// `retrieve_object_for_operation` (same as `SetAttribute` and `Activate`).
pub(crate) async fn modify_attribute(
    kms: &KMS,
    request: ModifyAttribute,
    user: &UserId,
) -> KResult<ModifyAttributeResponse> {
    debug!("ModifyAttribute request");

    let object_handle = from_request(request.unique_identifier.as_ref(), "ModifyAttribute")?;

    // Read-only guard — must be checked before the DB round-trip.
    check_read_only(request.new_attribute.tag(), KmipOperation::ModifyAttribute)?;
    check_rotate_name(&request.new_attribute, "ModifyAttribute")?;
    check_vendor_attribute(&request.new_attribute, KmipOperation::ModifyAttribute)?;

    let owm = Box::pin(retrieve_object_for_operation(
        object_handle,
        KmipOperation::ModifyAttribute,
        kms,
        user,
    ))
    .await?;
    let current_state = owm.state();
    trace!("ModifyAttribute: retrieved target object {}", owm.id());

    // For ActivationDate, KMIP spec §3.22 requires the object to be in Pre-Active state.
    // The transition Pre-Active → Active is triggered automatically when the new date is
    // in the past or equals the current time.
    let mut activate = false;
    if let Attribute::ActivationDate(_) = &request.new_attribute {
        if current_state != State::PreActive {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Wrong_Key_Lifecycle_State,
                format!(
                    "ModifyAttribute: ActivationDate can only be modified on a Pre-Active object \
                     (current state: {current_state:?})"
                ),
            ));
        }
    }

    check_grant(
        kms,
        &owm,
        user,
        KmipOperation::ModifyAttribute,
        request.new_attribute.tag(),
    )
    .await?;

    let (id, mut object, mut attributes) = Arc::unwrap_or_clone(owm).into_parts();
    check_modify_target(
        &attributes,
        &request.new_attribute,
        request.current_attribute.as_ref(),
    )?;
    with_common_simple_attributes! {
        match_set_attribute! { "ModifyAttribute", request.new_attribute, attributes, }
        simple {
            CryptographicLength => cryptographic_length,
            Description => description,
            NeverExtractable => never_extractable,
        }
        custom {
            Attribute::AlwaysSensitive(_) | Attribute::State(_) | Attribute::Digest(_) => {
                // Defensive: already refused by `check_read_only`.
                return Err(read_only_error(KmipOperation::ModifyAttribute));
            }
            Attribute::Sensitive(sensitive) => {
                // Setting Sensitive also (re)computes the server-managed
                // AlwaysSensitive attribute (KMIP 2.1 §4.3).
                trace!("ModifyAttribute: Sensitive: {:?}", sensitive);
                attributes.apply_sensitive(sensitive);
            }
            Attribute::Extractable(extractable) => {
                // Setting Extractable also (re)computes the server-managed
                // NeverExtractable attribute (KMIP 2.1 §4.33).
                trace!("ModifyAttribute: Extractable: {:?}", extractable);
                check_extractable_latch(&attributes, extractable, KmipOperation::ModifyAttribute)?;
                attributes.apply_extractable(extractable);
            }
            Attribute::ActivationDate(activation_date) => {
                trace!("ModifyAttribute: ActivationDate: {:?}", activation_date);
                attributes.activation_date = Some(activation_date);
                // Per KMIP spec §3.22: if the new date is in the past or present, transition to Active.
                let now = time_normalize()?;
                if activation_date <= now {
                    attributes.state = Some(State::Active);
                    activate = true;
                }
            }
            Attribute::Link(link) => {
                trace!("ModifyAttribute: Link: {}", link.linked_object_identifier);
                attributes.set_link(link.link_type, link.linked_object_identifier);
            }
            Attribute::VendorAttribute(vendor_attribute) => {
                trace!("ModifyAttribute: VendorAttribute: {}", vendor_attribute);
                attributes.set_vendor_attribute(
                    &vendor_attribute.vendor_identification,
                    &vendor_attribute.attribute_name,
                    vendor_attribute.attribute_value,
                );
            }
            Attribute::Name(name) => {
                trace!("ModifyAttribute: Name: {}", name);
                let names = attributes.name.get_or_insert_with(Vec::new);
                let target = match request.current_attribute {
                    Some(Attribute::Name(current)) => names.iter().position(|n| *n == current),
                    _ => (names.len() == 1).then_some(0),
                };
                match target.and_then(|i| names.get_mut(i)) {
                    Some(instance) => *instance = name,
                    None => names.push(name),
                }
            }
        }
    }
    attributes.last_change_date = Some(time_normalize()?);
    let tags = kms.database.retrieve_tags(&id).await?;

    // Write modified attributes back into the embedded key-block attributes for key objects.
    // For objects whose key value is a raw ByteString (e.g. opaque SecretData), the key
    // block has no Structure variant and cannot store embedded attributes.  In that case we
    // skip the embedding — the attributes are persisted independently via update_object below.
    match object.object_type() {
        ObjectType::PublicKey
        | ObjectType::PrivateKey
        | ObjectType::SplitKey
        | ObjectType::SecretData
        | ObjectType::PGPKey
        | ObjectType::SymmetricKey => {
            if let Ok(object_attributes) = object.attributes_mut() {
                object_attributes.clone_from(&attributes);
            }
        }
        _ => {}
    }

    debug!("ModifyAttribute: persisting attributes for {id}");
    kms.database
        .update_object(&id, &object, &attributes, Some(&tags))
        .await?;
    // Persist the state transition separately (dedicated DB column).
    if activate {
        kms.database.update_state(&id, State::Active).await?;
    }

    Ok(ModifyAttributeResponse {
        unique_identifier: Some(UniqueIdentifier::TextString(id)),
        echoed_attribute: None,
    })
}
