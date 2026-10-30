use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        KmipOperation,
        kmip_attributes::Attribute,
        kmip_objects::ObjectType,
        kmip_operations::{AddAttribute, AddAttributeResponse},
        kmip_types::UniqueIdentifier,
    },
    time_normalize,
};
use cosmian_logger::{debug, trace};

use super::policy::{
    check_grant, check_read_only, check_rotate_name, check_sql_rotate_name, check_vendor_attribute,
    read_only_error, single_valued,
};
use crate::{
    core::{
        KMS,
        retrieve_object_utils::retrieve_object_for_operation,
        uid_utils::{ObjectHandle, from_request},
    },
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

pub(crate) async fn add_attribute(
    kms: &KMS,
    request: AddAttribute,
    user: &UserId,
) -> KResult<AddAttributeResponse> {
    trace!("AddAttribute request");

    // there must be an identifier
    let object_handle = from_request(Some(&request.unique_identifier), "Add Attribute")?;

    // Read-only guard — these attributes are server-managed.
    check_read_only(request.new_attribute.tag(), KmipOperation::AddAttribute)?;
    check_rotate_name(&request.new_attribute, "AddAttribute")?;
    check_vendor_attribute(&request.new_attribute, KmipOperation::AddAttribute)?;

    let owm = Box::pin(retrieve_object_for_operation(
        object_handle,
        KmipOperation::AddAttribute,
        kms,
        user,
    ))
    .await?;
    let owm = Arc::unwrap_or_clone(owm);
    trace!("Retrieved object for AddAttribute");

    check_sql_rotate_name(owm.id(), &request.new_attribute, "AddAttribute", "key")?;

    // Capture before the macro runs (which may partially move request.new_attribute).
    let is_adding_rotate_name_on_sql = matches!(&request.new_attribute, Attribute::RotateName(_))
        && !ObjectHandle::from(owm.id()).is_hsm();

    check_grant(
        kms,
        &owm,
        user,
        KmipOperation::AddAttribute,
        request.new_attribute.tag(),
    )
    .await?;

    let echoed_attribute = Some(request.new_attribute.clone());
    let (id, mut object, mut attributes) = owm.into_parts();
    // Check if the attribute is allowed to be set
    with_common_simple_attributes! {
        match_add_attribute! { request.new_attribute, attributes, }
        simple {
            ActivationDate => activation_date,
            CryptographicLength => cryptographic_length,
        }
        custom {
            Attribute::Link(link) => {
                trace!("Link: {}", link);
                if attributes.get_link(link.link_type).is_some() {
                    return Err(single_valued("Link already exists"));
                }
                attributes.set_link(link.link_type, link.linked_object_identifier);
            }
            Attribute::VendorAttribute(vendor_attribute) => {
                trace!("Vendor Attribute: {}", vendor_attribute);
                // For KMIP 1.x deprecated attributes (e.g. OperationPolicyName)
                // that are stored as VendorAttributes with vendor_identification="KMIP1",
                // allow overwrite since the attribute may already exist from the
                // Create template. VAST sends OPN both in Create and via AddAttribute.
                let is_kmip1_compat =
                    vendor_attribute.vendor_identification == "KMIP1";
                if !is_kmip1_compat
                    && attributes
                        .get_vendor_attribute_value(
                            &vendor_attribute.vendor_identification,
                            &vendor_attribute.attribute_name,
                        )
                        .is_some()
                {
                    return Err(single_valued("Vendor Attribute already exists"));
                }
                attributes.set_vendor_attribute(
                    &vendor_attribute.vendor_identification,
                    &vendor_attribute.attribute_name,
                    vendor_attribute.attribute_value,
                );
            }
            Attribute::Name(name) => {
                trace!("Name: {name}");
                let names = attributes.name.get_or_insert(vec![]);
                if names.iter().any(|n| n == &name) {
                    return Err(KmsError::Kmip21Error(
                        ErrorReason::Non_Unique_Name_Attribute,
                        "DENIED".to_owned(),
                    ));
                }
                names.push(name);
            }
            Attribute::Description(description) => {
                trace!("Description: {:?}", description);
                if attributes.description.is_some() {
                    return Err(KmsError::Kmip21Error(
                        ErrorReason::Attribute_Single_Valued,
                        "DENIED".to_owned(),
                    ));
                }
                attributes.description = Some(description);
            }
            Attribute::AlwaysSensitive(_)
            | Attribute::NeverExtractable(_)
            | Attribute::State(_)
            | Attribute::Digest(_) => {
                // Defensive: already refused by `check_read_only`.
                return Err(read_only_error(KmipOperation::AddAttribute));
            }
            Attribute::Sensitive(sensitive) => {
                trace!("Sensitive: {:?}", sensitive);
                if attributes.sensitive.is_some() {
                    return Err(single_valued("Sensitive already exists"));
                }
                // Setting Sensitive also (re)computes the server-managed
                // AlwaysSensitive attribute (KMIP 2.1 §4.3).
                attributes.apply_sensitive(sensitive);
            }
            Attribute::Extractable(extractable) => {
                trace!("Extractable: {:?}", extractable);
                if attributes.extractable.is_some() {
                    return Err(single_valued("Extractable already exists"));
                }
                attributes.apply_extractable(extractable);
            }
        }
    }

    // Initialise keyset metadata when rotate_name is first added to an SQL key.
    if is_adding_rotate_name_on_sql {
        if attributes.rotate_generation.is_none() {
            attributes.rotate_generation = Some(0);
        }
        if attributes.rotate_latest.is_none() {
            attributes.rotate_latest = Some(true);
        }
    }

    // update the last change date
    attributes.last_change_date = Some(time_normalize()?);

    let tags = kms.database.retrieve_tags(&id).await?;

    match object.object_type() {
        ObjectType::PublicKey
        | ObjectType::PrivateKey
        | ObjectType::SplitKey
        | ObjectType::SecretData
        | ObjectType::PGPKey
        | ObjectType::SymmetricKey => {
            if let Ok(object_attributes) = object.attributes_mut() {
                object_attributes.clone_from(&attributes);
                debug!("Synchronized embedded object attributes");
            }
        }
        _ => {
            trace!(
                "Attribute: Object type {:?} does not have attributes (nor key block)",
                object.object_type()
            );
        }
    }

    debug!("Added object attribute");
    kms.database
        .update_object(&id, &object, &attributes, Some(&tags))
        .await?;

    Ok(AddAttributeResponse {
        unique_identifier: UniqueIdentifier::TextString(id),
        echoed_attribute,
    })
}
