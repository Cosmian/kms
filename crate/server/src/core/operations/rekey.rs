use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_objects::ObjectType,
            kmip_operations::{Create, ReKey, ReKeyResponse},
            kmip_types::{LinkType, LinkedObjectIdentifier, UniqueIdentifier},
        },
        time_normalize,
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use cosmian_logger::{info, trace};
use uuid::Uuid;

use crate::{
    core::{KMS, operations::key_ops::setup_object_lifecycle, wrapping::wrap_and_cache},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// KMIP `ReKey` operation for symmetric keys.
///
/// Per KMIP 2.1 §6.1.46:
/// - Creates a new replacement key with a new Unique Identifier.
/// - Sets a Link of type `ReplacementObjectLink` on the existing key pointing to the new key.
/// - Sets a Link of type `ReplacedObjectLink` on the new key pointing to the existing key.
/// - The replacement key takes over the Name attribute of the existing key.
/// - The existing key's **State is NOT changed** — the spec does not deactivate it.
pub(crate) async fn rekey(kms: &KMS, request: ReKey, owner: &str) -> KResult<ReKeyResponse> {
    trace!("ReKey: {}", serde_json::to_string(&request)?);

    if request.protection_storage_masks.is_some() {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Rekey: the symmetric key unique identifier must be a string")?;

    // retrieve the symmetric key associated with the uid
    for owm in kms
        .database
        .retrieve_objects(uid_or_tags)
        .await?
        .into_values()
    {
        // only active objects
        if owm.state() != State::Active {
            continue;
        }
        // only symmetric keys
        if owm.object().object_type() != ObjectType::SymmetricKey {
            continue;
        }

        let old_uid = owm.id().to_owned();
        let now = time_normalize()?;

        // Build attributes for the new key, copying from the existing key
        let mut new_attributes = owm.attributes().clone();

        // The replacement key takes over the Name attribute of the existing key
        // (already in new_attributes from the clone)

        // Remove any existing links and unique identifier from the new key attributes
        new_attributes.unique_identifier = None;
        new_attributes.remove_link(LinkType::ReplacementObjectLink);
        new_attributes.remove_link(LinkType::ReplacedObjectLink);

        // Set the ReplacedObjectLink on the new key pointing to the old key
        new_attributes.set_link(
            LinkType::ReplacedObjectLink,
            LinkedObjectIdentifier::TextString(old_uid.clone()),
        );

        // Create a new symmetric key with fresh key material
        let create_request = Create {
            object_type: ObjectType::SymmetricKey,
            attributes: new_attributes,
            protection_storage_masks: None,
        };
        let (_uid, mut new_object, tags) =
            KMS::create_symmetric_key_and_tags(kms.vendor_id(), &create_request)?;

        // Generate a new UID for the replacement key
        let new_uid = Uuid::new_v4().to_string();

        // Set up lifecycle attributes (state=Active with activation date)
        let new_obj_attributes =
            setup_object_lifecycle(&mut new_object, ObjectType::SymmetricKey, Some(now))?;

        // Wrap the new object if requested
        Box::pin(wrap_and_cache(
            kms,
            owner,
            &UniqueIdentifier::TextString(new_uid.clone()),
            &mut new_object,
        ))
        .await?;

        // Update the old key: set ReplacementObjectLink, remove name
        let mut old_object = owm.object().clone();
        let mut old_attributes = owm.attributes().clone();

        // Set the ReplacementObjectLink on the old key pointing to the new key
        old_attributes.set_link(
            LinkType::ReplacementObjectLink,
            LinkedObjectIdentifier::TextString(new_uid.clone()),
        );

        // Remove the Name from the old key (it's taken over by the new key)
        old_attributes.name = None;

        // Update internal object attributes too
        if let Ok(obj_attrs) = old_object.attributes_mut() {
            obj_attrs.set_link(
                LinkType::ReplacementObjectLink,
                LinkedObjectIdentifier::TextString(new_uid.clone()),
            );
            obj_attrs.name = None;
        }

        // Execute all operations atomically:
        // 1. Create the new replacement key
        // 2. Update the old key (add link, remove name)
        let operations = vec![
            AtomicOperation::Create((new_uid.clone(), new_object, new_obj_attributes, tags)),
            AtomicOperation::UpdateObject((old_uid.clone(), old_object, old_attributes, None)),
        ];

        kms.database.atomic(owner, &operations).await?;

        info!(
            old_uid = old_uid,
            new_uid = new_uid,
            user = owner,
            "Re-keyed symmetric key: old key deactivated, new replacement key created",
        );

        return Ok(ReKeyResponse {
            unique_identifier: UniqueIdentifier::TextString(new_uid),
        });
    }

    Err(KmsError::InvalidRequest(format!(
        "rekey: no active symmetric key found for uid/tags: {uid_or_tags}",
    )))
}
