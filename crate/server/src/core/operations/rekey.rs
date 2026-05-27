use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation,
            kmip_objects::ObjectType,
            kmip_operations::{Create, ReKey, ReKeyResponse},
            kmip_types::UniqueIdentifier,
        },
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use cosmian_logger::{info, trace};
use uuid::Uuid;

use super::rekey_common::{prepare_replacement_attributes, update_old_key_after_rekey};
use crate::{
    core::{
        KMS,
        operations::key_ops::{ObjectWithMetadataOps, setup_object_lifecycle},
        retrieve_object_utils::user_has_permission,
        wrapping::wrap_and_cache,
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// KMIP `ReKey` operation for symmetric keys.
///
/// Per KMIP 1.4 §4.4 / KMIP 2.1 §6.1.46:
/// - Creates a new replacement key with a new Unique Identifier.
/// - Sets a Link of type `ReplacementObjectLink` on the existing key pointing to the new key.
/// - Sets a Link of type `ReplacedObjectLink` on the new key pointing to the existing key.
/// - The replacement key takes over the Name attribute of the existing key.
/// - The existing key's **State is NOT changed** — the spec does not deactivate it.
/// - If `offset` is provided, date arithmetic per Table 172 is applied.
pub(crate) async fn rekey(
    kms: &KMS,
    request: ReKey,
    owner: &str,
    privileged_users: Option<Vec<String>>,
) -> KResult<ReKeyResponse> {
    trace!("ReKey: {}", serde_json::to_string(&request)?);

    if request.protection_storage_masks.is_some() {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // ReKey creates a new replacement key — enforce privileged-user restriction
    if let Some(ref users) = privileged_users {
        let has_permission = user_has_permission(owner, None, &KmipOperation::Create, kms).await?;

        if !has_permission && !users.iter().any(|u| u == owner) {
            kms_bail!(KmsError::Unauthorized(
                "User does not have create access-right.".to_owned()
            ))
        }
    }

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Rekey: the symmetric key unique identifier must be a string")?;

    let offset = request.offset;

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

        // Reject wrapped keys — the server cannot safely rekey a wrapped object
        if owm.object().key_wrapping_data().is_some() {
            kms_bail!(KmsError::InconsistentOperation(
                "The server cannot rekey: the key is wrapped. Unwrap it first.".to_owned()
            ))
        }

        let old_uid = owm.id().to_owned();

        // Verify the caller is allowed to rekey this object
        if !owm
            .user_can_perform_operation(owner, &KmipOperation::Rekey, kms)
            .await?
        {
            continue;
        }

        // Prepare replacement attributes using shared logic (links, name, dates)
        let new_attributes = prepare_replacement_attributes(owm.attributes(), &old_uid, offset)?;

        // Compute the activation date for lifecycle setup
        let activation_date = new_attributes.activation_date;

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

        // Set up lifecycle attributes (state based on activation date)
        let new_obj_attributes =
            setup_object_lifecycle(&mut new_object, ObjectType::SymmetricKey, activation_date)?;

        // Wrap the new object if requested
        Box::pin(wrap_and_cache(
            kms,
            owner,
            &UniqueIdentifier::TextString(new_uid.clone()),
            &mut new_object,
        ))
        .await?;

        // Update the old key using shared logic (ReplacementObjectLink, remove name, last change)
        let mut old_object = owm.object().clone();
        let mut old_attributes = owm.attributes().clone();

        update_old_key_after_rekey(&mut old_attributes, &new_uid)?;

        // Update internal object attributes too
        if let Ok(obj_attrs) = old_object.attributes_mut() {
            update_old_key_after_rekey(obj_attrs, &new_uid)?;
        }

        // Execute all operations atomically:
        // 1. Create the new replacement key
        // 2. Update the old key (add link, remove name, update last change date)
        let operations = vec![
            AtomicOperation::Create((new_uid.clone(), new_object, new_obj_attributes, tags)),
            AtomicOperation::UpdateObject((old_uid.clone(), old_object, old_attributes, None)),
        ];

        kms.database.atomic(owner, &operations).await?;

        info!(
            old_uid = old_uid,
            new_uid = new_uid,
            user = owner,
            "Re-keyed symmetric key: new replacement key created, old key remains Active",
        );

        return Ok(ReKeyResponse {
            unique_identifier: UniqueIdentifier::TextString(new_uid),
        });
    }

    Err(KmsError::InvalidRequest(format!(
        "rekey: no active symmetric key found for uid/tags: {uid_or_tags}",
    )))
}
