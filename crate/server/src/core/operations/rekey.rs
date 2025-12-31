use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{
        kmip_objects::ObjectType,
        kmip_operations::{Create, Import, ReKey, ReKeyResponse},
        kmip_types::UniqueIdentifier,
    },
};
use cosmian_logger::{debug, trace};

use crate::{
    core::{KMS, operations::import::process_symmetric_key},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

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

    // retrieve the symmetric key associated with the uid (the array MUST contain only one element)

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

        // create a new symmetric key KMIP object (in memory)
        let create_request = Create {
            object_type: ObjectType::SymmetricKey,
            attributes: owm.attributes().to_owned(),
            protection_storage_masks: None,
        };
        let (_uid, new_object, _tags) = KMS::create_symmetric_key_and_tags(&create_request)?;

        // import new KMIP object into the database (but overwrite the existing one)
        let import_request = Import {
            unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
            object_type: ObjectType::SymmetricKey,
            replace_existing: Some(true),
            key_wrap_type: None,
            attributes: new_object.attributes()?.clone(),
            object: new_object,
        };
        let (uid, operations) = Box::pin(process_symmetric_key(kms, import_request, owner)).await?;

        // execute the operations
        kms.database.atomic(owner, &operations).await?;

        // return the uid
        debug!("Re-key symmetric key with uid: {uid}");

        return Ok(ReKeyResponse {
            unique_identifier: UniqueIdentifier::TextString(uid),
        });
    }

    Err(KmsError::InvalidRequest(format!(
        "rekey: get: too many symmetric keys for uid/tags: {uid_or_tags}",
    )))
}
