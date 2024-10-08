use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{Create, CreateResponse},
    kmip_types::UniqueIdentifier,
};
use tracing::{debug, trace};

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub(crate) async fn create(
    kms: &KMS,
    request: Create,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CreateResponse> {
    trace!("Create: {}", serde_json::to_string(&request)?);
    if request.protection_storage_masks.is_some() {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    let (unique_identifier, object, tags) = match &request.object_type {
        ObjectType::SymmetricKey => KMS::create_symmetric_key_and_tags(&request)?,
        ObjectType::PrivateKey => {
            kms.create_private_key_and_tags(&request, owner, params)
                .await?
        }
        _ => {
            kms_bail!(KmsError::NotSupported(format!(
                "This server does not yet support creation of: {}",
                request.object_type
            )))
        }
    };
    let uid = kms
        .db
        .create(
            unique_identifier,
            owner,
            &object,
            object.attributes()?,
            &tags,
            params,
        )
        .await?;
    debug!(
        "Created KMS Object of type {:?} with id {uid}",
        &object.object_type(),
    );
    Ok(CreateResponse {
        object_type: request.object_type,
        unique_identifier: UniqueIdentifier::TextString(uid),
    })
}
