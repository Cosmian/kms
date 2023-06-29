use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{Create, CreateResponse},
};
use cosmian_kms_utils::{access::ExtraDatabaseParams, tagging::get_tags};
use tracing::{debug, trace};

use crate::{core::KMS, error::KmsError, kms_bail, result::KResult};

pub async fn create(
    kms: &KMS,
    request: Create,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CreateResponse> {
    trace!("Create: {}", serde_json::to_string(&request)?);
    if request.protection_storage_masks.is_some() {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // recover tags
    let tags = get_tags(&request.attributes);

    let object = match &request.object_type {
        ObjectType::SymmetricKey => {
            let mut rng = kms.rng.lock().expect("failed locking the CsRng");
            kms.create_symmetric_key(&mut rng, &request, owner)?
        }
        ObjectType::PrivateKey => kms.create_private_key(&request, owner, params).await?,
        _ => {
            kms_bail!(KmsError::NotSupported(format!(
                "This server does not yet support creation of: {}",
                request.object_type
            )))
        }
    };
    let uid = kms.db.create(None, owner, &object, &tags, params).await?;
    debug!(
        "Created KMS Object of type {:?} with id {uid}",
        &object.object_type(),
    );
    Ok(CreateResponse {
        object_type: request.object_type,
        unique_identifier: uid,
    })
}
