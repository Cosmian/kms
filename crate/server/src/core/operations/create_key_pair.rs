use cosmian_kmip::kmip::{
    kmip_operations::{CreateKeyPair, CreateKeyPairResponse},
    kmip_types::UniqueIdentifier,
};
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    database::AtomicOperation,
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub async fn create_key_pair(
    kms: &KMS,
    request: CreateKeyPair,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CreateKeyPairResponse> {
    trace!("Create key pair: {}", serde_json::to_string(&request)?);
    if request.common_protection_storage_masks.is_some()
        || request.private_protection_storage_masks.is_some()
        || request.public_protection_storage_masks.is_some()
    {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // generate uids and create the key pair and tags
    let sk_uid = Uuid::new_v4().to_string();
    let pk_uid = Uuid::new_v4().to_string();
    let (key_pair, sk_tags, pk_tags) = kms.create_key_pair_and_tags(request, &sk_uid, &pk_uid)?;

    trace!("create_key_pair: sk_uid: {sk_uid}, pk_uid: {pk_uid}");

    let private_key_attributes = key_pair.private_key().attributes()?.clone();
    let public_key_attributes = key_pair.public_key().attributes()?.clone();

    let operations = vec![
        AtomicOperation::Create((
            sk_uid.clone(),
            key_pair.private_key().to_owned(),
            private_key_attributes,
            sk_tags,
        )),
        AtomicOperation::Create((
            pk_uid.clone(),
            key_pair.public_key().to_owned(),
            public_key_attributes,
            pk_tags,
        )),
    ];
    kms.db.atomic(owner, &operations, params).await?;

    debug!("Created key pair: {}/{}", &sk_uid, &pk_uid);
    Ok(CreateKeyPairResponse {
        private_key_unique_identifier: UniqueIdentifier::TextString(sk_uid),
        public_key_unique_identifier: UniqueIdentifier::TextString(pk_uid),
    })
}
