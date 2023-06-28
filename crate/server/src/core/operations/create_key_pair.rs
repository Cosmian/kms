use std::collections::HashSet;

use cosmian_kmip::kmip::kmip_operations::{CreateKeyPair, CreateKeyPairResponse};
use cosmian_kms_utils::{access::ExtraDatabaseParams, tagging::get_tags, KeyPair};
use tracing::trace;
use uuid::Uuid;

use crate::{core::KMS, error::KmsError, kms_bail, result::KResult};

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

    // recover tags
    let tags = request
        .common_attributes
        .as_ref()
        .map(|attributes| get_tags(&attributes))
        .unwrap_or(HashSet::new());

    let sk_uid = Uuid::new_v4().to_string();
    let pk_uid = Uuid::new_v4().to_string();
    let key_pair: KeyPair = kms.create_key_pair_(&request, &sk_uid, &pk_uid).await?;
    trace!("create_key_pair: sk_uid: {sk_uid}, pk_uid: {pk_uid}");
    kms.db
        .create_objects(
            owner,
            &[
                (
                    Some(sk_uid.clone()),
                    key_pair.private_key().to_owned(),
                    &tags,
                ),
                (
                    Some(pk_uid.clone()),
                    key_pair.public_key().to_owned(),
                    &tags,
                ),
            ],
            params,
        )
        .await?;

    // debug!("Created  key pair: {}/{}", &sk_uid, &pk_uid);
    Ok(CreateKeyPairResponse {
        private_key_unique_identifier: sk_uid,
        public_key_unique_identifier: pk_uid,
    })
}
