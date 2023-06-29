use cloudproof::reexport::cover_crypt::statics::CoverCryptX25519Aes256;
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{ReKeyKeyPair, ReKeyKeyPairResponse},
    kmip_types::{CryptographicAlgorithm, StateEnumeration},
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use tracing::trace;

use crate::{
    core::{cover_crypt::rekey_keypair_cover_crypt, KMS},
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub async fn rekey_keypair(
    kms: &KMS,
    request: ReKeyKeyPair,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("Internal rekey key pair");

    let attributes = request.private_key_attributes.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Rekey keypair: the private key attributes must be supplied".to_owned(),
        )
    })?;

    // there must be an identifier
    let uid_or_tags = request
        .private_key_unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(&uid_or_tags, user, ObjectOperationType::Rekey, params)
        .await?
        .into_iter()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            owm.state == StateEnumeration::Active && object_type == ObjectType::PrivateKey
        })
        .collect::<Vec<ObjectWithMetadata>>();

    // there can only be one private key
    let owm = match owm_s.len() {
        0 => return Err(KmsError::ItemNotFound(uid_or_tags.to_owned())),
        1 => owm_s
            .pop()
            .expect(&format!("failed getting the object: {uid_or_tags}")),
        _ => {
            return Err(KmsError::InvalidRequest(format!(
                "too many items for {uid_or_tags}",
            )))
        }
    };

    match &attributes.cryptographic_algorithm {
        Some(CryptographicAlgorithm::CoverCrypt) => {
            rekey_keypair_cover_crypt(
                kms,
                CoverCryptX25519Aes256::default(),
                &owm.id,
                attributes,
                user,
                params,
            )
            .await
        }
        Some(other) => kms_bail!(KmsError::NotSupported(format!(
            "The rekey of a key pair for algorithm: {:?} is not yet supported",
            other
        ))),
        None => kms_bail!(KmsError::InvalidRequest(
            "The cryptographic algorithm must be specified in the private key attributes for key \
             pair creation"
                .to_string()
        )),
    }
}
