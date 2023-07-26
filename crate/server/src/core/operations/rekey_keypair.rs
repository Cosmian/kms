use cloudproof::reexport::cover_crypt::Covercrypt;
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{ReKeyKeyPair, ReKeyKeyPairResponse},
    kmip_types::{CryptographicAlgorithm, KeyFormatType, StateEnumeration},
};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, ObjectOperationType},
    crypto::cover_crypt::attributes::policy_from_attributes,
};
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
            // only active objects
            if owm.state != StateEnumeration::Active {
                return false
            }
            // only private keys
            if owm.object.object_type() != ObjectType::PrivateKey {
                return false
            }
            // if a Covercrypt key, it must be a master secret key
            if let Ok(attributes) = owm.object.attributes() {
                if attributes.key_format_type == Some(KeyFormatType::CoverCryptSecretKey) {
                    // a master key should have policies in the attributes
                    return policy_from_attributes(attributes).is_ok()
                }
            }
            true
        })
        .collect::<Vec<ObjectWithMetadata>>();

    // there can only be one private key
    let owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::ItemNotFound(uid_or_tags.clone()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many objects for key {uid_or_tags}",
        )))
    }

    match &attributes.cryptographic_algorithm {
        Some(CryptographicAlgorithm::CoverCrypt) => {
            rekey_keypair_cover_crypt(
                kms,
                Covercrypt::default(),
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
