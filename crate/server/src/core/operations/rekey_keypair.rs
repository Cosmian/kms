use cloudproof::reexport::cover_crypt::Covercrypt;
use cosmian_kmip::{
    crypto::cover_crypt::attributes::{policy_from_attributes, rekey_edit_action_from_attributes},
    kmip::{
        kmip_objects::ObjectType,
        kmip_operations::{ErrorReason, ReKeyKeyPair, ReKeyKeyPairResponse},
        kmip_types::{CryptographicAlgorithm, KeyFormatType, StateEnumeration},
    },
};
use cosmian_kms_client::access::ObjectOperationType;
use tracing::trace;

use crate::{
    core::{
        cover_crypt::rekey_keypair_cover_crypt, extra_database_params::ExtraDatabaseParams, KMS,
    },
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

pub(crate) async fn rekey_keypair(
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
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Rekey keypair: the private key unique identifier must be a string")?;

    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(uid_or_tags, user, ObjectOperationType::Rekey, params)
        .await?
        .into_values()
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
        .ok_or_else(|| KmsError::KmipError(ErrorReason::Item_Not_Found, uid_or_tags.to_owned()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many objects for key {uid_or_tags}",
        )))
    }

    if Some(CryptographicAlgorithm::CoverCrypt) == attributes.cryptographic_algorithm {
        let action = rekey_edit_action_from_attributes(attributes)?;
        rekey_keypair_cover_crypt(kms, Covercrypt::default(), owm.id, user, action, params).await
    } else if let Some(other) = attributes.cryptographic_algorithm {
        kms_bail!(KmsError::NotSupported(format!(
            "The rekey of a key pair for algorithm: {other:?} is not yet supported"
        )))
    } else {
        kms_bail!(KmsError::InvalidRequest(
            "The cryptographic algorithm must be specified in the private key attributes for key \
             pair creation"
                .to_owned()
        ))
    }
}
