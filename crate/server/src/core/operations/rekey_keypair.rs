use std::sync::Arc;

use cosmian_cover_crypt::api::Covercrypt;
use cosmian_kmip::kmip_2_1::{
    kmip_objects::ObjectType,
    kmip_operations::{ErrorReason, ReKeyKeyPair, ReKeyKeyPairResponse},
    kmip_types::{CryptographicAlgorithm, StateEnumeration},
};
use cosmian_kms_crypto::crypto::cover_crypt::attributes::rekey_edit_action_from_attributes;
use cosmian_kms_interfaces::SessionParams;
use tracing::trace;

use crate::{
    core::{cover_crypt::rekey_keypair_cover_crypt, KMS},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

pub(crate) async fn rekey_keypair(
    kms: &KMS,
    request: ReKeyKeyPair,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
    access_policy: String,
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
    let owm_s = kms
        .database
        .retrieve_objects(uid_or_tags, params.clone())
        .await?
        .into_values();

    for owm in owm_s {
        // only active objects
        if owm.state() != StateEnumeration::Active {
            continue
        }
        // only private keys
        if owm.object().object_type() != ObjectType::PrivateKey {
            continue
        }

        if Some(CryptographicAlgorithm::CoverCrypt) == attributes.cryptographic_algorithm {
            let action = rekey_edit_action_from_attributes(attributes)?;
            return Box::pin(rekey_keypair_cover_crypt(
                kms,
                Covercrypt::default(),
                owm.id().to_owned(),
                user,
                action,
                params,
                access_policy,
            ))
            .await
        } else if let Some(other) = attributes.cryptographic_algorithm {
            kms_bail!(KmsError::NotSupported(format!(
                "The rekey of a key pair for algorithm: {other:?} is not yet supported"
            )))
        }
        kms_bail!(KmsError::InvalidRequest(
            "The cryptographic algorithm must be specified in the private key attributes for key \
             pair creation"
                .to_owned()
        ))
    }

    Err(KmsError::KmipError(
        ErrorReason::Item_Not_Found,
        uid_or_tags.to_owned(),
    ))
}
