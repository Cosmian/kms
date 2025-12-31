#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{ErrorReason, State},
    kmip_2_1::{
        kmip_objects::ObjectType,
        kmip_operations::{ReKeyKeyPair, ReKeyKeyPairResponse},
        kmip_types::KeyFormatType,
    },
};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::{
    crypto::cover_crypt::attributes::rekey_edit_action_from_attributes,
    reexport::cosmian_cover_crypt::api::Covercrypt,
};
use cosmian_logger::trace;

#[cfg(feature = "non-fips")]
use crate::core::cover_crypt::rekey_keypair_cover_crypt;
use crate::{
    core::KMS,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

pub(crate) async fn rekey_keypair(
    kms: &KMS,
    request: ReKeyKeyPair,
    _user: &str,

    _privileged_users: Option<Vec<String>>,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("Internal rekey key pair");

    let _attributes = request.private_key_attributes.as_ref().ok_or_else(|| {
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
        .retrieve_objects(uid_or_tags)
        .await?
        .into_values();

    for owm in owm_s {
        // Only Active or PreActive objects are eligible for rekey
        if owm.state() != State::Active && owm.state() != State::PreActive {
            continue;
        }

        if owm.object().object_type() != ObjectType::PrivateKey {
            continue;
        }

        // if a Covercrypt key, it must be a master secret key
        if let Ok(attributes) = owm.object().attributes() {
            if attributes.key_format_type != Some(KeyFormatType::CoverCryptSecretKey) {
                continue;
            }
        }

        #[expect(clippy::used_underscore_binding)]
        #[cfg(feature = "non-fips")]
        if Some(CryptographicAlgorithm::CoverCrypt) == _attributes.cryptographic_algorithm {
            let action = rekey_edit_action_from_attributes(_attributes)?;
            return Box::pin(rekey_keypair_cover_crypt(
                kms,
                Covercrypt::default(),
                owm.id().to_owned(),
                _user,
                action,
                owm.attributes().sensitive.unwrap_or(false),
                _privileged_users,
            ))
            .await
            .context("Rekey keypair: Covercrypt rekey failed");
        } else if let Some(other) = _attributes.cryptographic_algorithm {
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

    Err(KmsError::Kmip21Error(
        ErrorReason::Item_Not_Found,
        uid_or_tags.to_owned(),
    ))
}
