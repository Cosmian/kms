use cloudproof::reexport::cover_crypt::statics::CoverCryptX25519Aes256;
use cosmian_kmip::kmip::{
    kmip_operations::{ReKeyKeyPair, ReKeyKeyPairResponse},
    kmip_types::CryptographicAlgorithm,
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use tracing::trace;

use crate::{
    core::{
        cover_crypt::rekey_keypair_cover_crypt, operations::uids::uid_from_identifier_tags, KMS,
    },
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

    // there must be an identifier
    let identifier = request
        .private_key_unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // retrieve from tags or use passed identifier
    let private_key_unique_identifier =
        uid_from_identifier_tags(kms, &identifier, user, ObjectOperationType::Encrypt, params)
            .await?
            .unwrap_or(identifier);

    let attributes = request.private_key_attributes.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Rekey keypair: the private key attributes must be supplied".to_owned(),
        )
    })?;

    match &attributes.cryptographic_algorithm {
        Some(CryptographicAlgorithm::CoverCrypt) => {
            rekey_keypair_cover_crypt(
                kms,
                CoverCryptX25519Aes256::default(),
                &private_key_unique_identifier,
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
