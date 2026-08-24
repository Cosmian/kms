//! Covercrypt in-place attribute rekey (non-FIPS only).
//!
//! Covercrypt uses a fundamentally different rotation model: key material is mutated
//! in-place via attribute-level policy changes rather than generating a new UID.
//! This module isolates that logic from the standard key pair rotation pipeline.

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        kmip_objects::ObjectType,
        kmip_operations::{ReKeyKeyPair, ReKeyKeyPairResponse},
        kmip_types::{CryptographicAlgorithm, KeyFormatType},
    },
    cosmian_kms_crypto::{
        crypto::cover_crypt::attributes::rekey_edit_action_from_attributes,
        reexport::cosmian_cover_crypt::api::Covercrypt,
    },
};

use crate::{
    core::{KMS, cover_crypt::rekey_keypair_cover_crypt, uid_utils::from_request},
    error::KmsError,
    result::{KResult, KResultHelper},
};

/// Attempt Covercrypt-specific rekey. Returns `Some(response)` if handled, `None` otherwise.
pub(super) async fn try_covercrypt_rekey(
    kms: &KMS,
    request: &ReKeyKeyPair,
    user: &str,
) -> KResult<Option<ReKeyKeyPairResponse>> {
    let object_handle = from_request(
        request.private_key_unique_identifier.as_ref(),
        "ReKeyKeyPair",
    )?;

    for owm in kms
        .retrieve_eligible_keys(object_handle, ObjectType::PrivateKey)
        .await?
    {
        let key_format_type = owm.attributes().key_format_type.or_else(|| {
            owm.object()
                .attributes()
                .ok()
                .and_then(|a| a.key_format_type)
        });

        if key_format_type == Some(KeyFormatType::CoverCryptSecretKey) {
            let attributes = request.private_key_attributes.as_ref().ok_or_else(|| {
                KmsError::InvalidRequest(
                    "ReKeyKeyPair: the private key attributes must be supplied for Covercrypt"
                        .to_owned(),
                )
            })?;
            if Some(CryptographicAlgorithm::CoverCrypt) == attributes.cryptographic_algorithm {
                let action = rekey_edit_action_from_attributes(kms.vendor_id(), attributes)?;
                let response = Box::pin(rekey_keypair_cover_crypt(
                    kms,
                    Covercrypt::default(),
                    owm.id().to_owned(),
                    user,
                    action,
                    owm.attributes().sensitive.unwrap_or(false),
                ))
                .await
                .context("ReKeyKeyPair: Covercrypt rekey failed")?;
                return Ok(Some(response));
            }
        }
    }
    Ok(None)
}
