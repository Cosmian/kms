use cosmian_kmip::kmip::{
    kmip_objects::{
        Object,
        ObjectType::{PrivateKey, PublicKey, SymmetricKey},
    },
    kmip_operations::{Revoke, RevokeResponse},
    kmip_types::{
        KeyFormatType, LinkType, RevocationReason, RevocationReasonEnumeration, StateEnumeration,
    },
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};

use super::{
    get::{check_state_active, get_},
    uids::uid_from_identifier_tags,
};
use crate::{
    core::{cover_crypt::revoke_user_decryption_keys, KMS},
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub async fn revoke_operation(
    kms: &KMS,
    request: Revoke,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<RevokeResponse> {
    //TODO http://gitlab.cosmian.com/core/cosmian_server/-/issues/131  Reasons should be kept
    let unique_identifier = &request
        .unique_identifier
        .to_owned()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // retrieve the object
    let (object, state) = get_(
        kms,
        unique_identifier,
        None,
        None,
        user,
        params,
        ObjectOperationType::Revoke,
    )
    .await?;

    let object_type = object.object_type();
    match object_type {
        SymmetricKey => {
            // revoke the key
            revoke_key_core(
                unique_identifier,
                object,
                state,
                request.revocation_reason,
                request.compromise_occurrence_date,
                kms,
                params,
            )
            .await?;
        }
        PrivateKey => {
            let private_key = revoke_key_core(
                unique_identifier,
                object,
                state,
                request.revocation_reason.clone(),
                request.compromise_occurrence_date,
                kms,
                params,
            )
            .await?;
            if let Some(public_key_id) = private_key.attributes()?.get_link(LinkType::PublicKeyLink)
            {
                let _ = revoke_key(
                    &public_key_id,
                    request.revocation_reason.clone(),
                    request.compromise_occurrence_date,
                    kms,
                    user,
                    params,
                )
                .await;
            }
            if let KeyFormatType::CoverCryptSecretKey = private_key.key_block()?.key_format_type {
                revoke_user_decryption_keys(
                    unique_identifier,
                    request.revocation_reason,
                    request.compromise_occurrence_date,
                    kms,
                    user,
                    params,
                )
                .await?
            }
        }
        PublicKey => {
            // revoke the public key
            let public_key = revoke_key_core(
                unique_identifier,
                object,
                state,
                request.revocation_reason.clone(),
                request.compromise_occurrence_date,
                kms,
                params,
            )
            .await?;
            if let Some(private_key_id) =
                public_key.attributes()?.get_link(LinkType::PrivateKeyLink)
            {
                if let Ok(private_key) = revoke_key(
                    &private_key_id,
                    request.revocation_reason.clone(),
                    request.compromise_occurrence_date,
                    kms,
                    user,
                    params,
                )
                .await
                {
                    if let KeyFormatType::CoverCryptSecretKey =
                        private_key.key_block()?.key_format_type
                    {
                        revoke_user_decryption_keys(
                            &private_key_id,
                            request.revocation_reason,
                            request.compromise_occurrence_date,
                            kms,
                            user,
                            params,
                        )
                        .await?
                    }
                }
            }
        }
        x => kms_bail!(KmsError::NotSupported(format!(
            "revoke operation is not supported for object type {:?}",
            x
        ))),
    };

    Ok(RevokeResponse {
        unique_identifier: unique_identifier.to_string(),
    })
}

/// Revoke a key, knowing the object and state
#[allow(clippy::too_many_arguments)]
async fn revoke_key_core(
    unique_identifier: &str,
    object: Object,
    state: StateEnumeration,
    revocation_reason: RevocationReason,
    compromise_occurrence_date: Option<u64>,
    kms: &KMS,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    //
    check_state_active(state, unique_identifier)?;

    let state = match revocation_reason {
        RevocationReason::Enumeration(e) => match e {
            RevocationReasonEnumeration::Unspecified
            | RevocationReasonEnumeration::AffiliationChanged
            | RevocationReasonEnumeration::Superseded
            | RevocationReasonEnumeration::CessationOfOperation
            | RevocationReasonEnumeration::PrivilegeWithdrawn => StateEnumeration::Deactivated,
            RevocationReasonEnumeration::KeyCompromise
            | RevocationReasonEnumeration::CACompromise => {
                if compromise_occurrence_date.is_none() {
                    kms_bail!(KmsError::InvalidRequest(
                        "A compromise date must be supplied in case of compromised object"
                            .to_owned()
                    ))
                }
                StateEnumeration::Compromised
            }
        },
        RevocationReason::TextString(_) => StateEnumeration::Deactivated,
    };
    kms.db
        .update_state(unique_identifier, state, params)
        .await?;

    Ok(object)
}

/// Revoke a key from its id
pub(crate) async fn revoke_key(
    unique_identifier: &str,
    revocation_reason: RevocationReason,
    compromise_occurrence_date: Option<u64>,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    // retrieve from tags or use passed identifier
    let unique_identifier = uid_from_identifier_tags(
        kms,
        unique_identifier,
        user,
        ObjectOperationType::Encrypt,
        params,
    )
    .await?
    .unwrap_or(unique_identifier.to_owned());

    // retrieve the object
    let (object, state) = get_(
        kms,
        &unique_identifier,
        None,
        None,
        user,
        params,
        ObjectOperationType::Revoke,
    )
    .await?;

    revoke_key_core(
        &unique_identifier,
        object,
        state,
        revocation_reason,
        compromise_occurrence_date,
        kms,
        params,
    )
    .await
}
