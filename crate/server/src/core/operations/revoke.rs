use std::collections::HashSet;

use async_recursion::async_recursion;
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType::{self, PrivateKey, PublicKey, SymmetricKey},
    kmip_operations::{Revoke, RevokeResponse},
    kmip_types::{
        KeyFormatType, LinkType, RevocationReason, RevocationReasonEnumeration, StateEnumeration,
    },
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};

use crate::{
    core::{cover_crypt::revoke_user_decryption_keys, KMS},
    database::object_with_metadata::ObjectWithMetadata,
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
    //TODO   Reasons should be kept

    let revocation_reason = request.revocation_reason.clone();
    let compromise_occurrence_date = request.compromise_occurrence_date;

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    recursively_revoke_key(
        &uid_or_tags,
        revocation_reason,
        compromise_occurrence_date,
        kms,
        user,
        params,
        HashSet::new(),
    )
    .await?;

    Ok(RevokeResponse {
        unique_identifier: uid_or_tags,
    })
}

/// Recursively revoke keys
#[async_recursion]
pub(crate) async fn recursively_revoke_key<'a: 'async_recursion>(
    uid_or_tags: &str,
    revocation_reason: RevocationReason,
    compromise_occurrence_date: Option<u64>,
    kms: &KMS,
    user: &str,
    params: Option<&'a ExtraDatabaseParams>,
    // keys that should be skipped
    mut ids_to_skip: HashSet<String>,
) -> KResult<()> {
    // retrieve from tags or use passed identifier
    let owm_s = kms
        .db
        .retrieve(uid_or_tags, user, ObjectOperationType::Revoke, params)
        .await?
        .into_iter()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            println!(
                "Revoke: filtering object type: {}, state {}, id {}",
                object_type, owm.state, owm.id
            );
            (owm.state == StateEnumeration::Active || owm.state == StateEnumeration::PreActive)
                && (object_type == ObjectType::PrivateKey
                    || object_type == ObjectType::SymmetricKey
                    || object_type == ObjectType::PublicKey)
        })
        .collect::<Vec<ObjectWithMetadata>>();

    if owm_s.is_empty() {
        return Err(KmsError::ItemNotFound(uid_or_tags.to_owned()))
    }

    // revoke the keys found
    for owm in owm_s {
        println!(
            "Revoke: revoking object type: {}, state {}, id {}",
            owm.object.object_type(),
            owm.state,
            owm.id
        );

        // perform the chain of revoke operations depending on the type of object
        let object_type = owm.object.object_type();
        match object_type {
            SymmetricKey => {
                // revoke the key
                revoke_key_core(
                    &owm.id,
                    revocation_reason.clone(),
                    compromise_occurrence_date,
                    kms,
                    params,
                )
                .await?;
            }
            PrivateKey => {
                //add this key to the ids to skip
                ids_to_skip.insert(owm.id.clone());
                // for Covercrypt, if that is a master secret key, revoke the user decryption keys
                if let KeyFormatType::CoverCryptSecretKey = owm.object.key_block()?.key_format_type
                {
                    revoke_user_decryption_keys(
                        &owm.id,
                        revocation_reason.clone(),
                        compromise_occurrence_date,
                        kms,
                        user,
                        params,
                        ids_to_skip.clone(),
                    )
                    .await?
                }
                // revoke any linked public key
                if let Some(public_key_id) =
                    owm.object.attributes()?.get_link(LinkType::PublicKeyLink)
                {
                    if !ids_to_skip.contains(&public_key_id) {
                        recursively_revoke_key(
                            &public_key_id,
                            revocation_reason.clone(),
                            compromise_occurrence_date,
                            kms,
                            user,
                            params,
                            ids_to_skip.clone(),
                        )
                        .await?;
                    }
                }
                // now revoke the private key
                revoke_key_core(
                    &owm.id,
                    revocation_reason.clone(),
                    compromise_occurrence_date,
                    kms,
                    params,
                )
                .await?;
            }
            PublicKey => {
                //add this key to the ids to skip
                ids_to_skip.insert(owm.id.clone());
                // revoke any linked private key
                if let Some(private_key_id) =
                    owm.object.attributes()?.get_link(LinkType::PrivateKeyLink)
                {
                    if !ids_to_skip.contains(&private_key_id) {
                        recursively_revoke_key(
                            &private_key_id,
                            revocation_reason.clone(),
                            compromise_occurrence_date,
                            kms,
                            user,
                            params,
                            ids_to_skip.clone(),
                        )
                        .await?;
                    }
                }
                // revoke the public key
                revoke_key_core(
                    &owm.id,
                    revocation_reason.clone(),
                    compromise_occurrence_date,
                    kms,
                    params,
                )
                .await?;
            }
            x => kms_bail!(KmsError::NotSupported(format!(
                "revoke operation is not supported for object type {:?}",
                x
            ))),
        };
    }

    Ok(())
}

/// Revoke a key, knowing the object and state
#[allow(clippy::too_many_arguments)]
async fn revoke_key_core(
    unique_identifier: &str,
    revocation_reason: RevocationReason,
    compromise_occurrence_date: Option<u64>,
    kms: &KMS,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
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

    Ok(())
}
/*













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
*/
