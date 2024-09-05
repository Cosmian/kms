use std::collections::HashSet;

use async_recursion::async_recursion;
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType::{self, PrivateKey, PublicKey, SymmetricKey},
    kmip_operations::{ErrorReason, Revoke, RevokeResponse},
    kmip_types::{
        KeyFormatType, LinkType, RevocationReason, RevocationReasonEnumeration, StateEnumeration,
        UniqueIdentifier,
    },
};
use cosmian_kms_client::access::ObjectOperationType;
use tracing::debug;

use crate::{
    core::{
        cover_crypt::revoke_user_decryption_keys, extra_database_params::ExtraDatabaseParams, KMS,
    },
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

pub(crate) async fn revoke_operation(
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
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("unique identifiers or tags should be strings")?;

    recursively_revoke_key(
        uid_or_tags,
        revocation_reason,
        compromise_occurrence_date,
        kms,
        user,
        params,
        HashSet::new(),
    )
    .await?;

    Ok(RevokeResponse {
        unique_identifier: UniqueIdentifier::TextString(uid_or_tags.to_owned()),
    })
}

/// Recursively revoke keys
#[async_recursion(?Send)]
pub(crate) async fn recursively_revoke_key(
    uid_or_tags: &str,
    revocation_reason: RevocationReason,
    compromise_occurrence_date: Option<u64>,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
    // keys that should be skipped
    mut ids_to_skip: HashSet<String>,
) -> KResult<()> {
    // retrieve from tags or use passed identifier
    let owm_s = kms
        .db
        .retrieve(uid_or_tags, user, ObjectOperationType::Revoke, params)
        .await?
        .into_values()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            (owm.state == StateEnumeration::Active || owm.state == StateEnumeration::PreActive)
                && (object_type == ObjectType::PrivateKey
                    || object_type == ObjectType::Certificate
                    || object_type == ObjectType::SymmetricKey
                    || object_type == ObjectType::PublicKey)
        })
        .collect::<Vec<ObjectWithMetadata>>();

    if owm_s.is_empty() {
        return Err(KmsError::KmipError(
            ErrorReason::Item_Not_Found,
            uid_or_tags.to_owned(),
        ))
    }

    // revoke the keys found
    for owm in owm_s {
        // perform the chain of revoke operations depending on the type of object
        let object_type = owm.object.object_type();
        match object_type {
            SymmetricKey | ObjectType::Certificate => {
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
                if owm.object.key_block()?.key_format_type == KeyFormatType::CoverCryptSecretKey {
                    revoke_user_decryption_keys(
                        &owm.id,
                        revocation_reason.clone(),
                        compromise_occurrence_date,
                        kms,
                        user,
                        params,
                        ids_to_skip.clone(),
                    )
                    .await?;
                }
                // revoke any linked public key
                if let Some(public_key_id) = owm
                    .object
                    .attributes()?
                    .get_link(LinkType::PublicKeyLink)
                    .map(|l| l.to_string())
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
                if let Some(private_key_id) = owm
                    .object
                    .attributes()?
                    .get_link(LinkType::PrivateKeyLink)
                    .map(|l| l.to_string())
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
                "revoke operation is not supported for object type {x:?}"
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

    debug!(
        "Object with unique identifier: {} revoked",
        unique_identifier
    );

    Ok(())
}
