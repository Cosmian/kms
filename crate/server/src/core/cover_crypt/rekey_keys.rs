use cloudproof::reexport::cover_crypt::{
    abe_policy::Policy, Covercrypt, MasterPublicKey, MasterSecretKey,
};
use cosmian_kmip::{
    crypto::cover_crypt::{
        attributes::{deserialize_access_policy, policy_from_attributes, RekeyEditAction},
        master_keys::{covercrypt_keys_from_kmip_objects, kmip_objects_from_covercrypt_keys},
        user_key::UserDecryptionKeysHandler,
    },
    kmip::{
        kmip_objects::{Object, ObjectType},
        kmip_operations::{ErrorReason, Get, Import, ReKeyKeyPairResponse},
        kmip_types::{LinkType, StateEnumeration, UniqueIdentifier},
    },
};
use tracing::trace;

use super::KMS;
use crate::{
    core::{cover_crypt::locate_user_decryption_keys, extra_database_params::ExtraDatabaseParams},
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// `Re_key` `CoverCrypt` master and user keys for the given action:
///
/// - `RekeyAccessPolicy`: Generate new keys for the given access policy.
/// - `PruneAccessPolicy`: Remove old keys associated to an access policy.
/// - `RemoveAttribute`: Remove attributes from the policy.
/// - `DisableAttribute`: Disable attributes in the policy.
/// - `AddAttribute`: Add new attributes to the policy.
/// - `RenameAttribute`: Rename attributes in the policy.
pub async fn rekey_keypair_cover_crypt(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    msk_uid: &str,
    owner: &str,
    action: RekeyEditAction,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("Internal rekey key pair CoverCrypt");

    let (msk_uid, mpk_uid) = match action {
        RekeyEditAction::RekeyAccessPolicy(ap) => {
            let (msk_uid, msk_object, mpk_uid) =
                update_master_keys(kmip_server, owner, params, msk_uid, |policy, msk, mpk| {
                    let ap = deserialize_access_policy(&ap)?;
                    cover_crypt.rekey_master_keys(&ap, policy, msk, mpk)?;
                    Ok(())
                })
                .await?;

            update_user_secret_keys(
                kmip_server,
                cover_crypt,
                &msk_uid,
                &msk_object,
                owner,
                params,
            )
            .await?;

            (msk_uid, mpk_uid)
        }
        RekeyEditAction::PruneAccessPolicy(ap) => {
            let (msk_uid, msk_object, mpk_uid) =
                update_master_keys(kmip_server, owner, params, msk_uid, |policy, msk, _mpk| {
                    let ap = deserialize_access_policy(&ap)?;
                    cover_crypt.prune_master_secret_key(&ap, policy, msk)?;
                    Ok(())
                })
                .await?;

            update_user_secret_keys(
                kmip_server,
                cover_crypt,
                &msk_uid,
                &msk_object,
                owner,
                params,
            )
            .await?;

            (msk_uid, mpk_uid)
        }
        RekeyEditAction::RemoveAttribute(attrs) => {
            let (msk_uid, msk_object, mpk_uid) =
                update_master_keys(kmip_server, owner, params, msk_uid, |policy, msk, mpk| {
                    attrs
                        .iter()
                        .try_for_each(|attr| policy.remove_attribute(attr))?;
                    cover_crypt.update_master_keys(policy, msk, mpk)?;
                    Ok(())
                })
                .await?;

            update_user_secret_keys(
                kmip_server,
                cover_crypt,
                &msk_uid,
                &msk_object,
                owner,
                params,
            )
            .await?;

            (msk_uid, mpk_uid)
        }
        RekeyEditAction::DisableAttribute(attrs) => {
            let (msk_uid, _, mpk_uid) =
                update_master_keys(kmip_server, owner, params, msk_uid, |policy, msk, mpk| {
                    attrs
                        .iter()
                        .try_for_each(|attr| policy.disable_attribute(attr))?;
                    cover_crypt.update_master_keys(policy, msk, mpk)?;
                    Ok(())
                })
                .await?;

            (msk_uid, mpk_uid)
        }
        RekeyEditAction::RenameAttribute(pairs_attr_name) => {
            let (msk_uid, _, mpk_uid) =
                update_master_keys(kmip_server, owner, params, msk_uid, |policy, msk, mpk| {
                    pairs_attr_name.iter().try_for_each(|(attr, new_name)| {
                        policy.rename_attribute(attr, new_name.clone())
                    })?;
                    cover_crypt.update_master_keys(policy, msk, mpk)?;
                    Ok(())
                })
                .await?;

            (msk_uid, mpk_uid)
        }
        RekeyEditAction::AddAttribute(attrs_properties) => {
            let (msk_uid, _, mpk_uid) =
                update_master_keys(kmip_server, owner, params, msk_uid, |policy, msk, mpk| {
                    attrs_properties
                        .iter()
                        .try_for_each(|(attr, encryption_hint)| {
                            policy.add_attribute(attr.clone(), *encryption_hint)
                        })?;
                    cover_crypt.update_master_keys(policy, msk, mpk)?;
                    Ok(())
                })
                .await?;

            (msk_uid, mpk_uid)
        }
    };

    Ok(ReKeyKeyPairResponse {
        private_key_unique_identifier: UniqueIdentifier::TextString(msk_uid.to_string()),
        public_key_unique_identifier: UniqueIdentifier::TextString(mpk_uid),
    })
}

/// Update the master key with a new Policy
/// (after editing the policy typically)
pub async fn update_master_keys(
    server: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
    msk_uid: &str,
    mutator: impl Fn(&mut Policy, &mut MasterSecretKey, &mut MasterPublicKey) -> KResult<()>,
) -> KResult<(String, Object, String)> {
    let (msk_object, mpk_uid, mpk_object, mut policy) =
        get_master_keys_and_policy(server, msk_uid, owner, params).await?;

    let (mut msk, mut mpk) = covercrypt_keys_from_kmip_objects(&msk_object, &mpk_object)?;
    mutator(&mut policy, &mut msk, &mut mpk)?;
    let (msk_object, mpk_object) =
        kmip_objects_from_covercrypt_keys(&policy, &msk, &msk_object, msk_uid, &mpk, msk_uid)?;

    import_rekeyed_master_keys(
        server,
        msk_uid,
        msk_object.clone(),
        &mpk_uid,
        mpk_object,
        owner,
        params,
    )
    .await?;

    Ok((msk_uid.to_string(), msk_object, mpk_uid))
}

async fn get_master_keys_and_policy(
    kmip_server: &KMS,
    master_private_key_uid: &str,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<(Object, String, Object, Policy)> {
    // Recover the master private key
    let master_private_key = kmip_server
        .get(Get::from(master_private_key_uid), owner, params)
        .await?
        .object;

    if master_private_key.key_wrapping_data().is_some() {
        kms_bail!(KmsError::InconsistentOperation(
            "The server can't rekey: the key is wrapped".to_owned()
        ));
    }

    // Get policy associated with the master private key
    let private_key_attributes = master_private_key.attributes()?;
    let policy = policy_from_attributes(private_key_attributes)?;

    // Recover the Master Public Key
    let key_block = match &master_private_key {
        Object::PrivateKey { key_block } => key_block,
        _ => {
            return Err(KmsError::KmipError(
                ErrorReason::Invalid_Object_Type,
                "KmsError::KmipErrorIP Private Key".to_owned(),
            ))
        }
    };

    let master_public_key_uid = key_block
        .get_linked_object_id(LinkType::PublicKeyLink)?
        .ok_or_else(|| {
            KmsError::KmipError(
                ErrorReason::Invalid_Object_Type,
                "Private key MUST contain a public key link".to_string(),
            )
        })?;

    let master_public_key = kmip_server
        .get(Get::from(master_public_key_uid.clone()), owner, params)
        .await?
        .object;

    Ok((
        master_private_key,
        master_public_key_uid,
        master_public_key,
        policy,
    ))
}

async fn import_rekeyed_master_keys(
    kmip_server: &KMS,
    master_private_key_uid: &str,
    updated_private_key: Object,
    master_public_key_uid: &str,
    updated_public_key: Object,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    // re_import it
    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString(master_private_key_uid.to_string()),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: updated_private_key.attributes()?.clone(),
        object: updated_private_key,
    };
    let _import_response = kmip_server.import(import_request, owner, params).await?;

    // Update Master Public Key Policy and re-import the key
    // re_import it
    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString(master_public_key_uid.to_string()),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: updated_public_key.attributes()?.clone(),
        object: updated_public_key,
    };
    let _import_response = kmip_server.import(import_request, owner, params).await?;

    Ok(())
}

/// Updates user secret keys for actions like rekeying or pruning.
async fn update_user_secret_keys(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    master_private_key_uid: &str,
    master_private_key: &Object,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    // Search the user decryption keys that need to be refreshed
    let locate_response = locate_user_decryption_keys(
        kmip_server,
        master_private_key_uid,
        None,
        Some(StateEnumeration::Active),
        owner,
        params,
    )
    .await?;

    // Refresh the User Decryption Key that were found
    if let Some(unique_identifiers) = &locate_response {
        //instantiate a CoverCrypt User Key Handler
        let handler = UserDecryptionKeysHandler::instantiate(cover_crypt, master_private_key)?;

        // Renew user decryption key previously found
        for user_decryption_key_uid in unique_identifiers {
            refresh_user_decryption_key(
                &handler,
                user_decryption_key_uid,
                kmip_server,
                owner,
                params,
            )
            .await?;
        }
    }

    Ok(())
}

async fn refresh_user_decryption_key(
    handler: &UserDecryptionKeysHandler,
    user_decryption_key_uid: &str,
    kmip_server: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    //fetch the user decryption key
    let get_response = kmip_server
        .get(Get::from(user_decryption_key_uid), owner, params)
        .await?;
    let user_decryption_key = get_response.object;

    // Generate a fresh User Decryption Key
    let updated_user_decryption_key =
        handler.refresh_user_decryption_key_object(&user_decryption_key, true)?;
    let import_request = Import {
        unique_identifier: get_response.unique_identifier,
        object_type: get_response.object_type,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: updated_user_decryption_key
            .attributes()
            .map_err(|e| KmsError::KmipError(ErrorReason::Attribute_Not_Found, e.to_string()))?
            .clone(),
        object: updated_user_decryption_key,
    };
    let _import_response = kmip_server.import(import_request, owner, params).await?;

    Ok(())
}
