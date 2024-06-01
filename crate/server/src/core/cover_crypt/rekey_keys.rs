use cloudproof::reexport::cover_crypt::{
    abe_policy::Policy, Covercrypt, MasterPublicKey, MasterSecretKey,
};
use cosmian_kmip::{
    crypto::cover_crypt::{
        attributes::{deserialize_access_policy, policy_from_attributes, RekeyEditAction},
        master_keys::{
            covercrypt_keys_from_kmip_objects, kmip_objects_from_covercrypt_keys, KmipKeyUidObject,
        },
        user_key::UserDecryptionKeysHandler,
    },
    kmip::{
        kmip_objects::{Object, ObjectType},
        kmip_operations::{ErrorReason, Get, Import, ReKeyKeyPairResponse},
        kmip_types::{LinkType, StateEnumeration, UniqueIdentifier},
    },
};
use cosmian_kms_server_database::ExtraStoreParams;
use tracing::trace;

use super::KMS;
use crate::{
    core::cover_crypt::locate_user_decryption_keys, error::KmsError, kms_bail, result::KResult,
};

/// KMIP `Re_key` for `CoverCrypt` master keys can be one of these actions:
///
/// - `RekeyAccessPolicy`: Generate new keys for the given access policy.
/// - `PruneAccessPolicy`: Remove old keys associated to an access policy.
/// - `RemoveAttribute`: Remove attributes from the policy.
/// - `DisableAttribute`: Disable attributes in the policy.
/// - `AddAttribute`: Add new attributes to the policy.
/// - `RenameAttribute`: Rename attributes in the policy.
pub(crate) async fn rekey_keypair_cover_crypt(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    msk_uid: String,
    owner: &str,
    action: RekeyEditAction,
    params: Option<&ExtraStoreParams>,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("Internal rekey key pair CoverCrypt");

    let (msk_uid, mpk_uid) = match action {
        RekeyEditAction::RekeyAccessPolicy(ap) => {
            let (msk_obj, mpk_obj) =
                update_master_keys(kmip_server, owner, params, msk_uid, |policy, msk, mpk| {
                    let ap = deserialize_access_policy(&ap)?;
                    cover_crypt.rekey_master_keys(&ap, policy, msk, mpk)?;
                    Ok(())
                })
                .await?;

            update_all_active_usk(kmip_server, cover_crypt, &msk_obj, owner, params).await?;

            (msk_obj.0, mpk_obj.0)
        }
        RekeyEditAction::PruneAccessPolicy(ap) => {
            let (msk_obj, mpk_obj) =
                update_master_keys(kmip_server, owner, params, msk_uid, |policy, msk, _mpk| {
                    let ap = deserialize_access_policy(&ap)?;
                    cover_crypt.prune_master_secret_key(&ap, policy, msk)?;
                    Ok(())
                })
                .await?;

            update_all_active_usk(kmip_server, cover_crypt, &msk_obj, owner, params).await?;

            (msk_obj.0, mpk_obj.0)
        }
        RekeyEditAction::RemoveAttribute(attrs) => {
            let (msk_obj, mpk_obj) =
                update_master_keys(kmip_server, owner, params, msk_uid, |policy, msk, mpk| {
                    attrs
                        .iter()
                        .try_for_each(|attr| policy.remove_attribute(attr))?;
                    cover_crypt.update_master_keys(policy, msk, mpk)?;
                    Ok(())
                })
                .await?;

            update_all_active_usk(kmip_server, cover_crypt, &msk_obj, owner, params).await?;

            (msk_obj.0, mpk_obj.0)
        }
        RekeyEditAction::DisableAttribute(attrs) => {
            let (msk_obj, mpk_obj) =
                update_master_keys(kmip_server, owner, params, msk_uid, |policy, msk, mpk| {
                    attrs
                        .iter()
                        .try_for_each(|attr| policy.disable_attribute(attr))?;
                    cover_crypt.update_master_keys(policy, msk, mpk)?;
                    Ok(())
                })
                .await?;

            (msk_obj.0, mpk_obj.0)
        }
        RekeyEditAction::RenameAttribute(pairs_attr_name) => {
            let (msk_obj, mpk_obj) =
                update_master_keys(kmip_server, owner, params, msk_uid, |policy, msk, mpk| {
                    pairs_attr_name.iter().try_for_each(|(attr, new_name)| {
                        policy.rename_attribute(attr, new_name.clone())
                    })?;
                    cover_crypt.update_master_keys(policy, msk, mpk)?;
                    Ok(())
                })
                .await?;
            (msk_obj.0, mpk_obj.0)
        }
        RekeyEditAction::AddAttribute(attrs_properties) => {
            let (msk_obj, mpk_obj) =
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

            (msk_obj.0, mpk_obj.0)
        }
    };

    Ok(ReKeyKeyPairResponse {
        private_key_unique_identifier: UniqueIdentifier::TextString(msk_uid),
        public_key_unique_identifier: UniqueIdentifier::TextString(mpk_uid),
    })
}

/// Updates the key-pair associated to the MSK which ID is given using the given mutator, and
/// replaces the stored key-pair with the mutated one.
pub(crate) async fn update_master_keys(
    server: &KMS,
    owner: &str,
    params: Option<&ExtraStoreParams>,
    msk_uid: String,
    mutator: impl Fn(&mut Policy, &mut MasterSecretKey, &mut MasterPublicKey) -> KResult<()>,
) -> KResult<((String, Object), (String, Object))> {
    let (msk_obj, mpk_obj, mut policy) =
        get_master_keys_and_policy(server, msk_uid, owner, params).await?;

    let (mut msk, mut mpk) = covercrypt_keys_from_kmip_objects(&msk_obj.1, &mpk_obj.1)?;
    mutator(&mut policy, &mut msk, &mut mpk)?;
    let (msk_obj, mpk_obj) =
        kmip_objects_from_covercrypt_keys(&policy, &msk, &mpk, msk_obj, mpk_obj)?;

    import_rekeyed_master_keys(server, owner, params, msk_obj.clone(), mpk_obj.clone()).await?;

    Ok((msk_obj, mpk_obj))
}

async fn get_master_keys_and_policy(
    kmip_server: &KMS,
    msk_uid: String,
    owner: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<(KmipKeyUidObject, KmipKeyUidObject, Policy)> {
    // Recover the master private key
    let msk = kmip_server
        .get(Get::from(&msk_uid), owner, params)
        .await?
        .object;

    if msk.key_wrapping_data().is_some() {
        kms_bail!(KmsError::InconsistentOperation(
            "The server can't rekey: the key is wrapped".to_owned()
        ));
    }

    // Get policy associated with the master private key
    let private_key_attributes = msk.attributes()?;
    let policy = policy_from_attributes(private_key_attributes)?;

    // Recover the Master Public Key
    let Object::PrivateKey { key_block } = &msk else {
        return Err(KmsError::KmipError(
            ErrorReason::Invalid_Object_Type,
            "KmsError::KmipErrorIP Private Key".to_owned(),
        ))
    };

    let mpk_uid = key_block
        .get_linked_object_id(LinkType::PublicKeyLink)?
        .ok_or_else(|| {
            KmsError::KmipError(
                ErrorReason::Invalid_Object_Type,
                "Private key MUST contain a public key link".to_owned(),
            )
        })?;

    let mpk = kmip_server
        .get(Get::from(mpk_uid.clone()), owner, params)
        .await?
        .object;

    Ok(((msk_uid, msk), (mpk_uid, mpk), policy))
}

/// Import the updated master keys in place of the old ones in the KMS
async fn import_rekeyed_master_keys(
    kmip_server: &KMS,
    owner: &str,
    params: Option<&ExtraStoreParams>,
    msk: KmipKeyUidObject,
    mpk: KmipKeyUidObject,
) -> KResult<()> {
    // re-import master secret key
    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString(msk.0),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: msk.1.attributes()?.clone(),
        object: msk.1,
    };
    let _import_response = kmip_server.import(import_request, owner, params).await?;

    // re-import master public key
    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString(mpk.0),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: mpk.1.attributes()?.clone(),
        object: mpk.1,
    };
    let _import_response = kmip_server.import(import_request, owner, params).await?;

    Ok(())
}

/// Updates user secret keys for actions like rekeying or pruning.
async fn update_all_active_usk(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    msk_obj: &KmipKeyUidObject,
    owner: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<()> {
    // Search the user decryption keys that need to be refreshed
    let locate_response = locate_user_decryption_keys(
        kmip_server,
        &msk_obj.0,
        None,
        Some(StateEnumeration::Active),
        owner,
        params,
    )
    .await?;

    // Refresh the User Decryption Key that were found
    if let Some(unique_identifiers) = &locate_response {
        //instantiate a CoverCrypt User Key Handler
        let handler = UserDecryptionKeysHandler::instantiate(cover_crypt, &msk_obj.1)?;

        // Renew user decryption key previously found
        for user_decryption_key_uid in unique_identifiers {
            update_usk(
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

/// Refresh an individual user secret key with a given handler to a master secret key
async fn update_usk(
    handler: &UserDecryptionKeysHandler,
    user_decryption_key_uid: &str,
    kmip_server: &KMS,
    owner: &str,
    params: Option<&ExtraStoreParams>,
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
