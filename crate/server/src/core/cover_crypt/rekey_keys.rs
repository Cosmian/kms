#![allow(clippy::large_stack_frames)]
use std::sync::Arc;

use cosmian_cover_crypt::{api::Covercrypt, MasterPublicKey, MasterSecretKey};
use cosmian_kmip::kmip_2_1::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::{ErrorReason, Get, Import, ReKeyKeyPairResponse},
    kmip_types::{LinkType, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_crypto::crypto::cover_crypt::{
    attributes::{deserialize_access_policy, RekeyEditAction},
    master_keys::{
        covercrypt_keys_from_kmip_objects, kmip_objects_from_covercrypt_keys, KmipKeyUidObject,
    },
    user_key::UserDecryptionKeysHandler,
};
use cosmian_kms_interfaces::SessionParams;
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
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("Internal rekey key pair Covercrypt");
    let (msk_uid, mpk_uid) = match action {
        RekeyEditAction::RekeyAccessPolicy(access_policy) => {
            let res = Box::pin(update_master_keys(
                kmip_server,
                owner,
                params.clone(),
                msk_uid,
                |msk, _mpk| {
                    let ap = deserialize_access_policy(&access_policy)?;
                    trace!("rekey_keypair_cover_crypt: access_policy: {access_policy}");
                    cover_crypt.rekey(msk, &ap)?;
                    Ok(())
                },
            ))
            .await?;
            let (msk_obj, mpk_obj) = res;

            update_all_active_usk(kmip_server, cover_crypt, &msk_obj, owner, params.clone())
                .await?;

            (msk_obj.0, mpk_obj.0)
        }
        RekeyEditAction::PruneAccessPolicy(access_policy) => {
            let res = Box::pin(update_master_keys(
                kmip_server,
                owner,
                params.clone(),
                msk_uid,
                |msk, _mpk| {
                    let ap = deserialize_access_policy(&access_policy)?;
                    cover_crypt.prune_master_secret_key(msk, &ap)?;
                    Ok(())
                },
            ))
            .await?;
            let (msk_obj, mpk_obj) = res;

            update_all_active_usk(kmip_server, cover_crypt, &msk_obj, owner, params.clone())
                .await?;

            (msk_obj.0, mpk_obj.0)
        }
        RekeyEditAction::DeleteAttribute(attrs) => {
            let res = Box::pin(update_master_keys(
                kmip_server,
                owner,
                params.clone(),
                msk_uid,
                |msk, _mpk| {
                    drop(
                        attrs
                            .iter()
                            .try_for_each(|attr| msk.access_structure.del_attribute(attr)),
                    );
                    cover_crypt.update_msk(msk)?;
                    Ok(())
                },
            ))
            .await?;
            let (msk_obj, mpk_obj) = res;

            update_all_active_usk(kmip_server, cover_crypt, &msk_obj, owner, params).await?;

            (msk_obj.0, mpk_obj.0)
        }
        RekeyEditAction::DisableAttribute(attrs) => {
            let res = Box::pin(update_master_keys(
                kmip_server,
                owner,
                params,
                msk_uid,
                |msk, _mpk| {
                    drop(
                        attrs
                            .iter()
                            .try_for_each(|attr| msk.access_structure.disable_attribute(attr)),
                    );
                    cover_crypt.update_msk(msk)?;
                    Ok(())
                },
            ))
            .await?;
            let (msk_obj, mpk_obj) = res;

            (msk_obj.0, mpk_obj.0)
        }
        RekeyEditAction::RenameAttribute(pairs_attr_name) => {
            let res = Box::pin(update_master_keys(
                kmip_server,
                owner,
                params,
                msk_uid,
                |msk, _mpk| {
                    drop(
                        pairs_attr_name
                            .iter()
                            .try_for_each(|(ap_attributes, new_name)| {
                                msk.access_structure
                                    .rename_attribute(ap_attributes, new_name.clone())
                            }),
                    );
                    cover_crypt.update_msk(msk)?;
                    Ok(())
                },
            ))
            .await?;
            let (msk_obj, mpk_obj) = res;
            (msk_obj.0, mpk_obj.0)
        }
        RekeyEditAction::AddAttribute(attrs_properties) => {
            let res = Box::pin(update_master_keys(
                kmip_server,
                owner,
                params,
                msk_uid,
                |msk, _mpk| {
                    drop(attrs_properties.iter().try_for_each(
                        |(attr, encryption_hint, _after)| {
                            msk.access_structure
                                .add_attribute(attr.clone(), *encryption_hint, None)
                        },
                    ));
                    cover_crypt.update_msk(msk)?;
                    Ok(())
                },
            ))
            .await?;
            let (msk_obj, mpk_obj) = res;

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
    params: Option<Arc<dyn SessionParams>>,
    msk_uid: String,
    mutator: impl Fn(&mut MasterSecretKey, &mut MasterPublicKey) -> KResult<()>,
) -> KResult<((String, Object), (String, Object))> {
    trace!("update_master_keys: msk_uid: {msk_uid}");
    let (msk_obj, mpk_obj) = get_master_keys(server, msk_uid, owner, params.clone()).await?;
    trace!("update_master_keys: get_master_keys OK");

    let (mut msk, mut mpk) = covercrypt_keys_from_kmip_objects(&msk_obj.1, &mpk_obj.1)?;
    trace!("update_master_keys: covercrypt_keys_from_kmip_objects OK");
    mutator(&mut msk, &mut mpk)?;
    trace!("update_master_keys: mutator OK");
    let (msk_obj, mpk_obj) = kmip_objects_from_covercrypt_keys(&msk, &mpk, msk_obj, mpk_obj)?;
    trace!("update_master_keys: kmip_objects_from_covercrypt_keys OK");

    import_rekeyed_master_keys(server, owner, params, msk_obj.clone(), mpk_obj.clone()).await?;
    trace!("update_master_keys: import_rekeyed_master_keys OK");

    Ok((msk_obj, mpk_obj))
}

async fn get_master_keys(
    kmip_server: &KMS,
    msk_uid: String,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<(KmipKeyUidObject, KmipKeyUidObject)> {
    // Recover the master private key
    let msk = kmip_server
        .get(Get::from(&msk_uid), owner, params.clone())
        .await?
        .object;

    if msk.key_wrapping_data().is_some() {
        kms_bail!(KmsError::InconsistentOperation(
            "The server can't rekey: the key is wrapped".to_owned()
        ));
    }

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

    Ok(((msk_uid, msk), (mpk_uid, mpk)))
}

/// Import the updated master keys in place of the old ones in the KMS
async fn import_rekeyed_master_keys(
    kmip_server: &KMS,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
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
    let _import_response = kmip_server
        .import(import_request, owner, params.clone())
        .await?;

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
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<()> {
    // Search the user decryption keys that need to be refreshed
    let locate_response = locate_user_decryption_keys(
        kmip_server,
        &msk_obj.0,
        None,
        Some(StateEnumeration::Active),
        owner,
        params.clone(),
    )
    .await?;

    // Refresh the User Decryption Key that were found
    if let Some(unique_identifiers) = &locate_response {
        //instantiate a CoverCrypt User Key Handler
        let handler = &mut UserDecryptionKeysHandler::instantiate(cover_crypt, &msk_obj.1)?;

        // Renew user decryption key previously found
        for user_decryption_key_uid in unique_identifiers {
            update_usk(
                handler,
                user_decryption_key_uid,
                kmip_server,
                owner,
                params.clone(),
            )
            .await?;
        }
    }

    Ok(())
}

/// Refresh an individual user secret key with a given handler to a master secret key
async fn update_usk(
    handler: &mut UserDecryptionKeysHandler,
    user_decryption_key_uid: &str,
    kmip_server: &KMS,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<()> {
    //fetch the user decryption key
    let get_response = kmip_server
        .get(Get::from(user_decryption_key_uid), owner, params.clone())
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
