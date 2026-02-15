use std::ops::AsyncFn;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, State},
        kmip_2_1::{
            kmip_objects::{Object, ObjectType},
            kmip_operations::{Get, Import, ReKeyKeyPairResponse},
            kmip_types::{LinkType, UniqueIdentifier},
        },
    },
    cosmian_kms_crypto::{
        crypto::cover_crypt::{
            attributes::RekeyEditAction,
            master_keys::{
                KmipKeyUidObject, cc_master_keypair_from_kmip_objects,
                kmip_objects_from_cc_master_keypair,
            },
            user_key::UserDecryptionKeysHandler,
        },
        reexport::cosmian_cover_crypt::{
            AccessPolicy, MasterPublicKey, MasterSecretKey, api::Covercrypt,
        },
    },
};
use cosmian_logger::trace;

use super::KMS;
use crate::{core::cover_crypt::locate_usk, error::KmsError, kms_bail, result::KResult};

/// KMIP `ReKey` for `CoverCrypt` master keys can be one of these actions:
///
/// - `RekeyAccessPolicy`: Generate new keys for the given access policy.
/// - `PruneAccessPolicy`: Remove old keys associated to an access policy.
/// - `RemoveAttribute`: Remove attributes from the access structure.
/// - `DisableAttribute`: Disable attributes in the access structure.
/// - `AddAttribute`: Add new attributes to the access structure.
/// - `RenameAttribute`: Rename attributes in the access structure.
#[expect(clippy::large_futures)]
pub(crate) async fn rekey_keypair_cover_crypt(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    msk_uid: String,
    owner: &str,
    action: RekeyEditAction,
    _sensitive: bool,
    privileged_users: Option<Vec<String>>,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("Internal rekey key pair Covercrypt");
    let mpk_uid = match action {
        RekeyEditAction::RekeyAccessPolicy(access_policy) => {
            update_master_keys(
                kmip_server,
                owner,
                &msk_uid,
                async |msk, mpk| {
                    let ap = AccessPolicy::parse(&access_policy)?;
                    *mpk = cover_crypt.rekey(msk, &ap)?;
                    update_all_active_usk(
                        kmip_server,
                        &cover_crypt,
                        &msk_uid,
                        msk,
                        owner,
                        &privileged_users,
                    )
                    .await?;
                    Ok(())
                },
                &privileged_users,
            )
            .await?
        }
        RekeyEditAction::PruneAccessPolicy(access_policy) => {
            update_master_keys(
                kmip_server,
                owner,
                &msk_uid,
                async |msk, _mpk| {
                    let ap = AccessPolicy::parse(&access_policy)?;
                    cover_crypt.prune_master_secret_key(msk, &ap)?;
                    update_all_active_usk(
                        kmip_server,
                        &cover_crypt,
                        &msk_uid,
                        msk,
                        owner,
                        &privileged_users,
                    )
                    .await?;
                    Ok(())
                },
                &privileged_users,
            )
            .await?
        }
        RekeyEditAction::DeleteAttribute(attrs) => {
            update_master_keys(
                kmip_server,
                owner,
                &msk_uid,
                async |msk, mpk| {
                    attrs
                        .iter()
                        .try_for_each(|attr| msk.access_structure.del_attribute(attr))?;
                    *mpk = cover_crypt.update_msk(msk)?;
                    update_all_active_usk(
                        kmip_server,
                        &cover_crypt,
                        &msk_uid,
                        msk,
                        owner,
                        &privileged_users,
                    )
                    .await?;
                    Ok(())
                },
                &privileged_users,
            )
            .await?
        }
        RekeyEditAction::DisableAttribute(attrs) => {
            update_master_keys(
                kmip_server,
                owner,
                &msk_uid,
                async |msk, mpk| {
                    attrs
                        .iter()
                        .try_for_each(|attr| msk.access_structure.disable_attribute(attr))?;
                    *mpk = cover_crypt.update_msk(msk)?;
                    Ok(())
                },
                &privileged_users,
            )
            .await?
        }
        RekeyEditAction::RenameAttribute(pairs_attr_name) => {
            update_master_keys(
                kmip_server,
                owner,
                &msk_uid,
                async |msk, mpk| {
                    pairs_attr_name
                        .iter()
                        .try_for_each(|(ap_attributes, new_name)| {
                            msk.access_structure
                                .rename_attribute(ap_attributes, new_name.clone())
                        })?;
                    *mpk = cover_crypt.update_msk(msk)?;
                    Ok(())
                },
                &privileged_users,
            )
            .await?
        }
        RekeyEditAction::AddAttribute(attrs_properties) => {
            update_master_keys(
                kmip_server,
                owner,
                &msk_uid,
                async |msk, mpk| {
                    attrs_properties
                        .iter()
                        .try_for_each(|(attr, encryption_hint, _after)| {
                            msk.access_structure
                                .add_attribute(attr.clone(), *encryption_hint, None)
                        })?;
                    *mpk = cover_crypt.update_msk(msk)?;
                    Ok(())
                },
                &privileged_users,
            )
            .await?
        }
    };

    Ok(ReKeyKeyPairResponse {
        private_key_unique_identifier: UniqueIdentifier::TextString(msk_uid),
        public_key_unique_identifier: UniqueIdentifier::TextString(mpk_uid),
    })
}

/// Updates the key-pair associated to the MSK which UID is given using the
/// given mutator, and replaces the stored key-pair with the mutated
/// one. Returns the associated MPK UID.
pub(super) async fn update_master_keys(
    server: &KMS,
    owner: &str,
    msk_uid: &String,
    mutator: impl AsyncFn(&mut MasterSecretKey, &mut MasterPublicKey) -> KResult<()>,
    privileged_users: &Option<Vec<String>>,
) -> KResult<String> {
    let (msk_obj, (mpk_uid, mpk_obj)) = get_master_keys(server, msk_uid, owner).await?;

    let (mut msk, mut mpk) = cc_master_keypair_from_kmip_objects(&msk_obj, &mpk_obj)?;

    mutator(&mut msk, &mut mpk).await?;

    let (msk_obj, mpk_obj) = kmip_objects_from_cc_master_keypair(&msk, &mpk, msk_obj, mpk_obj)?;

    import_rekeyed_master_keys(
        server,
        owner,
        (msk_uid.clone(), msk_obj),
        (mpk_uid.clone(), mpk_obj),
        privileged_users,
    )
    .await?;

    Ok(mpk_uid)
}

async fn get_master_keys(
    kmip_server: &KMS,
    msk_uid: &String,
    owner: &str,
) -> KResult<(Object, KmipKeyUidObject)> {
    let msk_obj = kmip_server.get(Get::from(msk_uid), owner).await?.object;

    if msk_obj.key_wrapping_data().is_some() {
        kms_bail!(KmsError::InconsistentOperation(
            "The server can't rekey: the key is wrapped".to_owned()
        ));
    }

    let mpk_uid = msk_obj
        .key_block()?
        .get_linked_object_id(LinkType::PublicKeyLink)?
        .ok_or_else(|| {
            KmsError::Kmip21Error(
                ErrorReason::Invalid_Object_Type,
                "Private key MUST contain a public key link".to_owned(),
            )
        })?;

    let mpk_obj = kmip_server.get(Get::from(&mpk_uid), owner).await?.object;

    Ok((msk_obj, (mpk_uid, mpk_obj)))
}

/// Import the updated master keys in place of the old ones in the KMS
async fn import_rekeyed_master_keys(
    kmip_server: &KMS,
    owner: &str,
    msk: KmipKeyUidObject,
    mpk: KmipKeyUidObject,
    privileged_users: &Option<Vec<String>>,
) -> KResult<()> {
    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString(msk.0),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: msk.1.attributes()?.clone(),
        object: msk.1,
    };

    kmip_server
        .import(import_request, owner, privileged_users.clone())
        .await?;

    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString(mpk.0),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: mpk.1.attributes()?.clone(),
        object: mpk.1,
    };

    kmip_server
        .import(import_request, owner, privileged_users.clone())
        .await?;

    Ok(())
}

/// Updates user secret keys for actions like rekeying or pruning.
async fn update_all_active_usk(
    kmip_server: &KMS,
    cover_crypt: &Covercrypt,
    msk_uid: &str,
    msk: &mut MasterSecretKey,
    owner: &str,
    privileged_users: &Option<Vec<String>>,
) -> KResult<()> {
    let res = locate_usk(kmip_server, msk_uid, None, Some(State::Active), owner).await?;

    if let Some(uids) = &res {
        let mut handler = UserDecryptionKeysHandler::instantiate(cover_crypt, msk);
        for usk_uid in uids {
            update_usk(&mut handler, usk_uid, kmip_server, owner, privileged_users).await?;
        }
    }

    Ok(())
}

/// Refresh an individual USK with a given handler to a MSK.
async fn update_usk(
    handler: &mut UserDecryptionKeysHandler<'_>,
    usk_uid: &str,
    kmip_server: &KMS,
    owner: &str,
    privileged_users: &Option<Vec<String>>,
) -> KResult<()> {
    let res = kmip_server.get(Get::from(usk_uid), owner).await?;

    let usk_obj = handler.refresh_usk_object(&res.object, true)?;

    let req = Import {
        unique_identifier: res.unique_identifier,
        object_type: res.object_type,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: usk_obj
            .attributes()
            .map_err(|e| KmsError::Kmip21Error(ErrorReason::Attribute_Not_Found, e.to_string()))?
            .clone(),
        object: usk_obj,
    };

    kmip_server
        .import(req, owner, privileged_users.clone())
        .await?;

    Ok(())
}
