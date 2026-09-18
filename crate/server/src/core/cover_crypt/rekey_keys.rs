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
        reexport::cosmian_cover_crypt::{AccessPolicy, MasterSecretKey, api::Covercrypt},
    },
};
use cosmian_logger::trace;

use super::KMS;
use crate::{
    core::cover_crypt::locate_usk, error::KmsError, kms_bail, middlewares::UserId, result::KResult,
};

/// KMIP `ReKey` for `CoverCrypt` master keys can be one of these actions:
///
/// - `RekeyAccessPolicy`: Generate new keys for the given access policy.
/// - `PruneAccessPolicy`: Remove old keys associated to an access policy.
/// - `RemoveAttribute`: Remove attributes from the access structure.
/// - `DisableAttribute`: Disable attributes in the access structure.
/// - `AddAttribute`: Add new attributes to the access structure.
/// - `RenameAttribute`: Rename attributes in the access structure.
/// - `AddAnarchy`: Add a new anarchical dimension to the access structure.
/// - `AddHierarchy`: Add a new hierarchical dimension to the access structure.
pub(crate) async fn rekey_keypair_cover_crypt(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    msk_uid: String,
    owner: &UserId,
    action: RekeyEditAction,
    _sensitive: bool,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("Internal rekey key pair Covercrypt");

    let mpk_uid = match action {
        RekeyEditAction::RekeyAccessPolicy(access_policy) => {
            Box::pin(update_msk(
                kmip_server,
                owner,
                &msk_uid,
                &cover_crypt,
                |mut msk| {
                    let ap = AccessPolicy::parse(&access_policy)?;
                    drop(cover_crypt.rekey(&mut msk, &ap)?);
                    Ok(msk)
                },
            ))
            .await?
        }
        RekeyEditAction::PruneAccessPolicy(access_policy) => {
            Box::pin(update_msk(
                kmip_server,
                owner,
                &msk_uid,
                &cover_crypt,
                |mut msk| {
                    let ap = AccessPolicy::parse(&access_policy)?;
                    cover_crypt.prune_master_secret_key(&mut msk, &ap)?;

                    Ok(msk)
                },
            ))
            .await?
        }
        RekeyEditAction::DeleteAttribute(attrs) => {
            Box::pin(update_msk(
                kmip_server,
                owner,
                &msk_uid,
                &cover_crypt,
                |mut msk| {
                    attrs
                        .iter()
                        .try_for_each(|attr| msk.access_structure.del_attribute(attr))?;
                    Ok(msk)
                },
            ))
            .await?
        }
        RekeyEditAction::DisableAttribute(attrs) => {
            Box::pin(update_msk(
                kmip_server,
                owner,
                &msk_uid,
                &cover_crypt,
                |mut msk| {
                    attrs
                        .iter()
                        .try_for_each(|attr| msk.access_structure.disable_attribute(attr))?;
                    Ok(msk)
                },
            ))
            .await?
        }
        RekeyEditAction::RenameAttribute(pairs_attr_name) => {
            Box::pin(update_msk(
                kmip_server,
                owner,
                &msk_uid,
                &cover_crypt,
                |mut msk| {
                    pairs_attr_name
                        .iter()
                        .try_for_each(|(ap_attributes, new_name)| {
                            msk.access_structure
                                .rename_attribute(ap_attributes, new_name.clone())
                        })?;
                    Ok(msk)
                },
            ))
            .await?
        }
        RekeyEditAction::AddAttribute(attrs_properties) => {
            Box::pin(update_msk(
                kmip_server,
                owner,
                &msk_uid,
                &cover_crypt,
                |mut msk| {
                    attrs_properties
                        .iter()
                        .try_for_each(|(attr, hint, after)| {
                            msk.access_structure.add_attribute(
                                attr.clone(),
                                *hint,
                                after.as_deref(),
                            )
                        })?;
                    Ok(msk)
                },
            ))
            .await?
        }
        RekeyEditAction::AddAnarchy(dimension, attributes) => {
            Box::pin(update_msk(
                kmip_server,
                owner,
                &msk_uid,
                &cover_crypt,
                |mut msk| {
                    msk.access_structure.add_anarchy(dimension.clone())?;
                    attributes
                        .iter()
                        .try_for_each(|(attribute, encryption_hint)| {
                            msk.access_structure.add_attribute(
                                attribute.clone(),
                                *encryption_hint,
                                None,
                            )
                        })?;
                    Ok(msk)
                },
            ))
            .await?
        }
        RekeyEditAction::AddHierarchy(dimension, attributes) => {
            Box::pin(update_msk(
                kmip_server,
                owner,
                &msk_uid,
                &cover_crypt,
                |mut msk| {
                    msk.access_structure.add_hierarchy(dimension.clone())?;
                    let mut prev = None;
                    for (attribute, encryption_hint) in &attributes {
                        msk.access_structure.add_attribute(
                            attribute.clone(),
                            *encryption_hint,
                            prev,
                        )?;
                        prev = Some(&attribute.name);
                    }
                    Ok(msk)
                },
            ))
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
pub(super) async fn update_msk(
    server: &KMS,
    owner: &UserId,
    msk_uid: &String,
    cover_crypt: &Covercrypt,
    mutator: impl Fn(Box<MasterSecretKey>) -> KResult<Box<MasterSecretKey>>,
) -> KResult<String> {
    let (msk_obj, (mpk_uid, mpk_obj)) = get_master_keys(server, msk_uid, owner).await?;
    let (msk, _) = cc_master_keypair_from_kmip_objects(&msk_obj, &mpk_obj)?;

    let mut msk = mutator(Box::new(msk))?;
    let mpk = cover_crypt.update_msk(&mut msk)?;

    update_all_active_usk(server, cover_crypt, msk_uid, &mut msk, owner).await?;

    let (msk_obj, mpk_obj) = kmip_objects_from_cc_master_keypair(&msk, &mpk, msk_obj, mpk_obj)?;

    import_rekeyed_master_keys(
        server,
        owner,
        (msk_uid.clone(), msk_obj),
        (mpk_uid.clone(), mpk_obj),
    )
    .await?;

    Ok(mpk_uid)
}

async fn get_master_keys(
    kmip_server: &KMS,
    msk_uid: &String,
    owner: &UserId,
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
    owner: &UserId,
    msk: KmipKeyUidObject,
    mpk: KmipKeyUidObject,
) -> KResult<()> {
    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString(msk.0),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: msk.1.attributes()?.clone(),
        object: msk.1,
    };

    kmip_server.import(import_request, owner).await?;

    let import_request = Import {
        unique_identifier: UniqueIdentifier::TextString(mpk.0),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: mpk.1.attributes()?.clone(),
        object: mpk.1,
    };

    kmip_server.import(import_request, owner).await?;

    Ok(())
}

/// Updates user secret keys for actions like rekeying or pruning.
async fn update_all_active_usk(
    kmip_server: &KMS,
    cover_crypt: &Covercrypt,
    msk_uid: &str,
    msk: &mut MasterSecretKey,
    owner: &UserId,
) -> KResult<()> {
    let res = locate_usk(kmip_server, msk_uid, None, Some(State::Active), owner).await?;

    if let Some(uids) = &res {
        let mut handler = UserDecryptionKeysHandler::instantiate(cover_crypt, msk);
        for usk_uid in uids {
            update_usk(&mut handler, usk_uid, kmip_server, owner).await?;
        }
    }

    Ok(())
}

/// Refresh an individual USK with a given handler to a MSK.
async fn update_usk(
    handler: &mut UserDecryptionKeysHandler<'_>,
    usk_uid: &str,
    kmip_server: &KMS,
    owner: &UserId,
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

    kmip_server.import(req, owner).await?;

    Ok(())
}
