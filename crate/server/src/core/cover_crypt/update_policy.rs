use cloudproof::reexport::cover_crypt::{abe_policy::Policy, Covercrypt};
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::{ErrorReason, Get, Import, ReKeyKeyPairResponse},
    kmip_types::{LinkType, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_crypto::cover_crypt::{
    attributes::{policy_from_attributes, EditPolicyAction},
    master_keys::update_master_keys,
    user_key::UserDecryptionKeysHandler,
};
use cosmian_kms_utils::access::ExtraDatabaseParams;
use tracing::trace;

use super::KMS;
use crate::{
    core::cover_crypt::locate_user_decryption_keys, error::KmsError, kms_bail, result::KResult,
};

/// `Re_key` a `CoverCrypt` master Key for the given attributes, which in `CoverCrypt` terms
/// is to "revoke" the list of given attributes by increasing their value
pub async fn rekey_keypair_cover_crypt(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    master_private_key_uid: &str,
    owner: &str,
    action: EditPolicyAction,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("Internal rekey key pair CoverCrypt");

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

    // Edit the policy according to the requested action
    let private_key_attributes = master_private_key.attributes()?;
    let mut policy = policy_from_attributes(private_key_attributes)?;
    update_policy(&action, &mut policy)?;

    // Rekey the master keys
    let master_public_key_uid = rekey_master_keys(
        &cover_crypt,
        kmip_server,
        master_private_key_uid,
        &master_private_key,
        &policy,
        owner,
        params,
    )
    .await?;

    // Rekey the user secret keys if needed
    locate_update_user_secret_keys(
        action,
        kmip_server,
        cover_crypt,
        master_private_key_uid,
        owner,
        params,
    )
    .await?;

    Ok(ReKeyKeyPairResponse {
        private_key_unique_identifier: UniqueIdentifier::TextString(
            master_private_key_uid.to_string(),
        ),
        public_key_unique_identifier: UniqueIdentifier::TextString(master_public_key_uid),
    })
}

/// Update a Covercrypt policy based on the specified action.
///
/// # Parameters
///
/// - `action`: An `EditPolicyAction` enum.
/// - `policy`: the master private key Policy.
fn update_policy(action: &EditPolicyAction, policy: &mut Policy) -> KResult<()> {
    match action {
        EditPolicyAction::RotateAttributes(attrs) => {
            attrs.iter().try_for_each(|attr| policy.rotate(attr))
        }
        EditPolicyAction::ClearOldAttributeValues(attrs) => attrs
            .iter()
            .try_for_each(|attr| policy.clear_old_attribute_values(attr)),
        EditPolicyAction::RemoveAttribute(attrs) => attrs
            .iter()
            .try_for_each(|attr| policy.remove_attribute(attr)), // TODO: revoke existing keys with deleted attribute?)
        EditPolicyAction::DisableAttribute(attrs) => attrs
            .iter()
            .try_for_each(|attr| policy.disable_attribute(attr)),
        EditPolicyAction::RenameAttribute(pairs_attr_name) => pairs_attr_name
            .iter()
            .try_for_each(|(attr, new_name)| policy.rename_attribute(attr, new_name)), // TODO: rename attributes in existing AccessPolicy
        EditPolicyAction::AddAttribute(attrs_properties) => {
            attrs_properties
                .iter()
                .try_for_each(|(attr, encryption_hint)| {
                    policy.add_attribute(attr.clone(), *encryption_hint)
                })
        }
    }
    .map_err(|e| {
        KmsError::KmipError(
            ErrorReason::Unsupported_Cryptographic_Parameters,
            e.to_string(),
        )
    })?;

    trace!("The new policy is : {policy:#?}");
    //Ok(attributes_to_update)
    Ok(())
}

/// Rekey the Master keys given the provided Private Master Key and Policy
/// Return the Public Mater Key Identifier
async fn rekey_master_keys(
    cover_crypt: &Covercrypt,
    kmip_server: &KMS,
    master_private_key_uid: &str,
    master_private_key: &Object,
    policy: &Policy,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<String> {
    // Recover the Master Public Key
    let key_block = match master_private_key {
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

    // update the master private key
    let (updated_private_key, updated_public_key) = update_master_keys(
        cover_crypt,
        policy,
        master_private_key,
        master_private_key_uid,
        &master_public_key,
        &master_public_key_uid,
    )?;

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
        unique_identifier: UniqueIdentifier::TextString(master_public_key_uid.clone()),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: updated_public_key.attributes()?.clone(),
        object: updated_public_key,
    };
    let _import_response = kmip_server.import(import_request, owner, params).await?;

    Ok(master_public_key_uid)
}

/// Updates user secret keys if the action requires it. For actions like attribute rotation or
/// clearing old attribute values, it identifies which attributes need updates and locates
/// the corresponding user decryption keys to refresh them accordingly.
async fn locate_update_user_secret_keys(
    action: EditPolicyAction,
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    master_private_key_uid: &str,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    // Get attributes to update in existing usk
    let attributes_usk_to_update = match action {
        EditPolicyAction::RotateAttributes(attrs) => Some(attrs),
        EditPolicyAction::ClearOldAttributeValues(attrs) => Some(attrs),
        _ => None, // no need to update existing usk
    };
    if let Some(attrs) = attributes_usk_to_update {
        // Search the user decryption keys that need to be refreshed
        let locate_response = locate_user_decryption_keys(
            kmip_server,
            master_private_key_uid,
            Some(attrs),
            Some(StateEnumeration::Active),
            owner,
            params,
        )
        .await?;

        // Refresh the User Decryption Key that were found
        if let Some(unique_identifiers) = &locate_response {
            // refresh the user keys
            refresh_user_decryption_keys(
                kmip_server,
                cover_crypt,
                master_private_key_uid,
                unique_identifiers,
                true, // new keys will get access to previous rotations, TODO: do we want make this a parameter ?
                owner,
                params,
            )
            .await?;
        }
    }
    Ok(())
}

async fn refresh_user_decryption_keys(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    master_private_key_uid: &str,
    user_decryption_key_unique_identifiers: &[String],
    preserve_access_to_old_partitions: bool,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    trace!(
        "Rekeying the following user decryption keys: {user_decryption_key_unique_identifiers:?}"
    );

    // Recover the updated master private key
    let master_private_key = kmip_server
        .get(Get::from(master_private_key_uid), owner, params)
        .await?
        .object;

    //instantiate a CoverCrypt User Key Handler
    let handler = UserDecryptionKeysHandler::instantiate(cover_crypt, &master_private_key)?;

    // Renew user decryption key previously found
    for user_decryption_key_unique_identifier in user_decryption_key_unique_identifiers {
        //fetch the user decryption key
        let get_response = kmip_server
            .get(
                Get::from(user_decryption_key_unique_identifier),
                owner,
                params,
            )
            .await?;
        let user_decryption_key = get_response.object;

        // Generate a fresh User Decryption Key
        let updated_user_decryption_key = handler.refresh_user_decryption_key_object(
            &user_decryption_key,
            preserve_access_to_old_partitions,
        )?;
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
    }

    Ok(())
}
