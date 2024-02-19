<<<<<<< HEAD
<<<<<<< HEAD:crate/server/src/core/cover_crypt/update_keys.rs
use cloudproof::reexport::cover_crypt::{abe_policy::Policy, Covercrypt};
use cosmian_kmip::{
=======
use cloudproof::reexport::cover_crypt::Covercrypt;
=======
use cloudproof::reexport::{
    cover_crypt::{abe_policy::Policy, Covercrypt},
    crypto_core::reexport::x509_cert::request::attributes,
};
>>>>>>> 83492acd (refacto: master keys rekey)
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::{ErrorReason, Get, Import, ReKeyKeyPairResponse},
    kmip_types::{LinkType, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
>>>>>>> 2b30289a (refacto: move policy and rekey action in dedicated files):crate/server/src/core/cover_crypt/rekey_keys.rs
    crypto::cover_crypt::{
        attributes::{
            policy_from_attributes, RekeyEditAction,
            RekeyEditAction::{
                AddAttribute, DisableAttribute, PruneAccessPolicy, RekeyAccessPolicy,
                RemoveAttribute, RenameAttribute,
            },
        },
        master_keys::{update_master_keys, update_policy},
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
/// - `RekeyAccessPolicy`: Generate new keys for the given access policy.
/// - `PruneAccessPolicy`: Remove old keys associated to an access policy.
/// - `RemoveAttribute`: Remove attributes from the policy.
/// - `DisableAttribute`: Disable attributes in the policy.
/// - `AddAttribute`: Add new attributes in the policy.
/// - `RenameAttribute`: Rename attributes in the policy.
///
/// Steps:
/// - retrieve current master keys and policy
/// - update existing policy if the action requires it
/// - update master keys if the policy was updated
/// - update user keys depending on the action
pub async fn rekey_keypair_cover_crypt(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    master_private_key_uid: &str,
    owner: &str,
    action: RekeyEditAction,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("Internal rekey key pair CoverCrypt");

    let (master_private_key, master_public_key_uid, master_public_key, mut policy) =
        get_master_keys_and_policy(kmip_server, master_private_key_uid, owner, params).await?;

    update_policy(&mut policy, &action)?;

    // Rekey the master keys
    let (updated_private_key, updated_public_key) = update_master_keys(
        &cover_crypt,
        &policy,
        &action,
        &master_private_key,
        master_private_key_uid,
        &master_public_key,
        &master_public_key_uid,
    )?;

    import_rekeyed_master_keys(
        kmip_server,
        master_private_key_uid,
        updated_private_key,
        &master_public_key_uid,
        updated_public_key,
        owner,
        params,
    )
    .await?;

    if action.induce_user_keys_refreshing() {
        // Rekey the user secret keys if needed
        update_user_secret_keys(
            kmip_server,
            cover_crypt,
            master_private_key_uid,
            owner,
            params,
        )
        .await?;
    }

    Ok(ReKeyKeyPairResponse {
        private_key_unique_identifier: UniqueIdentifier::TextString(
            master_private_key_uid.to_string(),
        ),
        public_key_unique_identifier: UniqueIdentifier::TextString(master_public_key_uid),
    })
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
        // refresh the user keys
        refresh_user_decryption_keys(
            kmip_server,
            cover_crypt,
            master_private_key_uid,
            unique_identifiers,
            true, // new keys will keep access to old keys, TODO: do we want make this a parameter?
            owner,
            params,
        )
        .await?;
    }

    Ok(())
}

async fn refresh_user_decryption_keys(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    master_private_key_uid: &str,
    user_decryption_key_unique_identifiers: &[String],
    keep_old_rights: bool,
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
        let updated_user_decryption_key =
            handler.refresh_user_decryption_key_object(&user_decryption_key, keep_old_rights)?;
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
