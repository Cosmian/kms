use cloudproof::reexport::cover_crypt::{
    abe_policy::{Attribute, Policy},
    Covercrypt,
};
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::{ErrorReason, Get, Import, ReKeyKeyPairResponse},
    kmip_types::{Attributes, KeyFormatType, LinkType, StateEnumeration},
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    crypto::cover_crypt::{
        attributes::{attributes_from_attributes, policy_from_attributes},
        master_keys::update_master_keys,
        user_key::UserDecryptionKeysHandler,
    },
};
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
    attributes: &Attributes,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("Internal rekey key pair CoverCrypt");

    // Verify the operation is performed for a CoverCrypt Master Key
    let key_format_type = attributes.key_format_type.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Unable to rekey a CoverCrypt key, the format type is not specified".to_owned(),
        )
    })?;
    if key_format_type != &KeyFormatType::CoverCryptSecretKey {
        kms_bail!(KmsError::NotSupported(
            "ReKey: the format of the key must be a CoverCrypt master key".to_string()
        ))
    }

    // Determine the list of policy attributes which will be revoked (i.e. their value increased)
    let cover_crypt_policy_attributes_to_revoke = attributes_from_attributes(attributes)?;
    trace!(
        "Revoking attributes: {:?}",
        &cover_crypt_policy_attributes_to_revoke
    );

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

    // Rotate the policy
    let policy = rotate_policy(
        &master_private_key,
        &cover_crypt_policy_attributes_to_revoke,
    )?;

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

    // Search the user decryption keys that need to be refreshed
    let locate_response = locate_user_decryption_keys(
        kmip_server,
        master_private_key_uid,
        Some(cover_crypt_policy_attributes_to_revoke),
        Some(StateEnumeration::Active),
        owner,
        params,
    )
    .await?;

    // Refresh the User Decryption Key that were found
    if let Some(unique_identifiers) = &locate_response {
        // refresh the user keys
        refresh_all_user_decryption_keys(
            kmip_server,
            cover_crypt,
            master_private_key_uid,
            unique_identifiers,
            true, //TODO: do we want to conserve this or make it a parameter ?
            owner,
            params,
        )
        .await?;
    }

    Ok(ReKeyKeyPairResponse {
        private_key_unique_identifier: master_private_key_uid.to_string(),
        public_key_unique_identifier: master_public_key_uid,
    })
}

/// Rotate the policy of the given Master Private Key
/// and return it
fn rotate_policy(
    private_key: &Object,
    cover_crypt_policy_attributes_to_revoke: &[Attribute],
) -> KResult<Policy> {
    // Recover the current policy
    let private_key_attributes = private_key.attributes()?;
    let mut policy = policy_from_attributes(private_key_attributes)?;

    // Rotate the Attributes values in the Policy
    for attr in cover_crypt_policy_attributes_to_revoke {
        policy.rotate(attr).map_err(|e| {
            KmsError::KmipError(
                ErrorReason::Unsupported_Cryptographic_Parameters,
                e.to_string(),
            )
        })?;
    }
    trace!("The new policy is : {policy:#?}");
    Ok(policy)
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
        unique_identifier: master_private_key_uid.to_string(),
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
        unique_identifier: master_public_key_uid.clone(),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: updated_public_key.attributes()?.clone(),
        object: updated_public_key,
    };
    let _import_response = kmip_server.import(import_request, owner, params).await?;

    Ok(master_public_key_uid)
}

async fn refresh_all_user_decryption_keys(
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
