use abe_policy::{Attribute, Policy};
use cosmian_cover_crypt::statics::CoverCryptX25519Aes256;
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::{
        Create, CreateKeyPair, ErrorReason, Get, Import, Locate, ReKeyKeyPairResponse,
    },
    kmip_types::{
        Attributes, CryptographicAlgorithm, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
    },
};
use cosmian_kms_utils::{
    crypto::cover_crypt::{
        attributes::{
            access_policy_from_attributes, attributes_as_vendor_attribute,
            attributes_from_attributes, policy_from_attributes,
        },
        master_keys::update_master_keys,
        user_key::UserDecryptionKeysHandler,
    },
    kmip_utils::public_key_unique_identifier_from_private_key,
    types::ExtraDatabaseParams,
    KeyPair,
};
use tracing::trace;

use crate::{core::crud::KmipServer, error::KmsError, kms_bail, result::KResult};

/// `Re_key` a CoverCrypt master Key for the given attributes, which in CoverCrypt terms
/// is to "revoke" the list of given attributes by increasing their value
pub(crate) async fn rekey_keypair_cover_crypt<K>(
    kmip_server: &K,
    cover_crypt: CoverCryptX25519Aes256,
    master_private_key_uid: &str,
    attributes: &Attributes,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ReKeyKeyPairResponse>
where
    K: KmipServer,
{
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

    if master_private_key.is_wrapped()? {
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
    let search_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
        key_format_type: Some(KeyFormatType::CoverCryptSecretKey),
        vendor_attributes: Some(vec![
            // cover_crypt_master_private_key_id_as_vendor_attribute(master_private_key_uid),
            attributes_as_vendor_attribute(cover_crypt_policy_attributes_to_revoke)?,
        ]),
        link: Some(vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                master_private_key_uid.to_owned(),
            ),
        }]),
        ..Attributes::new(ObjectType::PrivateKey)
    };
    let locate_request = Locate {
        attributes: search_attributes,
        ..Locate::new(ObjectType::PrivateKey)
    };
    let locate_response = kmip_server.locate(locate_request, owner, params).await?;

    // Refresh the User Decryption Key that were found
    if let Some(unique_identifiers) = &locate_response.unique_identifiers {
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
        .await?
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
        })?
    }
    trace!("The new policy is : {policy:#?}");
    Ok(policy)
}

/// Rekey the Master keys given the provided Private Master Key and Policy
/// Return the Public Mater Key Identifier
async fn rekey_master_keys<K>(
    cover_crypt: &CoverCryptX25519Aes256,
    kmip_server: &K,
    master_private_key_uid: &str,
    master_private_key: &Object,
    policy: &Policy,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<String>
where
    K: KmipServer,
{
    // Recover the Master Public Key
    let master_public_key_uid = public_key_unique_identifier_from_private_key(master_private_key)?;
    let master_public_key = kmip_server
        .get(Get::from(master_public_key_uid.clone()), owner, params)
        .await?
        .object;

    // update the master private key
    let (updated_private_key, updated_public_key) =
        update_master_keys(cover_crypt, policy, master_private_key, &master_public_key)?;

    // re_import it
    let import_request = Import {
        unique_identifier: master_private_key_uid.to_string(),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: updated_private_key.attributes()?.to_owned(),
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
        attributes: updated_public_key.attributes()?.to_owned(),
        object: updated_public_key,
    };
    let _import_response = kmip_server.import(import_request, owner, params).await?;

    Ok(master_public_key_uid)
}

async fn refresh_all_user_decryption_keys<K>(
    kmip_server: &K,
    cover_crypt: CoverCryptX25519Aes256,
    master_private_key_uid: &str,
    user_decryption_key_unique_identifiers: &[String],
    preserve_access_to_old_partitions: bool,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()>
where
    K: KmipServer,
{
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
                .to_owned(),
            object: updated_user_decryption_key,
        };
        let _import_response = kmip_server.import(import_request, owner, params).await?;
    }

    Ok(())
}

/// Create a User Decryption Key in the KMS
///
/// The attributes of the `Create` request must contain the
/// `Access Policy`
pub(crate) async fn create_user_decryption_key<K>(
    kmip_server: &K,
    cover_crypt: CoverCryptX25519Aes256,
    create_request: &Create,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object>
where
    K: KmipServer,
{
    create_user_decryption_key_(
        kmip_server,
        cover_crypt,
        &create_request.attributes,
        owner,
        params,
    )
    .await
}

async fn create_user_decryption_key_<K>(
    kmip_server: &K,
    cover_crypt: CoverCryptX25519Aes256,
    create_attributes: &Attributes,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object>
where
    K: KmipServer,
{
    // Recover the access policy
    let access_policy = access_policy_from_attributes(create_attributes)?;

    // Recover private key
    let master_private_key_uid = create_attributes.get_parent_id().ok_or_else(|| {
        KmsError::InvalidRequest(
            "there should be a reference to the master private key in the creation attributes"
                .to_string(),
        )
    })?;
    let gr_private_key = kmip_server
        .get(Get::from(master_private_key_uid.clone()), owner, params)
        .await?;
    let master_private_key = &gr_private_key.object;

    if master_private_key.is_wrapped()? {
        kms_bail!(KmsError::InconsistentOperation(
            "The server can't create a decryption key: the master private key is wrapped"
                .to_owned()
        ));
    }

    UserDecryptionKeysHandler::instantiate(cover_crypt, master_private_key)?
        .create_user_decryption_key_object(&access_policy, Some(create_attributes))
        .map_err(Into::into)
}

#[allow(unused)]
//TODO: there is noway to distinguish between the creation of a user decryption key pair and a master key pair
/// Create a KMIP tuple (`Object::PrivateKey`, `Object::PublicKey`)
pub(crate) async fn create_user_decryption_key_pair<K>(
    kmip_server: &K,
    cover_crypt: CoverCryptX25519Aes256,
    create_key_pair_request: &CreateKeyPair,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<KeyPair>
where
    K: KmipServer,
{
    // create user decryption key
    let private_key_attributes = create_key_pair_request
        .private_key_attributes
        .as_ref()
        .or(create_key_pair_request.common_attributes.as_ref())
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "Missing private attributes in CoverCrypt Create Keypair request".to_string(),
            )
        })?;
    let private_key = create_user_decryption_key_(
        kmip_server,
        cover_crypt,
        private_key_attributes,
        owner,
        params,
    )
    .await?;

    //Recover Public Key
    let public_key_attributes = create_key_pair_request
        .public_key_attributes
        .as_ref()
        .or(create_key_pair_request.common_attributes.as_ref())
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "Missing public attributes in CoverCrypt Create Keypair request".to_string(),
            )
        })?;
    let master_public_key_uid = public_key_attributes.get_parent_id().ok_or_else(|| {
        KmsError::InvalidRequest(
            "the master public key id should be available in the public creation attributes"
                .to_string(),
        )
    })?;
    let gr_public_key = kmip_server
        .get(Get::from(master_public_key_uid), owner, params)
        .await?;

    Ok(KeyPair((private_key, gr_public_key.object)))
}
