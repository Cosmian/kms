use cloudproof::reexport::cover_crypt::Covercrypt;
use cosmian_kmip::{
    crypto::{
        cover_crypt::{
            attributes::{access_policy_from_attributes, policy_from_attributes},
            user_key::UserDecryptionKeysHandler,
        },
        KeyPair,
    },
    kmip::{
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Create, CreateKeyPair, ErrorReason, Get},
        kmip_types::{Attributes, KeyFormatType, StateEnumeration, UniqueIdentifier},
    },
};
use cosmian_kms_client::access::ObjectOperationType;

use super::KMS;
use crate::{
    core::extra_database_params::ExtraDatabaseParams,
    database::object_with_metadata::ObjectWithMetadata, error::KmsError, kms_bail, result::KResult,
};

/// Create a User Decryption Key in the KMS
///
/// The attributes of the `Create` request must contain the
/// `Access Policy`
pub(crate) async fn create_user_decryption_key(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    create_request: &Create,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    create_user_decryption_key_(
        kmip_server,
        cover_crypt,
        &create_request.attributes,
        owner,
        params,
    )
    .await
}

async fn create_user_decryption_key_(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    create_attributes: &Attributes,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    // Recover the access policy
    let access_policy = access_policy_from_attributes(create_attributes)?;

    // Recover private key
    let msk_uid_or_tag = create_attributes
        .get_parent_id()
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "there should be a reference to the master private key in the creation attributes"
                    .to_owned(),
            )
        })?
        .to_string();

    // retrieve from tags or use passed identifier
    let mut owm_s = kmip_server
        .db
        .retrieve(&msk_uid_or_tag, user, ObjectOperationType::Get, params)
        .await?
        .into_values()
        .filter(|owm| {
            if owm.state != StateEnumeration::Active {
                return false
            }
            if owm.object.object_type() != ObjectType::PrivateKey {
                return false
            }

            let Ok(attributes) = owm.object.attributes() else {
                return false
            };

            if attributes.key_format_type != Some(KeyFormatType::CoverCryptSecretKey) {
                return false
            }
            // a master key should have policies in the attributes
            policy_from_attributes(attributes).is_ok()
        })
        .collect::<Vec<ObjectWithMetadata>>();

    // there can only be one object
    let owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::KmipError(ErrorReason::Item_Not_Found, msk_uid_or_tag.clone()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many objects for master private key {msk_uid_or_tag}",
        )))
    }

    let master_private_key = &owm.object;
    if master_private_key.key_wrapping_data().is_some() {
        kms_bail!(KmsError::InconsistentOperation(
            "The server can't create a decryption key: the master private key is wrapped"
                .to_owned()
        ));
    }

    UserDecryptionKeysHandler::instantiate(cover_crypt, master_private_key)?
        .create_user_decryption_key_object(&access_policy, Some(create_attributes), &owm.id)
        .map_err(Into::into)
}

#[allow(unused)]
//TODO: there is noway to distinguish between the creation of a user decryption key pair and a master key pair
/// Create a KMIP tuple (`Object::PrivateKey`, `Object::PublicKey`)
pub(crate) async fn create_user_decryption_key_pair(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    create_key_pair_request: &CreateKeyPair,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<KeyPair> {
    // create user decryption key
    let private_key_attributes = create_key_pair_request
        .private_key_attributes
        .as_ref()
        .or(create_key_pair_request.common_attributes.as_ref())
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "Missing private attributes in CoverCrypt Create Keypair request".to_owned(),
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
                "Missing public attributes in CoverCrypt Create Keypair request".to_owned(),
            )
        })?;
    let master_public_key_uid = public_key_attributes.get_parent_id().ok_or_else(|| {
        KmsError::InvalidRequest(
            "the master public key id should be available in the public creation attributes"
                .to_owned(),
        )
    })?;
    let gr_public_key = kmip_server
        .get(
            Get::from(UniqueIdentifier::from(master_public_key_uid)),
            owner,
            params,
        )
        .await?;

    Ok(KeyPair((private_key, gr_public_key.object)))
}
