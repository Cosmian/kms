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
        kmip_operations::{Create, CreateKeyPair, Get},
        kmip_types::{Attributes, KeyFormatType, StateEnumeration, UniqueIdentifier},
    },
};
use cosmian_kms_server_database::ExtraStoreParams;

use super::KMS;
use crate::{error::KmsError, kms_bail, result::KResult};

/// Create a User Decryption Key in the KMS
///
/// The attributes of the `Create` request must contain the
/// `Access Policy`
pub(crate) async fn create_user_decryption_key(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    create_request: &Create,
    owner: &str,
    params: Option<&ExtraStoreParams>,
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
    kms: &KMS,
    cover_crypt: Covercrypt,
    create_attributes: &Attributes,
    _user: &str,
    params: Option<&ExtraStoreParams>,
) -> KResult<Object> {
    // Recover the access policy
    let access_policy = access_policy_from_attributes(create_attributes)?;

    // Recover private key
    let msk_uid_or_tags = create_attributes
        .get_parent_id()
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "there should be a reference to the master private key in the creation attributes"
                    .to_owned(),
            )
        })?
        .to_string();

    // retrieve from tags or use passed identifier
    for owm in kms
        .database
        .retrieve_objects(&msk_uid_or_tags, params)
        .await?
        .values()
    {
        if owm.state() != StateEnumeration::Active {
            continue;
        }

        if owm.object().object_type() != ObjectType::PrivateKey {
            continue
        }

        // The master key should have attributes
        let Ok(attributes) = owm.object().attributes() else {
            continue;
        };

        // The master key should be a CoverCrypt secret key
        if attributes.key_format_type != Some(KeyFormatType::CoverCryptSecretKey) {
            continue;
        }
        // a master key should have policies in the attributes
        if policy_from_attributes(attributes).is_err() {
            continue;
        }

        let master_private_key = owm.object();
        if master_private_key.key_wrapping_data().is_some() {
            kms_bail!(KmsError::InconsistentOperation(
                "The server can't create a decryption key: the master private key is wrapped"
                    .to_owned()
            ));
        }

        return UserDecryptionKeysHandler::instantiate(cover_crypt, master_private_key)?
            .create_user_decryption_key_object(&access_policy, Some(create_attributes), owm.id())
            .map_err(Into::into)
    }

    Err(KmsError::InvalidRequest(format!(
        "get: no Covercrypt master private key found for: {msk_uid_or_tags}",
    )))
}

#[allow(unused)]
//TODO: there is noway to distinguish between the creation of a user decryption key pair and a master key pair
/// Create a KMIP tuple (`Object::PrivateKey`, `Object::PublicKey`)
pub(crate) async fn create_user_decryption_key_pair(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    create_key_pair_request: &CreateKeyPair,
    owner: &str,
    params: Option<&ExtraStoreParams>,
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
