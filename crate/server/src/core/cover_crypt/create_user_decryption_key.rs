use cloudproof::reexport::cover_crypt::statics::CoverCryptX25519Aes256;
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Create, CreateKeyPair, Get},
    kmip_types::Attributes,
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    crypto::cover_crypt::{
        attributes::access_policy_from_attributes, user_key::UserDecryptionKeysHandler,
    },
    KeyPair,
};

use super::KMS;
use crate::{error::KmsError, kms_bail, result::KResult};

/// Create a User Decryption Key in the KMS
///
/// The attributes of the `Create` request must contain the
/// `Access Policy`
pub async fn create_user_decryption_key(
    kmip_server: &KMS,
    cover_crypt: CoverCryptX25519Aes256,
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
    cover_crypt: CoverCryptX25519Aes256,
    create_attributes: &Attributes,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
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

    if master_private_key.key_wrapping_data().is_some() {
        kms_bail!(KmsError::InconsistentOperation(
            "The server can't create a decryption key: the master private key is wrapped"
                .to_owned()
        ));
    }

    UserDecryptionKeysHandler::instantiate(cover_crypt, master_private_key)?
        .create_user_decryption_key_object(
            &access_policy,
            Some(create_attributes),
            &master_private_key_uid,
        )
        .map_err(Into::into)
}

#[allow(unused)]
//TODO: there is noway to distinguish between the creation of a user decryption key pair and a master key pair
/// Create a KMIP tuple (`Object::PrivateKey`, `Object::PublicKey`)
pub async fn create_user_decryption_key_pair(
    kmip_server: &KMS,
    cover_crypt: CoverCryptX25519Aes256,
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
