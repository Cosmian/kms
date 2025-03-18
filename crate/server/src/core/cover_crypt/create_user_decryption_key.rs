use std::sync::Arc;

use cosmian_cover_crypt::{MasterSecretKey, api::Covercrypt};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kmip::kmip_2_1::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Create, Import},
    kmip_types::{Attributes, KeyFormatType, StateEnumeration, UniqueIdentifier},
};
use cosmian_kms_crypto::crypto::cover_crypt::{
    attributes::{access_policy_from_attributes, access_structure_from_attributes},
    master_keys::create_msk_object,
    user_key::UserDecryptionKeysHandler,
};
use cosmian_kms_interfaces::{ObjectWithMetadata, SessionParams};
use tracing::{debug, trace};

use super::KMS;
use crate::{error::KmsError, kms_bail, result::KResult};

/// Create a User Decryption Key in the KMS.
///
/// The attributes of the `Create` request must contain the `Access Policy`.
pub(crate) async fn create_user_decryption_key(
    kmip_server: &KMS,
    cover_crypt: Covercrypt,
    create_request: &Create,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
    sensitive: bool,
) -> KResult<Object> {
    let msk_uid_or_tags = create_request
        .attributes
        .get_parent_id()
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "there should be a reference to the MSK in the creation attributes".to_owned(),
            )
        })?
        .to_string();

    for owm in kmip_server
        .database
        .retrieve_objects(&msk_uid_or_tags, params.clone())
        .await?
        .into_values()
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
        if access_structure_from_attributes(attributes).is_err() {
            continue;
        }

        let access_policy = access_policy_from_attributes(&create_request.attributes)?;
        debug!("create_user_decryption_key_: Access Policy: {access_policy}");

        let (msk_obj, usk_obj) = create_user_decryption_key_(
            &owm,
            &cover_crypt,
            &access_policy,
            &create_request.attributes,
            sensitive,
        )
        .await?;

        let import_request = Import {
            unique_identifier: UniqueIdentifier::TextString(owm.id().to_string()),
            object_type: ObjectType::PrivateKey,
            replace_existing: Some(true),
            key_wrap_type: None,
            attributes: owm.attributes().clone(),
            object: msk_obj,
        };

        kmip_server
            .import(import_request, owner, params.clone())
            .await?;

        return Ok(usk_obj);
    }

    Err(KmsError::InvalidRequest(format!(
        "get: no Covercrypt master secret key found for: {msk_uid_or_tags}",
    )))
}

async fn create_user_decryption_key_(
    owm: &ObjectWithMetadata,
    cover_crypt: &Covercrypt,
    access_policy: &String,
    create_attributes: &Attributes,
    sensitive: bool,
) -> KResult<(Object, Object)> {
    if owm.object().key_wrapping_data().is_some() {
        kms_bail!(KmsError::InconsistentOperation(
            "The server can't create a decryption key: the master secret key is wrapped".to_owned()
        ));
    }

    let mut msk = MasterSecretKey::deserialize(&**owm.object().key_block()?.key_bytes()?)?;
    let mut usk_handler = UserDecryptionKeysHandler::instantiate(&cover_crypt, &mut msk);

    let usk_obj = usk_handler
        .create_usk_object(access_policy, Some(create_attributes), owm.id())
        .map_err(KmsError::from)?;

    let msk_bytes = msk.serialize()?;

    trace!(
        "create_user_decryption_key_: updated_master_secret_key_bytes len: {}",
        msk_bytes.len()
    );

    let msk_attributes = owm.object().attributes()?;
    let mpk_link = msk_attributes
        .get_link(cosmian_kmip::kmip_2_1::kmip_types::LinkType::PublicKeyLink)
        .ok_or_else(|| {
            KmsError::InconsistentOperation(
                "The server can't create a decryption key: the master secret key has no public \
                 key link"
                    .to_owned(),
            )
        })?;

    let msk_obj = create_msk_object(
        msk_bytes,
        msk_attributes.clone(),
        &mpk_link.to_string(),
        sensitive,
    )?;

    return Ok((msk_obj, usk_obj));
}
