use cloudproof::reexport::cover_crypt::Covercrypt;
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{Encrypt, EncryptResponse, ErrorReason},
    kmip_types::StateEnumeration,
};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
use tracing::{debug, trace};
use cosmian_kmip::kmip::kmip_objects::Object;
use cosmian_kmip::kmip::kmip_types::{CryptographicAlgorithm, KeyFormatType};
use cosmian_kmip::openssl::kmip_public_key_to_openssl;
use cosmian_kms_utils::crypto::cover_crypt::encryption::CoverCryptEncryption;
use cosmian_kms_utils::crypto::symmetric::AesGcmSystem;
use cosmian_kms_utils::EncryptionSystem;

use crate::{core::KMS, database::object_with_metadata::ObjectWithMetadata, error::KmsError, kms_bail, kms_not_supported, result::{KResult, KResultHelper}};
use crate::core::operations::unwrap_key;

pub async fn encrypt(
    kms: &KMS,
    request: Encrypt,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<EncryptResponse> {
    trace!("operations::encrypt: {}", serde_json::to_string(&request)?);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Encrypt: the unique identifier or tags must be a string")?;
    trace!("operations::encrypt: uid_or_tags: {uid_or_tags}");

    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(uid_or_tags, user, ObjectOperationType::Encrypt, params)
        .await?
        .into_values()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            owm.state == StateEnumeration::Active
                && (object_type == ObjectType::PublicKey
                    || object_type == ObjectType::SymmetricKey
                    || object_type == ObjectType::Certificate)
        })
        .collect::<Vec<ObjectWithMetadata>>();

    trace!("operations::encrypt: owm_s: {:?}", owm_s);
    // there can only be one key
    let mut owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::KmipError(ErrorReason::Item_Not_Found, uid_or_tags.to_string()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many objects for key {uid_or_tags}",
        )))
    }


    // the key must be active
    if owm.state != StateEnumeration::Active {
        kms_bail!(KmsError::InconsistentOperation(
                "the server can't encrypt: the key is not active".to_owned()
            ));
    }

    // unwrap if wrapped
    match &mut owm.object {
        Object::Certificate { .. } => {}
        _ => {
            if owm.object.key_wrapping_data().is_some() {
                let key_block = owm.object.key_block_mut()?;
                unwrap_key(key_block, self, &owm.owner, params).await?;
            }
        }
    }
    trace!("get_encryption_system: unwrap done (if required)");


    match &owm.object {
        Object::SymmetricKey { key_block } => match &key_block.key_format_type {
            KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {}
        }
    }

    let encryption_system = match &owm.object {
        Object::SymmetricKey { key_block } => match &key_block.key_format_type {
            KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {
                match &key_block.cryptographic_algorithm {
                    Some(CryptographicAlgorithm::AES) => {
                        Ok(Box::new(AesGcmSystem::instantiate(&owm.id, &owm.object)?)
                            as Box<dyn EncryptionSystem>)
                    }
                    other => {
                        kms_not_supported!(
                                "symmetric encryption with algorithm: {}",
                                other.map_or("[N/A]".to_string(), |alg| alg.to_string())
                            )
                    }
                }
            }
            other => kms_not_supported!("encryption with keys of format: {other}"),
        },
        Object::PublicKey { key_block } => match &key_block.key_format_type {
            KeyFormatType::CoverCryptPublicKey => Ok(Box::new(
                CoverCryptEncryption::instantiate(Covercrypt::default(), &owm.id, &owm.object)?,
            )
                as Box<dyn EncryptionSystem>),
            KeyFormatType::TransparentECPublicKey
            | KeyFormatType::TransparentRSAPublicKey
            | KeyFormatType::PKCS1
            | KeyFormatType::PKCS8 => {
                trace!(
                        "get_encryption_system: matching on key format type: {:?}",
                        key_block.key_format_type
                    );
                let public_key = kmip_public_key_to_openssl(&owm.object)?;
                trace!(
                        "get_encryption_system: OpenSSL Public Key instantiated before encryption"
                    );
                Ok(
                    Box::new(HybridEncryptionSystem::new(&owm.id, public_key, false))
                        as Box<dyn EncryptionSystem>,
                )
            }
            other => kms_not_supported!("encryption with public keys of format: {other}"),
        },
        Object::Certificate {
            certificate_value, ..
        } => Ok(
            Box::new(HybridEncryptionSystem::instantiate_with_certificate(
                &owm.id,
                certificate_value,
                false,
            )?) as Box<dyn EncryptionSystem>,
        ),
        other => kms_not_supported!("encryption with keys of type: {}", other.object_type()),
    };
    trace!("get_encryption_system: exiting");
    encryption_system
    
    
    
    debug!("operations::encrypt: Encrypting for {}", uid_or_tags);
    kms.get_encryption_system(owm, params)
        .await?
        .encrypt(&request)
        .map_err(Into::into)
}
