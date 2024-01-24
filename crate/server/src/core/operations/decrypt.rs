use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{Decrypt, DecryptResponse, ErrorReason},
    kmip_types::{KeyFormatType, StateEnumeration},
};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, ObjectOperationType},
    crypto::cover_crypt::attributes,
};
use tracing::trace;

use crate::{
    core::KMS,
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    result::{KResult, KResultHelper},
};

pub async fn decrypt(
    kms: &KMS,
    request: Decrypt,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<DecryptResponse> {
    trace!("Decrypt: {:?}", &request.unique_identifier);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Decrypt: unique_identifier must be a string")?;
    trace!("decrypt: uid_or_tags: {uid_or_tags}");

    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(uid_or_tags, user, ObjectOperationType::Decrypt, params)
        .await?
        .into_values()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            if owm.state != StateEnumeration::Active {
                return false
            }
            if object_type == ObjectType::SymmetricKey {
                return true
            }
            if object_type != ObjectType::PrivateKey {
                return false
            }
            if let Ok(attributes) = owm.object.attributes() {
                // is it a Covercrypt secret key?
                if attributes.key_format_type == Some(KeyFormatType::CoverCryptSecretKey) {
                    // does it have an access policy that allows decryption?
                    return attributes::access_policy_from_attributes(attributes).is_ok()
                }
            }
            true
        })
        .collect::<Vec<ObjectWithMetadata>>();
    trace!("decrypt: owm_s: {:?}", owm_s);

    // there can only be one key
    let owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::KmipError(ErrorReason::Item_Not_Found, uid_or_tags.to_string()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many objects for key {uid_or_tags}",
        )))
    }

    // unwrap if wrapped
    if owm.object.key_wrapping_data().is_some() {
        let key_block = owm.object.key_block_mut()?;
        unwrap_key(key_block, self, &owm.owner, params).await?;
    }

    trace!(
        "get_decryption_system: matching on object: {:?}",
        owm.object
    );
    match &owm.object {
        Object::PrivateKey { key_block } => {
            match &key_block.key_format_type {
                KeyFormatType::CoverCryptSecretKey => Ok(Box::new(
                    CovercryptDecryption::instantiate(Covercrypt::default(), &owm.id, &owm.object)?,
                )),
                KeyFormatType::PKCS8
                | KeyFormatType::PKCS1
                | KeyFormatType::TransparentRSAPrivateKey
                | KeyFormatType::TransparentECPrivateKey => {
                    let p_key = kmip_private_key_to_openssl(&owm.object)?;
                    // match  cryptographic_parameters.and_then(|cp| cp.cryptographic_algorithm) {
                    //             CryptographicAlgorithm::RSA => {
                    //                 Ok(Box::new(HybridDecryptionSystem::new(
                    //                     Some(owm.id),
                    //                     p_key,
                    //                     false,
                    //                 )) as Box<dyn DecryptionSystem>)
                    //             }
                    //             CryptographicAlgorithm::CoverCrypt => {
                    //                 Ok(Box::new(HybridDecryptionSystem::new(
                    //                     Some(owm.id),
                    //                     p_key,
                    //                     true,
                    //                 )) as Box<dyn DecryptionSystem>)
                    //             }
                    //             other =>
                    // }
                    Ok(
                        Box::new(HybridDecryptionSystem::new(Some(owm.id), p_key, false))
                            as Box<dyn DecryptionSystem>,
                    )
                }
                other => kms_not_supported!("decryption with keys of format: {other}"),
            }
        }
        Object::SymmetricKey { key_block } => match &key_block.key_format_type {
            KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {
                match &key_block.cryptographic_algorithm {
                    Some(CryptographicAlgorithm::AES) => {
                        Ok(Box::new(AesGcmSystem::instantiate(&owm.id, &owm.object)?))
                    }
                    other => {
                        kms_not_supported!(
                            "symmetric decryption with algorithm: {}",
                            other.map_or("[N/A]".to_string(), |alg| alg.to_string())
                        )
                    }
                }
            }
            other => kms_not_supported!("decryption with keys of format: {other}"),
        },
        other => kms_not_supported!("decryption with keys of type: {}", other.object_type()),
    }

    // decrypt
    kms.get_decryption_system(owm, request.cryptographic_parameters.as_ref(), params)
        .await?
        .decrypt(&request)
        .map_err(Into::into)
}
