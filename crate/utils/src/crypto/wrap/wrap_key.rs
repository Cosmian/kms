use std::ops::Deref;

use cosmian_kmip::{
    kmip::{
        kmip_data_structures::{
            KeyBlock, KeyMaterial, KeyValue, KeyWrappingData, KeyWrappingSpecification,
        },
        kmip_objects::Object,
        kmip_operations::Encrypt,
        kmip_types::{
            CryptographicAlgorithm, EncodingOption, HashingAlgorithm, KeyFormatType, PaddingMethod,
            WrappingMethod,
        },
    },
    openssl::kmip_public_key_to_openssl,
};
use openssl::pkey::{Id, PKey, Public};
use tracing::debug;
use zeroize::Zeroizing;

use crate::{
    crypto::{
        elliptic_curves::ecies::ecies_encrypt,
        hybrid_encryption::HybridEncryptionSystem,
        rsa::{
            ckm_rsa_aes_key_wrap::ckm_rsa_aes_key_wrap,
            ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_key_wrap,
        },
        symmetric::rfc5649::rfc5649_wrap,
    },
    error::KmipUtilsError,
    kmip_utils_bail, EncryptionSystem,
};

/// Wrap a key block with a wrapping key
/// The wrapping key is fetched from the database
/// The key is wrapped using the wrapping key
///
/// # Arguments
/// * `rng` - the random number generator
/// * `object_key_block` - the key block of the object to wrap
/// * `wrapping_key` - the wrapping key
/// * `key_wrapping_specification` - the key wrapping specification
/// # Returns
/// * `KResult<()>` - the result of the operation
pub fn wrap_key_block(
    object_key_block: &mut KeyBlock,
    wrapping_key: &Object,
    key_wrapping_specification: &KeyWrappingSpecification,
) -> Result<(), KmipUtilsError> {
    if object_key_block.key_wrapping_data.is_some() {
        kmip_utils_bail!("unable to wrap the key: it is already wrapped")
    }
    // check that the wrapping method is supported
    match &key_wrapping_specification.wrapping_method {
        WrappingMethod::Encrypt => {
            // ok
        }
        x => {
            kmip_utils_bail!("Unable to wrap the key: wrapping method is not supported: {x:?}")
        }
    }

    // determine the encoding of the wrapping
    let encoding = key_wrapping_specification
        .encoding_option
        .unwrap_or(EncodingOption::TTLVEncoding);

    let key_wrapping_data = KeyWrappingData {
        wrapping_method: key_wrapping_specification.wrapping_method,
        encryption_key_information: key_wrapping_specification
            .encryption_key_information
            .clone(),
        mac_or_signature_key_information: key_wrapping_specification
            .mac_or_signature_key_information
            .clone(),
        encoding_option: key_wrapping_specification.encoding_option,
        ..KeyWrappingData::default()
    };

    // wrap the key based on the encoding
    // wrap the key based on the encoding
    match encoding {
        EncodingOption::TTLVEncoding => {
            let key_to_wrap = Zeroizing::from(serde_json::to_vec(&object_key_block.key_value)?);
            let ciphertext = wrap(wrapping_key, &key_wrapping_data, &key_to_wrap)?;
            object_key_block.key_value = KeyValue {
                key_material: KeyMaterial::ByteString(ciphertext),
                // not clear whether this should be filled or not
                attributes: object_key_block.key_value.attributes.clone(),
            };
        }
        EncodingOption::NoEncoding => {
            let key_to_wrap = object_key_block.key_bytes()?;
            let ciphertext = wrap(wrapping_key, &key_wrapping_data, &key_to_wrap)?;
            object_key_block.key_value.key_material = KeyMaterial::ByteString(ciphertext);
        }
    };

    object_key_block.key_wrapping_data = Some(key_wrapping_data);

    Ok(())
}

/// Encrypt bytes using the wrapping key
pub(crate) fn wrap(
    wrapping_key: &Object,
    key_wrapping_data: &KeyWrappingData,
    key_to_wrap: &Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, KmipUtilsError> {
    debug!(
        "encrypt_bytes: with object: {:?}",
        wrapping_key.object_type()
    );
    match wrapping_key {
        Object::Certificate {
            certificate_value, ..
        } => {
            // TODO(ECSE): cert should be verified before anything
            //verify_certificate(certificate_value, kms, owner, params).await?;
            debug!("encrypt_bytes: Encryption with certificate: certificate OK");
            let encrypt_system = HybridEncryptionSystem::instantiate_with_certificate(
                "id",
                certificate_value,
                true,
            )?;
            let request = Encrypt {
                data: Some(key_to_wrap.to_vec()),
                ..Encrypt::default()
            };
            let encrypt_response = encrypt_system.encrypt(&request)?;
            let ciphertext = encrypt_response.data.ok_or(KmipUtilsError::Default(
                "Encrypt response does not contain ciphertext".to_string(),
            ))?;
            debug!(
                "encrypt_bytes: succeeded: ciphertext length: {}",
                ciphertext.len()
            );
            Ok(ciphertext)
        }
        Object::PGPKey { key_block, .. }
        | Object::SecretData { key_block, .. }
        | Object::SplitKey { key_block, .. }
        | Object::PrivateKey { key_block }
        | Object::PublicKey { key_block }
        | Object::SymmetricKey { key_block } => {
            // wrap the wrapping key if necessary
            if key_block.key_wrapping_data.is_some() {
                kmip_utils_bail!(
                    "unable to wrap keys: wrapping key is wrapped and that is not supported"
                )
            }
            let ciphertext = match key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => {
                    // wrap using rfc_5649
                    let wrap_secret = key_block.key_bytes()?;
                    let ciphertext = rfc5649_wrap(key_to_wrap, &wrap_secret)?;
                    Ok(ciphertext)
                }
                KeyFormatType::TransparentECPublicKey | KeyFormatType::TransparentRSAPublicKey => {
                    //convert to transparent key and wrap
                    // note: when moving to full openssl this double conversion will be unnecessary
                    let p_key = kmip_public_key_to_openssl(wrapping_key)?;
                    wrap_with_public_key(p_key, key_wrapping_data, key_to_wrap)
                }
                // this really is SPKI
                KeyFormatType::PKCS8 => {
                    let p_key = PKey::public_key_from_der(&key_block.key_bytes()?)?;
                    wrap_with_public_key(p_key, key_wrapping_data, key_to_wrap)
                }
                x => {
                    kmip_utils_bail!(
                        "Unable to wrap key: wrapping key: key format not supported for wrapping: \
                         {x:?}"
                    )
                }
            }?;
            Ok(ciphertext)
        }
        _ => Err(KmipUtilsError::NotSupported(format!(
            "Wrapping key type not supported: {:?}",
            wrapping_key.object_type()
        ))),
    }
}

fn wrap_with_public_key(
    pub_key: PKey<Public>,
    key_wrapping_data: &KeyWrappingData,
    key_to_wrap: &Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, KmipUtilsError> {
    let ciphertext = match pub_key.id() {
        Id::RSA => wrap_with_rsa(pub_key, key_wrapping_data, key_to_wrap)?,
        Id::EC | Id::X25519 | Id::ED25519 => ecies_encrypt(&pub_key, key_to_wrap.deref())?,
        other => {
            kmip_utils_bail!(
                "Unable to wrap key: wrapping public key type not supported: {other:?}"
            )
        }
    };

    Ok(ciphertext)
}

fn wrap_with_rsa(
    pub_key: PKey<Public>,
    key_wrapping_data: &KeyWrappingData,
    key_to_wrap: &Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, KmipUtilsError> {
    let (algorithm, padding, hashing_fn) = key_wrapping_data
        .encryption_key_information
        .as_ref()
        .and_then(|eki| eki.cryptographic_parameters.as_ref())
        .map(|cp| {
            (
                cp.cryptographic_algorithm
                    .unwrap_or(CryptographicAlgorithm::RSAAESKeyWrap),
                cp.padding_method.unwrap_or(PaddingMethod::OAEP),
                cp.hashing_algorithm.unwrap_or(HashingAlgorithm::SHA256),
            )
        })
        .unwrap_or_else(|| {
            (
                // default to CKM_RSA_AES_KEY_WRAP
                CryptographicAlgorithm::RSAAESKeyWrap,
                PaddingMethod::OAEP,
                HashingAlgorithm::SHA256,
            )
        });
    if padding != PaddingMethod::OAEP {
        kmip_utils_bail!("Unable to wrap key with RSA: padding method not supported: {padding:?}")
    }
    match algorithm {
        CryptographicAlgorithm::RSAAESKeyWrap => {
            ckm_rsa_aes_key_wrap(&pub_key, hashing_fn.into(), key_to_wrap)
        }
        CryptographicAlgorithm::RSA => {
            ckm_rsa_pkcs_oaep_key_wrap(&pub_key, hashing_fn.into(), key_to_wrap)
        }
        x => {
            kmip_utils_bail!(
                "Unable to wrap key with RSA: algorithm not supported for wrapping: {x:?}"
            )
        }
    }
}
