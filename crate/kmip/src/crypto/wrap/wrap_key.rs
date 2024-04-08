use openssl::{
    pkey::{Id, PKey, Public},
    x509::X509,
};
use tracing::debug;
use zeroize::Zeroizing;

use super::WRAPPING_SECRET_LENGTH;
#[cfg(not(feature = "fips"))]
use crate::crypto::elliptic_curves::ecies::ecies_encrypt;
use crate::{
    crypto::{
        password_derivation::derive_key_from_password,
        rsa::{
            ckm_rsa_aes_key_wrap::ckm_rsa_aes_key_wrap,
            ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_key_wrap,
        },
        symmetric::rfc5649::rfc5649_wrap,
        wrap::common::rsa_parameters,
    },
    error::KmipError,
    kmip::{
        kmip_data_structures::{
            KeyBlock, KeyMaterial, KeyValue, KeyWrappingData, KeyWrappingSpecification,
        },
        kmip_objects::Object,
        kmip_operations::ErrorReason,
        kmip_types::{
            CryptographicAlgorithm, CryptographicUsageMask, EncodingOption, KeyFormatType,
            PaddingMethod, WrappingMethod,
        },
    },
    kmip_bail, kmip_error,
    openssl::kmip_public_key_to_openssl,
};

/// Wrap a key using a password
pub fn wrap_key_bytes(key: &[u8], wrapping_password: &str) -> Result<Vec<u8>, KmipError> {
    let wrapping_secret =
        derive_key_from_password::<WRAPPING_SECRET_LENGTH>(wrapping_password.as_bytes())?;
    rfc5649_wrap(key, wrapping_secret.as_ref()).map_err(|e| KmipError::Default(e.to_string()))
}

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
) -> Result<(), KmipError> {
    if object_key_block.key_wrapping_data.is_some() {
        kmip_bail!("unable to wrap the key: it is already wrapped")
    }
    // check that the wrapping method is supported
    match &key_wrapping_specification.wrapping_method {
        WrappingMethod::Encrypt => {
            // ok
        }
        x => {
            kmip_bail!("Unable to wrap the key: wrapping method is not supported: {x:?}")
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
    match encoding {
        EncodingOption::TTLVEncoding => {
            let key_to_wrap = Zeroizing::from(serde_json::to_vec(&object_key_block.key_value)?);
            let ciphertext = wrap(wrapping_key, &key_wrapping_data, &key_to_wrap)?;
            object_key_block.key_value = KeyValue {
                key_material: KeyMaterial::ByteString(ciphertext.into()),
                // not clear whether this should be filled or not
                attributes: object_key_block.key_value.attributes.clone(),
            };
        }
        EncodingOption::NoEncoding => {
            let key_to_wrap = object_key_block.key_bytes()?;
            let ciphertext = wrap(wrapping_key, &key_wrapping_data, &key_to_wrap)?;
            object_key_block.key_value.key_material = KeyMaterial::ByteString(ciphertext.into());
        }
    };

    object_key_block.key_wrapping_data = Some(Box::new(key_wrapping_data));

    Ok(())
}

/// Encrypt bytes using the wrapping key
pub(crate) fn wrap(
    wrapping_key: &Object,
    key_wrapping_data: &KeyWrappingData,
    key_to_wrap: &[u8],
) -> Result<Vec<u8>, KmipError> {
    debug!(
        "encrypt_bytes: with object: {:?}",
        wrapping_key.object_type()
    );
    match wrapping_key {
        Object::Certificate {
            certificate_value, ..
        } => {
            let cert = X509::from_der(certificate_value)
                .map_err(|e| KmipError::ConversionError(format!("invalid X509 DER: {e:?}")))?;
            let public_key = cert.public_key().map_err(|e| {
                KmipError::ConversionError(format!("invalid certificate public key: error: {e:?}"))
            })?;
            wrap_with_public_key(public_key, key_wrapping_data, key_to_wrap)
        }
        Object::PGPKey { key_block, .. }
        | Object::SecretData { key_block, .. }
        | Object::SplitKey { key_block, .. }
        | Object::PrivateKey { key_block }
        | Object::PublicKey { key_block }
        | Object::SymmetricKey { key_block } => {
            // wrap the wrapping key if necessary
            if key_block.key_wrapping_data.is_some() {
                kmip_bail!("unable to wrap keys: wrapping key is wrapped and that is not supported")
            }

            // Make sure that the key used to wrap can be used to wrap.
            if !wrapping_key
                .attributes()?
                .is_usage_authorized_for(CryptographicUsageMask::WrapKey)?
            {
                return Err(KmipError::InvalidKmipValue(
                    ErrorReason::Incompatible_Cryptographic_Usage_Mask,
                    "CryptographicUsageMask not authorized for WrapKey".to_owned(),
                ))
            }

            let ciphertext = match key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => {
                    // wrap using rfc_5649
                    let wrap_secret = key_block.key_bytes()?;
                    let ciphertext = rfc5649_wrap(key_to_wrap, &wrap_secret)?;
                    Ok(ciphertext)
                }
                #[cfg(feature = "openssl")]
                KeyFormatType::TransparentECPublicKey | KeyFormatType::TransparentRSAPublicKey => {
                    // convert to transparent key and wrap
                    // note: when moving to full openssl this double conversion will be unnecessary
                    let p_key = kmip_public_key_to_openssl(wrapping_key)?;
                    wrap_with_public_key(p_key, key_wrapping_data, key_to_wrap)
                }
                // this really is SPKI
                #[cfg(feature = "openssl")]
                KeyFormatType::PKCS8 => {
                    let p_key = PKey::public_key_from_der(&key_block.key_bytes()?)?;
                    wrap_with_public_key(p_key, key_wrapping_data, key_to_wrap)
                }
                x => {
                    kmip_bail!(
                        "Unable to wrap key: wrapping key: key format not supported for wrapping: \
                         {x:?}"
                    )
                }
            }?;
            Ok(ciphertext)
        }
        _ => Err(KmipError::NotSupported(format!(
            "Wrapping key type not supported: {:?}",
            wrapping_key.object_type()
        ))),
    }
}

fn wrap_with_public_key(
    public_key: PKey<Public>,
    key_wrapping_data: &KeyWrappingData,
    key_to_wrap: &[u8],
) -> Result<Vec<u8>, KmipError> {
    match public_key.id() {
        Id::RSA => wrap_with_rsa(public_key, key_wrapping_data, key_to_wrap),
        #[cfg(not(feature = "fips"))]
        Id::EC | Id::X25519 | Id::ED25519 => ecies_encrypt(&public_key, key_to_wrap),
        other => Err(kmip_error!(
            "Unable to wrap key: wrapping public key type not supported: {other:?}"
        )),
    }
}

fn wrap_with_rsa(
    pub_key: PKey<Public>,
    key_wrapping_data: &KeyWrappingData,
    key_to_wrap: &[u8],
) -> Result<Vec<u8>, KmipError> {
    let (algorithm, padding, hashing_fn) = rsa_parameters(key_wrapping_data);
    if padding != PaddingMethod::OAEP {
        kmip_bail!("Unable to wrap key with RSA: padding method not supported: {padding:?}")
    }
    match algorithm {
        CryptographicAlgorithm::AES => ckm_rsa_aes_key_wrap(&pub_key, hashing_fn, key_to_wrap),
        CryptographicAlgorithm::RSA => {
            ckm_rsa_pkcs_oaep_key_wrap(&pub_key, hashing_fn, key_to_wrap)
        }
        x => Err(kmip_error!(
            "Unable to wrap key with RSA: algorithm not supported for wrapping: {x:?}"
        )),
    }
}
