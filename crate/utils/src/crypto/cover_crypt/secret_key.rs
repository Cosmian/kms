use std::convert::TryFrom;

use abe_policy::{AccessPolicy, Attribute as PolicyAttribute};
use cosmian_crypto_base::symmetric_crypto::aes_256_gcm_pure;
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingData},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{ErrorReason, GetResponse},
        kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType, WrappingMethod},
    },
};
use cover_crypt::{api::CoverCrypt, PublicKey};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::{
    crypto::cover_crypt::attributes::{access_policy_as_vendor_attribute, policy_from_attributes},
    kmip_utils::key_bytes_and_attributes_from_key_block,
};

// ------------------------------------------------------------------------------
// ------------------------- setup parameters for KMIP --------------------------
// ------------------------------------------------------------------------------

/// The whole Key Value structure is wrapped
/// A reference to the CoverCrypt master public key is kept to access the policy later
/// when locating symmetric keys
pub fn wrapped_secret_key(
    public_key_response: &GetResponse,
    access_policy: &AccessPolicy,
    cover_crypt_header_uid: &[u8],
) -> Result<Object, KmipError> {
    let sk = prepare_symmetric_key(
        public_key_response,
        &access_policy.attributes(),
        cover_crypt_header_uid,
    )?;
    // Since KMIP 2.1 does not plan to locate wrapped key, we serialize vendor
    // attributes and symmetric key consecutively
    let wrapped_key_attributes = Attributes {
        vendor_attributes: Some(vec![access_policy_as_vendor_attribute(access_policy)?]),
        ..Attributes::new(ObjectType::SymmetricKey)
    };

    let cryptographic_length = sk.encrypted_symmetric_key.len() as i32;
    let key_value = KeyValue {
        key_material: KeyMaterial::ByteString(sk.encrypted_symmetric_key),
        attributes: Some(wrapped_key_attributes),
    };
    let key_wrapping_data = KeyWrappingData {
        wrapping_method: WrappingMethod::Encrypt,
        iv_counter_nonce: None,
        ..KeyWrappingData::default()
    };

    Ok(Object::SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::AES,
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value,
            cryptographic_length,
            key_wrapping_data: Some(key_wrapping_data),
        },
    })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CoverCryptSymmetricKey {
    pub symmetric_key: Vec<u8>,
    pub uid: Vec<u8>,
    pub encrypted_symmetric_key: Vec<u8>,
}

fn prepare_symmetric_key(
    public_key_response: &GetResponse,
    policy_attributes: &[PolicyAttribute],
    cover_crypt_header_uid: &[u8],
) -> Result<CoverCryptSymmetricKey, KmipError> {
    trace!("Starting create secret key");

    let (public_key_bytes, public_key_attributes) = key_bytes_and_attributes_from_key_block(
        public_key_response.object.key_block()?,
        &public_key_response.unique_identifier,
    )?;
    let public_key = PublicKey::try_from_bytes(public_key_bytes).map_err(|e| {
        KmipError::KmipError(
            ErrorReason::Codec_Error,
            format!("cover crypt: failed deserializing the master public key: {e}"),
        )
    })?;

    let policy = policy_from_attributes(public_key_attributes.ok_or_else(|| {
        KmipError::InvalidKmipObject(
            ErrorReason::Attribute_Not_Found,
            "the master public key does not have attributes with the Policy".to_string(),
        )
    })?)?;

    let engine = CoverCrypt::default();
    let (sk, sk_enc) = engine
        .generate_symmetric_key(
            &policy,
            &public_key,
            policy_attributes,
            aes_256_gcm_pure::KEY_LENGTH,
        )
        .map_err(|e| {
            KmipError::InvalidKmipValue(ErrorReason::Invalid_Attribute_Value, e.to_string())
        })?;

    debug!("Generate symmetric key for CoverCrypt OK");
    Ok(CoverCryptSymmetricKey {
        uid: cover_crypt_header_uid.to_vec(),
        symmetric_key: sk.into(),
        encrypted_symmetric_key: sk_enc.try_to_bytes().map_err(|e| {
            KmipError::KmipError(
                ErrorReason::Codec_Error,
                format!("cover crypt: failed serializing the encapsulation: {e}"),
            )
        })?,
    })
}

impl TryFrom<&KeyBlock> for CoverCryptSymmetricKey {
    type Error = KmipError;

    fn try_from(sk: &KeyBlock) -> Result<Self, Self::Error> {
        if sk.cryptographic_algorithm != CryptographicAlgorithm::CoverCrypt
            || sk.key_format_type != KeyFormatType::TransparentSymmetricKey
        {
            return Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Data_Type,
                "this Secret Key does not contain an CoverCrypt key".to_string(),
            ))
        }

        if sk.key_wrapping_data.is_some() {
            return Err(KmipError::KmipNotSupported(
                ErrorReason::Key_Wrap_Type_Not_Supported,
                "unwrapping an CoverCrypt Secret Key is not yet supported".to_string(),
            ))
        }
        serde_json::from_slice::<CoverCryptSymmetricKey>(match &sk.key_value.key_material {
            KeyMaterial::TransparentSymmetricKey { key } => key,
            other => {
                return Err(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Object_Type,
                    format!("Invalid key material for an CoverCrypt secret key: {other:?}"),
                ))
            }
        })
        .map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed deserializing the CoverCrypt Secret Key from the Key Material {e}"),
            )
        })
    }
}
