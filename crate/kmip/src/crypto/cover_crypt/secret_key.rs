use std::convert::TryFrom;

use cloudproof::reexport::{
    cover_crypt::{abe_policy::AccessPolicy, Covercrypt, MasterPublicKey},
    crypto_core::bytes_ser_de::Serializable,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::{
    crypto::cover_crypt::attributes::{access_policy_as_vendor_attribute, policy_from_attributes},
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingData},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{ErrorReason, GetResponse},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType,
            WrappingMethod,
        },
    },
};

// ------------------------------------------------------------------------------
// ------------------------- setup parameters for KMIP --------------------------
// ------------------------------------------------------------------------------

/// The whole Key Value structure is wrapped
/// A reference to the `CoverCrypt` master public key is kept to access the policy later
/// when locating symmetric keys
pub fn wrapped_secret_key(
    cover_crypt: &Covercrypt,
    public_key_response: &GetResponse,
    access_policy: &str,
    cover_crypt_header_uid: &[u8],
) -> Result<Object, KmipError> {
    let sk = prepare_symmetric_key(
        cover_crypt,
        public_key_response,
        &AccessPolicy::from_boolean_expression(access_policy)?,
        cover_crypt_header_uid,
    )?;
    // Since KMIP 2.1 does not plan to locate wrapped key, we serialize vendor
    // attributes and symmetric key consecutively
    let wrapped_key_attributes = Attributes {
        object_type: Some(ObjectType::SymmetricKey),
        vendor_attributes: Some(vec![access_policy_as_vendor_attribute(access_policy)?]),
        cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
        ..Attributes::default()
    };

    let cryptographic_length = Some(i32::try_from(sk.encrypted_symmetric_key.len())? * 8);
    let key_value = KeyValue {
        key_material: KeyMaterial::ByteString(Zeroizing::from(sk.encrypted_symmetric_key)),
        attributes: Some(Box::new(wrapped_key_attributes)),
    };
    let key_wrapping_data = KeyWrappingData {
        wrapping_method: WrappingMethod::Encrypt,
        iv_counter_nonce: None,
        ..KeyWrappingData::default()
    };

    Ok(Object::SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value,
            cryptographic_length,
            key_wrapping_data: Some(Box::new(key_wrapping_data)),
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
    cover_crypt: &Covercrypt,
    public_key_response: &GetResponse,
    access_policy: &AccessPolicy,
    cover_crypt_header_uid: &[u8],
) -> Result<CoverCryptSymmetricKey, KmipError> {
    trace!("Starting create secret key");

    let (public_key_bytes, public_key_attributes) = public_key_response
        .object
        .key_block()?
        .key_bytes_and_attributes()?;

    let public_key = MasterPublicKey::deserialize(&public_key_bytes).map_err(|e| {
        KmipError::KmipError(
            ErrorReason::Codec_Error,
            format!("cover crypt: failed deserializing the master public key: {e}"),
        )
    })?;

    let policy = policy_from_attributes(public_key_attributes.ok_or_else(|| {
        KmipError::InvalidKmipObject(
            ErrorReason::Attribute_Not_Found,
            "the master public key does not have attributes with the Policy".to_owned(),
        )
    })?)?;

    let (sk, sk_enc) = cover_crypt
        .encaps(&policy, &public_key, access_policy)
        .map_err(|e| {
            KmipError::InvalidKmipValue(ErrorReason::Invalid_Attribute_Value, e.to_string())
        })?;

    debug!("Generate symmetric key for CoverCrypt OK");
    Ok(CoverCryptSymmetricKey {
        uid: cover_crypt_header_uid.to_vec(),
        symmetric_key: sk.to_vec(),
        encrypted_symmetric_key: sk_enc
            .serialize()
            .map_err(|e| {
                KmipError::KmipError(
                    ErrorReason::Codec_Error,
                    format!("cover crypt: failed serializing the encapsulation: {e}"),
                )
            })?
            .to_vec(),
    })
}

impl TryFrom<&KeyBlock> for CoverCryptSymmetricKey {
    type Error = KmipError;

    fn try_from(sk: &KeyBlock) -> Result<Self, Self::Error> {
        if sk.cryptographic_algorithm != Some(CryptographicAlgorithm::CoverCrypt)
            || sk.key_format_type != KeyFormatType::TransparentSymmetricKey
        {
            return Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Data_Type,
                "this Secret Key does not contain an CoverCrypt key".to_owned(),
            ))
        }

        if sk.key_wrapping_data.is_some() {
            return Err(KmipError::KmipNotSupported(
                ErrorReason::Key_Wrap_Type_Not_Supported,
                "unwrapping an CoverCrypt Secret Key is not yet supported".to_owned(),
            ))
        }
        serde_json::from_slice::<Self>(match &sk.key_value.key_material {
            KeyMaterial::TransparentSymmetricKey { key } => key,
            other => {
                return Err(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Object_Type,
                    format!("Invalid key material for an CoverCrypt secret key: {other}"),
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
