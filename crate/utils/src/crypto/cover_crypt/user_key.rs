use cosmian_crypto_base::asymmetric::ristretto::X25519Crypto;
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_operations::ErrorReason,
        kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType},
    },
};
use cover_crypt::{
    api::{CoverCrypt, PrivateKey},
    policies::{AccessPolicy, Policy},
};
use tracing::trace;

use crate::crypto::cover_crypt::attributes::{
    access_policy_from_attributes, upsert_access_policy_in_attributes,
};

/// Create a User Decryption Key Object from the passed master private key bytes,
/// Policy, Access Policy and optional additional attributes
///
/// see `cover_crypt_unwrap_user_decryption_key` for the reverse operation
pub fn create_user_decryption_key_object(
    master_private_key_bytes: &[u8],
    policy: &Policy,
    access_policy: &AccessPolicy,
    attributes: Option<&Attributes>,
) -> Result<Object, KmipError> {
    //
    // Generate a fresh user decryption key
    //
    let engine = CoverCrypt::<X25519Crypto>::default();
    let master_private_key = PrivateKey::try_from_bytes(master_private_key_bytes).map_err(|e| {
        KmipError::KmipError(
            ErrorReason::Codec_Error,
            format!("cover crypt: failed deserializing the master private key: {e}"),
        )
    })?;
    let uk = engine
        .generate_user_private_key(&master_private_key, access_policy, policy)
        .map_err(|e| {
            KmipError::InvalidKmipValue(ErrorReason::Invalid_Attribute_Value, e.to_string())
        })?;
    trace!("Created user decryption key {uk:?} with access policy: {access_policy:?}");
    let user_decryption_key_bytes = uk.try_to_bytes().map_err(|e| {
        KmipError::KmipError(
            ErrorReason::Codec_Error,
            format!("cover crypt: failed serializing the user key: {e}"),
        )
    })?;
    let user_decryption_key_len = user_decryption_key_bytes.len();

    let mut attributes = attributes
        .map(|att| {
            let mut att = att.clone();
            att.object_type = ObjectType::PrivateKey;
            att
        })
        .unwrap_or_else(|| Attributes::new(ObjectType::PrivateKey));
    upsert_access_policy_in_attributes(&mut attributes, access_policy)?;
    Ok(Object::PrivateKey {
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::CoverCrypt,
            key_format_type: KeyFormatType::CoverCryptSecretKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(user_decryption_key_bytes),
                attributes: Some(attributes),
            },
            cryptographic_length: user_decryption_key_len as i32 * 8,
            key_wrapping_data: None,
        },
    })
}

/// Unwrap the User Decryption Key bytes, Policy and Access Policy from the
/// provided User Decryption Key Object
///
/// see `cover_crypt_create_user_decryption_key_object` for the reverse operation
pub(crate) fn unwrap_user_decryption_key_object(
    user_decryption_key: &Object,
) -> Result<(Vec<u8>, AccessPolicy, Attributes), KmipError> {
    let key_block = match &user_decryption_key {
        Object::PrivateKey { key_block } => key_block.clone(),
        _ => {
            return Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Object_Type,
                "Expected a KMIP Private Key".to_owned(),
            ))
        }
    };
    if key_block.key_format_type != KeyFormatType::CoverCryptSecretKey {
        return Err(KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Object_Type,
            "Expected an CoverCrypt User Decryption Key".to_owned(),
        ))
    }
    let bytes = match &key_block.key_value.key_material {
        KeyMaterial::ByteString(b) => b.clone(),
        x => {
            return Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Object_Type,
                format!("Invalid Key Material for the CoverCrypt User Decryption Key: {x:?}"),
            ))
        }
    };
    let attributes = key_block.key_value.attributes().map_err(|e| {
        KmipError::InvalidKmipValue(
            ErrorReason::Attribute_Not_Found,
            format!("The CoverCrypt Master private key should have attributes: {e}"),
        )
    })?;
    let access_policy = access_policy_from_attributes(attributes)?;
    Ok((bytes, access_policy, attributes.clone()))
}
