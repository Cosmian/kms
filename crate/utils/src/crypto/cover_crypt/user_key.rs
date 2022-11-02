use abe_policy::{AccessPolicy, Policy};
use cosmian_cover_crypt::{
    api::CoverCrypt,
    interfaces::statics::{CoverCryptX25519Aes256, MasterSecretKey, UserSecretKey},
};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_operations::ErrorReason,
        kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType},
    },
};
use tracing::trace;

use crate::crypto::cover_crypt::attributes::{
    access_policy_from_attributes, policy_from_attributes, upsert_access_policy_in_attributes,
};

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

/// Handles operations on user keys, caching the engine
/// and the master key information for efficiency
pub struct UserDecryptionKeysHandler {
    cover_crypt: CoverCryptX25519Aes256,
    master_private_key: MasterSecretKey,
    policy: Policy,
}

impl UserDecryptionKeysHandler {
    pub fn instantiate(
        cover_crypt: CoverCryptX25519Aes256,
        master_private_key: &Object,
    ) -> Result<UserDecryptionKeysHandler, KmipError> {
        let msk_key_block = master_private_key.key_block()?;
        let msk_key_bytes = msk_key_block.as_bytes()?;
        let msk = MasterSecretKey::try_from_bytes(msk_key_bytes).map_err(|e| {
            KmipError::KmipError(
                ErrorReason::Codec_Error,
                format!("cover crypt: failed deserializing the master private key: {e}"),
            )
        })?;
        let private_key_attributes = master_private_key.attributes()?;
        let policy = policy_from_attributes(private_key_attributes)?;
        Ok(UserDecryptionKeysHandler {
            cover_crypt,
            master_private_key: msk,
            policy,
        })
    }

    /// Create a User Decryption Key Object from the passed master private key bytes,
    /// Policy, Access Policy and optional additional attributes
    ///
    /// see `cover_crypt_unwrap_user_decryption_key` for the reverse operation
    pub fn create_user_decryption_key_object(
        &self,
        access_policy: &AccessPolicy,
        attributes: Option<&Attributes>,
    ) -> Result<Object, KmipError> {
        //
        // Generate a fresh user decryption key
        //
        let uk = self
            .cover_crypt
            .generate_user_secret_key(&self.master_private_key, access_policy, &self.policy)
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

    /// Refresh the user decryption key according to the (new) policy of the master key
    pub fn refresh_user_decryption_key_object(
        &self,
        user_decryption_key: &Object,
        preserve_access_to_old_partitions: bool,
    ) -> Result<Object, KmipError> {
        let (usk_key_bytes, usk_access_policy, usk_attributes) =
            unwrap_user_decryption_key_object(user_decryption_key)?;
        let mut usk = UserSecretKey::try_from_bytes(&usk_key_bytes).map_err(|e| {
            KmipError::KmipError(
                ErrorReason::Codec_Error,
                format!("cover crypt: failed deserializing the user decryption key: {e}"),
            )
        })?;

        self.cover_crypt
            .refresh_user_secret_key(
                &mut usk,
                &usk_access_policy,
                &self.master_private_key,
                &self.policy,
                preserve_access_to_old_partitions,
            )
            .map_err(|e| {
                KmipError::KmipError(
                    ErrorReason::Cryptographic_Failure,
                    format!("cover crypt: failed refreshing the user decryption key: {e}"),
                )
            })?;

        trace!("Refreshed  user decryption key {usk:?} with access policy: {usk_access_policy:?}");

        let user_decryption_key_bytes = usk.try_to_bytes().map_err(|e| {
            KmipError::KmipError(
                ErrorReason::Codec_Error,
                format!("cover crypt: failed serializing the user key: {e}"),
            )
        })?;
        let user_decryption_key_len = user_decryption_key_bytes.len() as i32 * 8;

        Ok(Object::PrivateKey {
            key_block: KeyBlock {
                cryptographic_algorithm: CryptographicAlgorithm::CoverCrypt,
                key_format_type: KeyFormatType::CoverCryptSecretKey,
                key_compression_type: None,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(user_decryption_key_bytes),
                    attributes: Some(usk_attributes),
                },
                cryptographic_length: user_decryption_key_len,
                key_wrapping_data: None,
            },
        })
    }
}
