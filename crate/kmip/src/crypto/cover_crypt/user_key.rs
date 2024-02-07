use cloudproof::reexport::{
    cover_crypt::{
        abe_policy::{AccessPolicy, Policy},
        Covercrypt, MasterSecretKey, UserSecretKey,
    },
    crypto_core::bytes_ser_de::Serializable,
};
use tracing::trace;

use crate::{
    crypto::cover_crypt::attributes::{
        access_policy_from_attributes, policy_from_attributes, upsert_access_policy_in_attributes,
    },
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_operations::ErrorReason,
        kmip_types::{
            Attributes, CryptographicAlgorithm, KeyFormatType, Link, LinkType,
            LinkedObjectIdentifier,
        },
    },
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
    Ok((
        bytes,
        AccessPolicy::from_boolean_expression(access_policy.as_str())?,
        attributes.clone(),
    ))
}

/// Handles operations on user keys, caching the engine
/// and the master key information for efficiency
pub struct UserDecryptionKeysHandler {
    cover_crypt: Covercrypt,
    master_private_key: MasterSecretKey,
    policy: Policy,
}

impl UserDecryptionKeysHandler {
    pub fn instantiate(
        cover_crypt: Covercrypt,
        master_private_key: &Object,
    ) -> Result<Self, KmipError> {
        let msk_key_block = master_private_key.key_block()?;
        let msk_key_bytes = msk_key_block.key_bytes()?;
        let msk = MasterSecretKey::deserialize(&msk_key_bytes).map_err(|e| {
            KmipError::KmipError(
                ErrorReason::Codec_Error,
                format!("cover crypt: failed deserializing the master private key: {e}"),
            )
        })?;
        let private_key_attributes = master_private_key.attributes()?;
        let policy = policy_from_attributes(private_key_attributes)?;
        Ok(Self {
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
        access_policy_str: &str,
        attributes: Option<&Attributes>,
        master_private_key_id: &str,
    ) -> Result<Object, KmipError> {
        //
        // Generate a fresh user decryption key
        //
        // let access_policy = AccessPolicy::try_from(access_policy_str)?;
        let access_policy = AccessPolicy::from_boolean_expression(access_policy_str)?;

        let uk = self
            .cover_crypt
            .generate_user_secret_key(&self.master_private_key, &access_policy, &self.policy)
            .map_err(|e| {
                KmipError::InvalidKmipValue(ErrorReason::Invalid_Attribute_Value, e.to_string())
            })?;
        trace!("Created user decryption key {uk:?} with access policy: {access_policy:?}");
        let user_decryption_key_bytes = uk.serialize().map_err(|e| {
            KmipError::KmipError(
                ErrorReason::Codec_Error,
                format!("cover crypt: failed serializing the user key: {e}"),
            )
        })?;
        let user_decryption_key_len = user_decryption_key_bytes.len();

        let mut attributes = attributes.cloned().unwrap_or_default();
        attributes.object_type = Some(ObjectType::PrivateKey);

        // Add the access policy to the attributes
        upsert_access_policy_in_attributes(&mut attributes, access_policy_str)?;

        // Add the link to the master private key
        attributes.link = Some(vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                master_private_key_id.to_string(),
            ),
        }]);
        Ok(Object::PrivateKey {
            key_block: KeyBlock {
                cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
                key_format_type: KeyFormatType::CoverCryptSecretKey,
                key_compression_type: None,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(user_decryption_key_bytes.to_vec()),
                    attributes: Some(attributes),
                },
                cryptographic_length: Some(user_decryption_key_len as i32 * 8),
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
        let mut usk = UserSecretKey::deserialize(&usk_key_bytes).map_err(|e| {
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

        let user_decryption_key_bytes = usk.serialize().map_err(|e| {
            KmipError::KmipError(
                ErrorReason::Codec_Error,
                format!("cover crypt: failed serializing the user key: {e}"),
            )
        })?;
        let user_decryption_key_len = user_decryption_key_bytes.len() as i32 * 8;

        Ok(Object::PrivateKey {
            key_block: KeyBlock {
                cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
                key_format_type: KeyFormatType::CoverCryptSecretKey,
                key_compression_type: None,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(user_decryption_key_bytes.to_vec()),
                    attributes: Some(usk_attributes),
                },
                cryptographic_length: Some(user_decryption_key_len),
                key_wrapping_data: None,
            },
        })
    }
}
