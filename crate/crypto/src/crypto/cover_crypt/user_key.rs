use cosmian_cover_crypt::{AccessPolicy, MasterSecretKey, UserSecretKey, api::Covercrypt};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PrivateKey},
        kmip_types::{
            CryptographicAlgorithm, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
            UniqueIdentifier,
        },
    },
};
use cosmian_logger::trace;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    crypto::cover_crypt::attributes::upsert_access_policy_in_attributes, error::CryptoError,
};

/// Unwrap the User Decryption Key bytes, Policy and Access Policy from the
/// provided User Decryption Key Object
///
/// see `cover_crypt_create_user_decryption_key_object` for the reverse operation
pub(crate) fn unwrap_user_decryption_key_object(
    user_decryption_key: &Object,
) -> Result<(Zeroizing<Vec<u8>>, Attributes), CryptoError> {
    let key_block = match &user_decryption_key {
        Object::PrivateKey(PrivateKey { key_block }) => key_block.clone(),
        _ => return Err(CryptoError::Kmip("Expected a KMIP Private Key".to_owned())),
    };
    if key_block.key_format_type != KeyFormatType::CoverCryptSecretKey {
        return Err(CryptoError::Kmip(
            "Expected an Covercrypt User Decryption Key".to_owned(),
        ));
    }
    let Some(KeyValue::Structure { key_material, .. }) = key_block.key_value.as_ref() else {
        return Err(CryptoError::Default(
            "Key value not found in Covercrypt user decryption key".to_owned(),
        ));
    };
    let bytes = match key_material {
        KeyMaterial::ByteString(b) => b.clone(),
        x => {
            return Err(CryptoError::Kmip(format!(
                "Invalid Key Material for the Covercrypt User Decryption Key: {x}"
            )));
        }
    };
    let attributes = key_block.attributes().map_err(|e| {
        CryptoError::Kmip(format!(
            "The CoverCrypt Master private key should have attributes: {e}"
        ))
    })?;
    Ok((bytes, attributes.clone()))
}

/// Handles operations on user keys, caching the engine
/// and the master key information for efficiency
pub struct UserDecryptionKeysHandler<'a> {
    cover_crypt: &'a Covercrypt,
    msk: &'a mut MasterSecretKey,
}

impl<'a> UserDecryptionKeysHandler<'a> {
    pub const fn instantiate(cover_crypt: &'a Covercrypt, msk: &'a mut MasterSecretKey) -> Self {
        Self { cover_crypt, msk }
    }

    /// Create a User Decryption Key Object from the passed master secret key bytes,
    /// Access Policy and optional additional attributes
    ///
    /// see `cover_crypt_unwrap_user_decryption_key` for the reverse operation
    pub fn create_usk_object(
        &mut self,
        access_policy: &str,
        create_attributes: &Attributes,
        msk_id: &str,
    ) -> Result<Object, CryptoError> {
        // Generate a fresh user decryption key
        //
        trace!("Access Policy: {access_policy:?}");
        let uk = self
            .cover_crypt
            .generate_user_secret_key(self.msk, &AccessPolicy::parse(access_policy)?)
            .map_err(|e| CryptoError::Kmip(e.to_string()))?;

        trace!("Created user decryption key with access policy: {access_policy:?}");
        let user_decryption_key_bytes = uk.serialize().map_err(|e| {
            CryptoError::Kmip(format!("covercrypt: failed serializing the user key: {e}"))
        })?;
        let user_decryption_key_len = user_decryption_key_bytes.len();

        // Tag the object as a private key
        let mut tags = create_attributes.get_tags();
        tags.insert("_uk".to_owned());

        // Set the unique identifier, if not provided, generate a new one
        let uid = match create_attributes
            .unique_identifier
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default()
        {
            uid if uid.is_empty() => Uuid::new_v4().to_string(),
            uid => uid,
        };

        let mut attributes = create_attributes.clone();
        attributes.object_type = Some(ObjectType::PrivateKey);
        attributes.cryptographic_algorithm = Some(CryptographicAlgorithm::CoverCrypt);
        // Covercrypt keys are set to have unrestricted usage.
        attributes.set_cryptographic_usage_mask_bits(CryptographicUsageMask::Unrestricted);
        // set the tags in the attributes
        attributes.set_tags(tags.clone())?;
        // set the unique identifier
        attributes.unique_identifier = Some(UniqueIdentifier::TextString(uid));

        // Add the access policy to the attributes
        upsert_access_policy_in_attributes(&mut attributes, access_policy)?;

        // Add the link to the master secret key
        attributes.link = Some(vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(msk_id.to_owned()),
        }]);
        let cryptographic_length = Some(i32::try_from(user_decryption_key_len)? * 8);
        Ok(Object::PrivateKey(PrivateKey {
            key_block: KeyBlock {
                cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
                key_format_type: KeyFormatType::CoverCryptSecretKey,
                key_compression_type: None,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(user_decryption_key_bytes),
                    attributes: Some(attributes),
                }),
                cryptographic_length,
                key_wrapping_data: None,
            },
        }))
    }

    /// Refresh the user decryption key according to the (new) policy of the master key
    pub fn refresh_usk_object(
        &mut self,
        user_decryption_key: &Object,
        keep_old_rights: bool,
    ) -> Result<Object, CryptoError> {
        let (usk_key_bytes, usk_attributes) =
            unwrap_user_decryption_key_object(user_decryption_key)?;
        let mut usk = UserSecretKey::deserialize(&usk_key_bytes).map_err(|e| {
            CryptoError::Kmip(format!(
                "covercrypt: failed deserializing the user decryption key: {e}"
            ))
        })?;

        self.cover_crypt
            .refresh_usk(self.msk, &mut usk, keep_old_rights)
            .map_err(|e| {
                CryptoError::Kmip(format!(
                    "covercrypt: failed refreshing the user decryption key: {e}"
                ))
            })?;

        trace!("Refreshed user decryption key {usk:?}");

        let user_decryption_key_bytes = usk.serialize().map_err(|e| {
            CryptoError::Kmip(format!("covercrypt: failed serializing the user key: {e}"))
        })?;
        let cryptographic_length = Some(i32::try_from(user_decryption_key_bytes.len())? * 8);
        Ok(Object::PrivateKey(PrivateKey {
            key_block: KeyBlock {
                cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
                key_format_type: KeyFormatType::CoverCryptSecretKey,
                key_compression_type: None,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(user_decryption_key_bytes),
                    attributes: Some(usk_attributes),
                }),
                cryptographic_length,
                key_wrapping_data: None,
            },
        }))
    }
}
