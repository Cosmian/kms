use cloudproof::reexport::{
    cover_crypt::{abe_policy::Policy, Covercrypt, MasterPublicKey, MasterSecretKey},
    crypto_core::bytes_ser_de::Serializable,
};
use zeroize::Zeroizing;

use crate::{
    crypto::{
        cover_crypt::attributes::{policy_from_attributes, upsert_policy_in_attributes},
        KeyPair,
    },
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_operations::ErrorReason,
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, Link,
            LinkType, LinkedObjectIdentifier,
        },
    },
};

/// Group a key UID with its KMIP Object
pub type KmipKeyUidObject = (String, Object);

/// Generate a `KeyPair` `(PrivateKey, MasterPublicKey)` from the attributes
/// of a `CreateKeyPair` operation
pub fn create_master_keypair(
    cover_crypt: &Covercrypt,
    private_key_uid: &str,
    public_key_uid: &str,
    common_attributes: &Option<Attributes>,
    private_key_attributes: &Option<Attributes>,
    public_key_attributes: &Option<Attributes>,
) -> Result<KeyPair, KmipError> {
    let any_attributes = common_attributes
        .as_ref()
        .or(private_key_attributes.as_ref())
        .or(public_key_attributes.as_ref())
        .ok_or_else(|| {
            KmipError::InvalidKmipValue(
                ErrorReason::Attribute_Not_Found,
                "Attributes must be provided in a CreateKeyPair request".to_owned(),
            )
        })?;

    // verify that we can recover the policy
    let policy = policy_from_attributes(any_attributes)?;

    // Now generate a master key using the CoverCrypt Engine
    let (sk, pk) = cover_crypt
        .generate_master_keys(&policy)
        .map_err(|e| KmipError::InvalidKmipValue(ErrorReason::Invalid_Message, e.to_string()))?;

    // Private Key generation
    // First generate fresh attributes with that policy
    let private_key_attributes = private_key_attributes
        .as_ref()
        .or(common_attributes.as_ref());
    let sk_bytes = sk.serialize().map_err(|e| {
        KmipError::KmipError(
            ErrorReason::Codec_Error,
            format!("cover crypt: failed serializing the master private key: {e}"),
        )
    })?;
    let private_key = create_master_private_key_object(
        &sk_bytes,
        &policy,
        private_key_attributes,
        public_key_uid,
    )?;

    // Public Key generation
    // First generate fresh attributes with that policy
    let public_key_attributes = public_key_attributes
        .as_ref()
        .or(common_attributes.as_ref());
    let pk_bytes = pk.serialize().map_err(|e| {
        KmipError::KmipError(
            ErrorReason::Codec_Error,
            format!("cover crypt: failed serializing the master public key: {e}"),
        )
    })?;
    let public_key = create_master_public_key_object(
        &pk_bytes,
        &policy,
        public_key_attributes,
        private_key_uid,
    )?;

    Ok(KeyPair((private_key, public_key)))
}

fn create_master_private_key_object(
    key: &[u8],
    policy: &Policy,
    attributes: Option<&Attributes>,
    master_public_key_uid: &str,
) -> Result<Object, KmipError> {
    let mut attributes = attributes.cloned().unwrap_or_default();
    attributes.object_type = Some(ObjectType::PrivateKey);
    attributes.key_format_type = Some(KeyFormatType::CoverCryptSecretKey);
    // Covercrypt keys are set to have unrestricted usage.
    attributes.set_cryptographic_usage_mask_bits(CryptographicUsageMask::Unrestricted);
    // add the policy to the attributes
    upsert_policy_in_attributes(&mut attributes, policy)?;
    // link the private key to the public key
    attributes.link = Some(vec![Link {
        link_type: LinkType::PublicKeyLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString(
            master_public_key_uid.to_owned(),
        ),
    }]);
    let cryptographic_length = Some(i32::try_from(key.len())? * 8);
    Ok(Object::PrivateKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            key_format_type: KeyFormatType::CoverCryptSecretKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(Zeroizing::from(key.to_vec())),
                attributes: Some(attributes),
            },
            cryptographic_length,
            key_wrapping_data: None,
        },
    })
}

/// Create a Master Public Key Object from the passed key bytes,
/// Policy and optional additional attributes
///
/// see `cover_crypt_unwrap_master_public_key` for the reverse operation
fn create_master_public_key_object(
    key: &[u8],
    policy: &Policy,
    attributes: Option<&Attributes>,
    master_private_key_uid: &str,
) -> Result<Object, KmipError> {
    let mut attributes = attributes.cloned().unwrap_or_default();
    attributes.sensitive = false;
    attributes.object_type = Some(ObjectType::PublicKey);
    attributes.key_format_type = Some(KeyFormatType::CoverCryptPublicKey);
    // Covercrypt keys are set to have unrestricted usage.
    attributes.set_cryptographic_usage_mask_bits(CryptographicUsageMask::Unrestricted);
    // add the policy to the attributes
    upsert_policy_in_attributes(&mut attributes, policy)?;
    // link the public key to the private key
    attributes.link = Some(vec![Link {
        link_type: LinkType::PrivateKeyLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString(
            master_private_key_uid.to_owned(),
        ),
    }]);
    let cryptographic_length = Some(i32::try_from(key.len())? * 8);
    Ok(Object::PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            key_format_type: KeyFormatType::CoverCryptPublicKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(Zeroizing::from(key.to_vec())),
                attributes: Some(attributes),
            },
            cryptographic_length,
            key_wrapping_data: None,
        },
    })
}

pub fn covercrypt_keys_from_kmip_objects(
    master_private_key: &Object,
    master_public_key: &Object,
) -> Result<(MasterSecretKey, MasterPublicKey), KmipError> {
    // Recover the CoverCrypt PrivateKey Object
    let msk_key_block = master_private_key.key_block()?;
    let msk_key_bytes = msk_key_block.key_bytes()?;
    let msk = MasterSecretKey::deserialize(&msk_key_bytes).map_err(|e| {
        KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Data_Type,
            format!("Failed deserializing the CoverCrypt Master Private Key: {e}"),
        )
    })?;

    // Recover the CoverCrypt MasterPublicKey Object
    let mpk_key_block = master_public_key.key_block()?;
    let mpk_key_bytes = mpk_key_block.key_bytes()?;
    let mpk = MasterPublicKey::deserialize(&mpk_key_bytes).map_err(|e| {
        KmipError::InvalidKmipObject(
            ErrorReason::Invalid_Data_Type,
            format!("Failed deserializing the CoverCrypt Master Public Key: {e}"),
        )
    })?;

    Ok((msk, mpk))
}

pub fn kmip_objects_from_covercrypt_keys(
    policy: &Policy,
    msk: &MasterSecretKey,
    mpk: &MasterPublicKey,
    msk_obj: KmipKeyUidObject,
    mpk_obj: KmipKeyUidObject,
) -> Result<(KmipKeyUidObject, KmipKeyUidObject), KmipError> {
    let updated_master_private_key_bytes = &msk.serialize().map_err(|e| {
        KmipError::KmipError(
            ErrorReason::Cryptographic_Failure,
            format!("Failed serializing the CoverCrypt Master Private Key: {e}"),
        )
    })?;
    let updated_master_private_key = create_master_private_key_object(
        updated_master_private_key_bytes,
        policy,
        Some(msk_obj.1.attributes()?),
        &mpk_obj.0,
    )?;
    let updated_master_public_key_bytes = &mpk.serialize().map_err(|e| {
        KmipError::KmipError(
            ErrorReason::Cryptographic_Failure,
            format!("Failed serializing the CoverCrypt Master Public Key: {e}"),
        )
    })?;
    let updated_master_public_key = create_master_public_key_object(
        updated_master_public_key_bytes,
        policy,
        Some(mpk_obj.1.attributes()?),
        &msk_obj.0,
    )?;

    Ok((
        (msk_obj.0, updated_master_private_key),
        (mpk_obj.0, updated_master_public_key),
    ))
}
