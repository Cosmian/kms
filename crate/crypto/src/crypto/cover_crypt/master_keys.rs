use cosmian_cover_crypt::{api::Covercrypt, MasterPublicKey, MasterSecretKey};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kmip::kmip_2_1::{
    extra::VENDOR_ID_COSMIAN,
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, Link, LinkType,
        LinkedObjectIdentifier,
    },
};
use tracing::debug;
use zeroize::Zeroizing;

use crate::{
    crypto::{
        cover_crypt::attributes::{
            access_structure_from_attributes, VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE,
        },
        KeyPair,
    },
    error::CryptoError,
};

/// Group a key UID with its KMIP Object
pub type KmipKeyUidObject = (String, Object);

/// Generate a new Covercrypt master keypair the attributes of a `CreateKeyPair`
/// operation.
pub fn create_master_keypair(
    cover_crypt: &Covercrypt,
    private_key_uid: String,
    public_key_uid: &str,
    mut common_attributes: Attributes,
    msk_attributes: Option<Attributes>,
    mpk_attributes: Option<Attributes>,
    sensitive: bool,
) -> Result<KeyPair, CryptoError> {
    let access_structure = access_structure_from_attributes(&common_attributes)?;

    debug!("server: access_structure: {access_structure:?}");

    let (mut msk, _) = cover_crypt
        .setup()
        .map_err(|e| CryptoError::Kmip(e.to_string()))?;
    msk.access_structure = access_structure;
    let mpk = cover_crypt.update_msk(&mut msk)?;

    // Removes the access structure from the common attributes.
    common_attributes
        .remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE);

    let msk_owm = create_msk_object(
        msk.serialize()?,
        msk_attributes.unwrap_or_else(|| common_attributes.clone()),
        public_key_uid,
        sensitive,
    )?;

    let mpk_owm = create_mpk_object(
        mpk.serialize()?,
        mpk_attributes.unwrap_or(common_attributes),
        private_key_uid,
    )?;

    Ok(KeyPair((msk_owm, mpk_owm)))
}

pub fn create_msk_object(
    msk_bytes: Zeroizing<Vec<u8>>,
    mut attributes: Attributes,
    mpk_uid: &str,
    sensitive: bool,
) -> Result<Object, CryptoError> {
    debug!(
        "create_msk_object: key len: {}, attributes: {attributes:?}",
        msk_bytes.len()
    );

    attributes.object_type = Some(ObjectType::PrivateKey);
    attributes.key_format_type = Some(KeyFormatType::CoverCryptSecretKey);
    attributes.set_cryptographic_usage_mask_bits(CryptographicUsageMask::Unrestricted);
    attributes.link = Some(vec![Link {
        link_type: LinkType::PublicKeyLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString(mpk_uid.to_owned()),
    }]);
    attributes.sensitive = sensitive;

    let cryptographic_length = Some(i32::try_from(msk_bytes.len())? * 8);

    Ok(Object::PrivateKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            key_format_type: KeyFormatType::CoverCryptSecretKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(msk_bytes),
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
fn create_mpk_object(
    key: Zeroizing<Vec<u8>>,
    mut attributes: Attributes,
    msk_uid: String,
) -> Result<Object, CryptoError> {
    attributes.sensitive = false;
    attributes.object_type = Some(ObjectType::PublicKey);
    attributes.key_format_type = Some(KeyFormatType::CoverCryptPublicKey);
    // Covercrypt keys are set to have unrestricted usage.
    attributes.set_cryptographic_usage_mask_bits(CryptographicUsageMask::Unrestricted);
    // link the public key to the private key
    attributes.link = Some(vec![Link {
        link_type: LinkType::PrivateKeyLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString(msk_uid),
    }]);
    let cryptographic_length = Some(i32::try_from(key.len())? * 8);
    Ok(Object::PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            key_format_type: KeyFormatType::CoverCryptPublicKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(key),
                attributes: Some(attributes),
            },
            cryptographic_length,
            key_wrapping_data: None,
        },
    })
}

pub fn cc_master_keypair_from_kmip_objects(
    msk: &Object,
    mpk: &Object,
) -> Result<(MasterSecretKey, MasterPublicKey), CryptoError> {
    let msk_bytes = msk.key_block()?.key_bytes()?;
    let msk = MasterSecretKey::deserialize(&msk_bytes)
        .map_err(|e| CryptoError::Kmip(format!("Failed deserializing the Covercrypt MSK: {e}")))?;

    let mpk_bytes = mpk.key_block()?.key_bytes()?;
    let mpk = MasterPublicKey::deserialize(&mpk_bytes)
        .map_err(|e| CryptoError::Kmip(format!("Failed deserializing the Covercrypt MPK: {e}")))?;

    Ok((msk, mpk))
}

pub fn kmip_objects_from_cc_master_keypair(
    msk: &MasterSecretKey,
    mpk: &MasterPublicKey,
    mut msk_obj: Object,
    mut mpk_obj: Object,
) -> Result<(Object, Object), CryptoError> {
    let msk_bytes = msk
        .serialize()
        .map_err(|e| CryptoError::Kmip(format!("Failed serializing the Covercrypt MSK: {e}")))?;

    match &mut msk_obj.key_block_mut()?.key_value.key_material {
        KeyMaterial::ByteString(bytes) => {
            *bytes = msk_bytes;
            Ok(())
        }
        _ => Err(CryptoError::Kmip(
            "wrong key material type for MSK".to_owned(),
        )),
    }?;

    let mpk_bytes = mpk
        .serialize()
        .map_err(|e| CryptoError::Kmip(format!("Failed serializing the Covercrypt MPK: {e}")))?;

    match &mut mpk_obj.key_block_mut()?.key_value.key_material {
        KeyMaterial::ByteString(bytes) => {
            *bytes = mpk_bytes;
            Ok(())
        }
        _ => Err(CryptoError::Kmip(
            "wrong key material type for MPK".to_owned(),
        )),
    }?;

    Ok((msk_obj, mpk_obj))
}
