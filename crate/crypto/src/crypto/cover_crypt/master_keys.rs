use cosmian_cover_crypt::{api::Covercrypt, AccessStructure, MasterPublicKey, MasterSecretKey};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kmip::kmip_2_1::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, Link, LinkType,
        LinkedObjectIdentifier,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::{
    crypto::{
        cover_crypt::attributes::{
            access_structure_from_attributes, upsert_access_structure_in_attributes,
        },
        KeyPair,
    },
    error::CryptoError,
};

/// Group a key UID with its KMIP Object
pub type KmipKeyUidObject = (String, Object);

#[derive(Serialize, Deserialize, Debug)]
pub struct PolicySpecs {
    pub security_level: Vec<String>,
    pub department: Vec<String>,
}
/// Generate a `KeyPair` `(PrivateKey, MasterPublicKey)` from the attributes
/// of a `CreateKeyPair` operation
pub fn create_master_keypair(
    cover_crypt: &Covercrypt,
    private_key_uid: &str,
    public_key_uid: &str,
    common_attributes: &Option<Attributes>,
    private_key_attributes: &Option<Attributes>,
    public_key_attributes: &Option<Attributes>,
) -> Result<KeyPair, CryptoError> {
    let access_structure =
        access_structure_from_attributes(&common_attributes.clone().unwrap_or_default())?;
    debug!("server: access_structure: {access_structure:?}");

    // Now generate a master key using the Covercrypt Engine
    let (mut msk, _mpk) = cover_crypt
        .setup()
        .map_err(|e| CryptoError::Kmip(e.to_string()))?;

    msk.access_structure = access_structure;

    let mpk = cover_crypt.update_msk(&mut msk)?;

    // First generate fresh attributes with that policy
    let private_key_attributes = private_key_attributes.as_ref();
    let private_key = create_master_private_key_object(
        &msk.serialize()?,
        private_key_attributes,
        public_key_uid,
        &msk.access_structure,
    )?;

    // Public Key generation
    // First generate fresh attributes with that policy
    let public_key_attributes = public_key_attributes.as_ref();
    let public_key =
        create_master_public_key_object(&mpk.serialize()?, public_key_attributes, private_key_uid)?;
    Ok(KeyPair((private_key, public_key)))
}

fn create_master_private_key_object(
    key: &[u8],
    attributes: Option<&Attributes>,
    master_public_key_uid: &str,
    access_structure: &AccessStructure,
) -> Result<Object, CryptoError> {
    debug!("create_master_private_key_object: key len: {}", key.len());
    let mut attributes = attributes.cloned().unwrap_or_default();
    attributes.object_type = Some(ObjectType::PrivateKey);
    attributes.key_format_type = Some(KeyFormatType::CoverCryptSecretKey);
    // Covercrypt keys are set to have unrestricted usage.
    attributes.set_cryptographic_usage_mask_bits(CryptographicUsageMask::Unrestricted);
    // add the policy to the attributes
    upsert_access_structure_in_attributes(&mut attributes, access_structure)?;
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
    attributes: Option<&Attributes>,
    master_private_key_uid: &str,
) -> Result<Object, CryptoError> {
    let mut attributes = attributes.cloned().unwrap_or_default();
    attributes.sensitive = false;
    attributes.object_type = Some(ObjectType::PublicKey);
    attributes.key_format_type = Some(KeyFormatType::CoverCryptPublicKey);
    // Covercrypt keys are set to have unrestricted usage.
    attributes.set_cryptographic_usage_mask_bits(CryptographicUsageMask::Unrestricted);
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
) -> Result<(MasterSecretKey, MasterPublicKey), CryptoError> {
    // Recover the Covercrypt PrivateKey Object
    let msk_key_block = master_private_key.key_block()?;
    let msk_key_bytes = msk_key_block.key_bytes()?;
    trace!(
        "covercrypt_keys_from_kmip_objects: msk_key_bytes len: {}",
        msk_key_bytes.len()
    );
    let msk = MasterSecretKey::deserialize(&msk_key_bytes).map_err(|e| {
        CryptoError::Kmip(format!(
            "Failed deserializing the Covercrypt Master Private Key: {e}"
        ))
    })?;

    // Recover the Covercrypt MasterPublicKey Object
    let mpk_key_block = master_public_key.key_block()?;
    let mpk_key_bytes = mpk_key_block.key_bytes()?;
    let mpk = MasterPublicKey::deserialize(&mpk_key_bytes).map_err(|e| {
        CryptoError::Kmip(format!(
            "Failed deserializing the Covercrypt Master Public Key: {e}"
        ))
    })?;

    Ok((msk, mpk))
}

pub fn kmip_objects_from_covercrypt_keys(
    msk: &MasterSecretKey,
    mpk: &MasterPublicKey,
    msk_obj: KmipKeyUidObject,
    mpk_obj: KmipKeyUidObject,
) -> Result<(KmipKeyUidObject, KmipKeyUidObject), CryptoError> {
    let updated_master_private_key_bytes = &msk.serialize()?;
    trace!(
        "kmip_objects_from_covercrypt_keys: updated_master_private_key_bytes len: {}",
        updated_master_private_key_bytes.len()
    );
    let updated_master_private_key = create_master_private_key_object(
        updated_master_private_key_bytes,
        Some(msk_obj.1.attributes()?),
        &mpk_obj.0,
        &msk.access_structure,
    )?;
    let updated_master_public_key_bytes = &mpk.serialize().map_err(|e| {
        CryptoError::Kmip(format!(
            "Failed serializing the Covercrypt Master Public Key: {e}"
        ))
    })?;
    let updated_master_public_key = create_master_public_key_object(
        updated_master_public_key_bytes,
        Some(mpk_obj.1.attributes()?),
        &msk_obj.0,
    )?;

    Ok((
        (msk_obj.0, updated_master_private_key),
        (mpk_obj.0, updated_master_public_key),
    ))
}
