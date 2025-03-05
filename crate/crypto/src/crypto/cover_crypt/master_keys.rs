use cosmian_cover_crypt::{api::Covercrypt, MasterPublicKey, MasterSecretKey};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kmip::kmip_2_1::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, Link, LinkType,
        LinkedObjectIdentifier,
    },
};
use zeroize::Zeroizing;

use crate::{crypto::KeyPair, error::CryptoError};

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
) -> Result<KeyPair, CryptoError> {
    let _any_attributes = common_attributes
        .as_ref()
        .or(private_key_attributes.as_ref())
        .or(public_key_attributes.as_ref())
        .ok_or_else(|| {
            CryptoError::Kmip("Attributes must be provided in a CreateKeyPair request".to_owned())
        })?;

    let access_structure = common_attributes
        .as_ref()
        .expect("LINK")
        .get_link(LinkType::ChildLink)
        .expect("klm")
        .to_string();
    println!("create keypair: {access_structure:?}");
    // Now generate a master key using the CoverCrypt Engine
    let (msk, mpk) = cover_crypt
        .setup()
        .map_err(|e| CryptoError::Kmip(e.to_string()))?;

    let json_struct = serde_json::from_str::<serde_json::Value>(&access_structure)?;
    //let json_struct: Struct = serde_json::from_str(&access_structure)?;

    println!("create keypair json: {json_struct:?}");

    // for (name, attributes) in json_struct {
    //     if name.contains("Security") {
    //         let n = name.trim_end_matches("::<");
    //         msk.access_structure.add_hierarchy(n.to_owned())?;
    //     } else {
    //         msk.access_structure.add_anarchy(name.clone())?;
    //     }

    //     for attr in attributes {
    //         msk.access_structure.add_attribute(
    //             QualifiedAttribute {
    //                 dimension: name.clone(),
    //                 name: attr.trim_end_matches("::+").to_owned(),
    //             },
    //             if attr.contains("::+") {
    //                 EncryptionHint::Hybridized
    //             } else {
    //                 EncryptionHint::Classic
    //             },
    //             None,
    //         )?;
    //     }
    // }

    // let mpk = cover_crypt.update_msk(&mut msk)?;
    // println!("MSK AS : {:?}", msk.access_structure);

    // First generate fresh attributes with that policy
    let private_key_attributes = private_key_attributes.as_ref();
    let sk_bytes = msk.serialize().map_err(|e| {
        CryptoError::Kmip(format!(
            "cover crypt: failed serializing the master private key: {e}"
        ))
    })?;
    let private_key = create_master_private_key_object(
        &access_structure,
        &sk_bytes,
        private_key_attributes,
        public_key_uid,
    )?;

    // Public Key generation
    // First generate fresh attributes with that policy
    let public_key_attributes = public_key_attributes.as_ref();
    let pk_bytes = mpk.serialize().map_err(|e| {
        CryptoError::Kmip(format!(
            "cover crypt: failed serializing the master public key: {e}"
        ))
    })?;
    let public_key =
        create_master_public_key_object(&pk_bytes, public_key_attributes, private_key_uid)?;

    Ok(KeyPair((private_key, public_key)))
}

fn create_master_private_key_object(
    access_structure: &str,
    key: &[u8],
    attributes: Option<&Attributes>,
    master_public_key_uid: &str,
) -> Result<Object, CryptoError> {
    let mut attributes = attributes.cloned().unwrap_or_default();
    attributes.object_type = Some(ObjectType::PrivateKey);
    attributes.key_format_type = Some(KeyFormatType::CoverCryptSecretKey);
    // Covercrypt keys are set to have unrestricted usage.
    attributes.set_cryptographic_usage_mask_bits(CryptographicUsageMask::Unrestricted);
    // link the private key to the public key
    attributes.link = Some(vec![
        Link {
            link_type: LinkType::PublicKeyLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                master_public_key_uid.to_owned(),
            ),
        },
        Link {
            link_type: LinkType::ChildLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                access_structure.to_owned(),
            ),
        },
    ]);
    let cryptographic_length = Some(i32::try_from(key.len())? * 8);
    println!("master key: {attributes:?}");

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
    // Recover the CoverCrypt PrivateKey Object
    let msk_key_block = master_private_key.key_block()?;
    let msk_key_bytes = msk_key_block.key_bytes()?;
    let msk = MasterSecretKey::deserialize(&msk_key_bytes).map_err(|e| {
        CryptoError::Kmip(format!(
            "Failed deserializing the CoverCrypt Master Private Key: {e}"
        ))
    })?;

    // Recover the CoverCrypt MasterPublicKey Object
    let mpk_key_block = master_public_key.key_block()?;
    let mpk_key_bytes = mpk_key_block.key_bytes()?;
    let mpk = MasterPublicKey::deserialize(&mpk_key_bytes).map_err(|e| {
        CryptoError::Kmip(format!(
            "Failed deserializing the CoverCrypt Master Public Key: {e}"
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
    let updated_master_private_key_bytes = &msk.serialize().map_err(|e| {
        CryptoError::Kmip(format!(
            "Failed serializing the CoverCrypt Master Private Key: {e}"
        ))
    })?;
    let ser_access_structure = msk.access_structure.serialize()?;
    let str_access_structure = &serde_json::to_string(&ser_access_structure)?;
    let updated_master_private_key = create_master_private_key_object(
        str_access_structure,
        updated_master_private_key_bytes,
        Some(msk_obj.1.attributes()?),
        &mpk_obj.0,
    )?;
    let updated_master_public_key_bytes = &mpk.serialize().map_err(|e| {
        CryptoError::Kmip(format!(
            "Failed serializing the CoverCrypt Master Public Key: {e}"
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
