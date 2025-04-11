use cloudproof::reexport::{
    cover_crypt::{abe_policy::Policy, Covercrypt, MasterPublicKey, MasterSecretKey},
    crypto_core::bytes_ser_de::Serializable,
};
use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PrivateKey, PublicKey},
        kmip_types::{
            CryptographicAlgorithm, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
            UniqueIdentifier,
        },
    },
};
use zeroize::Zeroizing;

use crate::{
    crypto::{
        cover_crypt::attributes::{policy_from_attributes, upsert_policy_in_attributes},
        KeyPair,
    },
    error::CryptoError,
};

/// Group a key UID with its KMIP Object
pub type KmipKeyUidObject = (String, Object);

/// Generate a `KeyPair` `(PrivateKey, MasterPublicKey)` from the attributes
/// of a `CreateKeyPair` operation
pub fn create_master_keypair(
    cover_crypt: &Covercrypt,
    private_key_uid: &str,
    public_key_uid: &str,
    mut common_attributes: Attributes,
    private_key_attributes: &Option<Attributes>,
    public_key_attributes: &Option<Attributes>,
) -> Result<KeyPair, CryptoError> {
    // Recover the policy
    let mut merged_attributes = common_attributes.clone();
    if let Some(private_key_attributes) = private_key_attributes {
        merged_attributes.merge(private_key_attributes, false);
    }
    if let Some(public_key_attributes) = public_key_attributes {
        merged_attributes.merge(public_key_attributes, false);
    }
    let policy = policy_from_attributes(&merged_attributes)?;

    // recover tags and clean them up from the common attributes
    let tags = common_attributes.remove_tags().unwrap_or_default();
    Attributes::check_user_tags(&tags)?;

    // Now generate a master key using the CoverCrypt Engine
    let (sk, pk) = cover_crypt
        .generate_master_keys(&policy)
        .map_err(|e| CryptoError::Kmip(e.to_string()))?;

    // Private Key generation
    // First generate fresh attributes with that policy
    let mut private_key_attributes = private_key_attributes.clone().unwrap_or_default();
    private_key_attributes.merge(&common_attributes, false);
    let sk_bytes = sk.serialize().map_err(|e| {
        CryptoError::Kmip(format!(
            "cover crypt: failed serializing the master private key: {e}"
        ))
    })?;
    let mut private_key = create_master_private_key_object(
        &sk_bytes,
        &policy,
        private_key_attributes.clone(),
        public_key_uid,
    )?;
    // Merge the created object attributes
    private_key_attributes.merge(private_key.attributes()?, true);
    // Set the private key UID
    private_key_attributes.unique_identifier =
        Some(UniqueIdentifier::TextString(private_key_uid.to_owned()));
    // Add the tags
    let mut sk_tags = tags.clone();
    sk_tags.insert("_sk".to_owned());
    private_key_attributes.set_tags(sk_tags)?;
    // and set them on the object
    private_key
        .key_block_mut()?
        .key_value
        .as_mut()
        .ok_or_else(|| CryptoError::Default("Key value not found in private key".to_owned()))?
        .attributes = Some(private_key_attributes);

    // Public Key generation
    // First generate fresh attributes with that policy
    let mut public_key_attributes = public_key_attributes.clone().unwrap_or_default();
    public_key_attributes.merge(&common_attributes, false);
    let pk_bytes = pk.serialize().map_err(|e| {
        CryptoError::Kmip(format!(
            "cover crypt: failed serializing the master public key: {e}"
        ))
    })?;
    let mut public_key = create_master_public_key_object(
        &pk_bytes,
        &policy,
        public_key_attributes.clone(),
        private_key_uid,
    )?;
    // Merge the created object attributes
    public_key_attributes.merge(public_key.attributes()?, true);
    // Set the public key UID
    public_key_attributes.unique_identifier =
        Some(UniqueIdentifier::TextString(public_key_uid.to_owned()));
    // Add the tags
    let mut pk_tags = tags;
    pk_tags.insert("_pk".to_owned());
    public_key_attributes.set_tags(pk_tags)?;
    // and set them on the object
    public_key
        .key_block_mut()?
        .key_value
        .as_mut()
        .ok_or_else(|| CryptoError::Default("Key value not found in public key".to_owned()))?
        .attributes = Some(public_key_attributes);

    Ok(KeyPair((private_key, public_key)))
}

fn create_master_private_key_object(
    key: &[u8],
    policy: &Policy,
    mut attributes: Attributes,
    master_public_key_uid: &str,
) -> Result<Object, CryptoError> {
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
    Ok(Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            key_format_type: KeyFormatType::CoverCryptSecretKey,
            key_compression_type: None,
            key_value: Some(KeyValue {
                key_material: KeyMaterial::ByteString(Zeroizing::from(key.to_vec())),
                attributes: Some(attributes),
            }),
            cryptographic_length,
            key_wrapping_data: None,
        },
    }))
}

/// Create a Master Public Key Object from the passed key bytes,
/// Policy and optional additional attributes
///
/// see `cover_crypt_unwrap_master_public_key` for the reverse operation
fn create_master_public_key_object(
    key: &[u8],
    policy: &Policy,
    mut attributes: Attributes,
    master_private_key_uid: &str,
) -> Result<Object, CryptoError> {
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
    // This is a public key, make sure it is not sensitive
    attributes.sensitive = Some(false);
    let cryptographic_length = Some(i32::try_from(key.len())? * 8);
    Ok(Object::PublicKey(PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
            key_format_type: KeyFormatType::CoverCryptPublicKey,
            key_compression_type: None,
            key_value: Some(KeyValue {
                key_material: KeyMaterial::ByteString(Zeroizing::from(key.to_vec())),
                attributes: Some(attributes),
            }),
            cryptographic_length,
            key_wrapping_data: None,
        },
    }))
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
    policy: &Policy,
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
    let updated_master_private_key = create_master_private_key_object(
        updated_master_private_key_bytes,
        policy,
        msk_obj.1.attributes()?.clone(),
        &mpk_obj.0,
    )?;
    let updated_master_public_key_bytes = &mpk.serialize().map_err(|e| {
        CryptoError::Kmip(format!(
            "Failed serializing the CoverCrypt Master Public Key: {e}"
        ))
    })?;
    let updated_master_public_key = create_master_public_key_object(
        updated_master_public_key_bytes,
        policy,
        mpk_obj.1.attributes()?.clone(),
        &msk_obj.0,
    )?;

    Ok((
        (msk_obj.0, updated_master_private_key),
        (mpk_obj.0, updated_master_public_key),
    ))
}
