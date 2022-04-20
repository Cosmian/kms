use abe_gpsw::core::{
    bilinear_map::bls12_381::Bls12_381,
    gpsw::{AsBytes, Gpsw},
    policy::Policy,
    Engine,
};
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{CreateKeyPair, ErrorReason},
        kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType},
    },
};

use crate::{
    crypto::abe::attributes::{policy_from_attributes, upsert_policy_in_attributes},
    KeyPair,
};

/// Generate a `KeyPair` `(PrivateKey, PublicKey)` from the attributes
/// of a `CreateKeyPair` operation
pub fn create_master_keypair(request: &CreateKeyPair) -> Result<KeyPair, KmipError> {
    let attributes = request
        .common_attributes
        .as_ref()
        .or(request.private_key_attributes.as_ref())
        .or(request.public_key_attributes.as_ref())
        .ok_or_else(|| {
            KmipError::InvalidKmipValue(
                ErrorReason::Attribute_Not_Found,
                "Attributes must be provided in a CreateKeyPair request".to_owned(),
            )
        })?;

    // verify that we can recover the policy
    let policy = policy_from_attributes(attributes)?;

    // Now generate a master key using the ABE Engine
    let engine = Engine::<Gpsw<Bls12_381>>::new();
    let mk = engine
        .generate_master_key(&policy)
        .map_err(|e| KmipError::InvalidKmipValue(ErrorReason::Invalid_Message, e.to_string()))?;

    // Private Key generation
    // First generate fresh attributes with that policy
    let private_key_attributes = request
        .private_key_attributes
        .as_ref()
        .or(request.common_attributes.as_ref());
    let private_key = create_master_private_key_object(
        &mk.0.as_bytes().map_err(|e| {
            KmipError::InvalidKmipValue(ErrorReason::Invalid_Message, e.to_string())
        })?,
        &policy,
        private_key_attributes,
    )?;

    // Public Key generation
    // First generate fresh attributes with that policy
    let public_key_attributes = request
        .public_key_attributes
        .as_ref()
        .or(request.common_attributes.as_ref());
    let public_key = create_master_public_key_object(
        &mk.1.as_bytes().map_err(|e| {
            KmipError::InvalidKmipValue(ErrorReason::Invalid_Message, e.to_string())
        })?,
        &policy,
        public_key_attributes,
    )?;

    Ok(KeyPair((private_key, public_key)))
}

fn create_master_private_key_object(
    key: &[u8],
    policy: &Policy,
    attributes: Option<&Attributes>,
) -> Result<Object, KmipError> {
    let mut attributes = attributes
        .map(|att| {
            let mut att = att.clone();
            att.object_type = ObjectType::PrivateKey;
            att
        })
        .unwrap_or_else(|| Attributes::new(ObjectType::PrivateKey));
    upsert_policy_in_attributes(&mut attributes, policy)?;
    Ok(Object::PrivateKey {
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::ABE,
            key_format_type: KeyFormatType::AbeMasterSecretKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
                key_material: KeyMaterial::ByteString(key.to_vec()),
                attributes: Some(attributes),
            },
            cryptographic_length: key.len() as i32,
            key_wrapping_data: None,
        },
    })
}

/// Create a Master Public Key Object from the passed key bytes,
/// Policy and optional additional attributes
///
/// see `abe_unwrap_master_public_key` for the reverse operation
fn create_master_public_key_object(
    key: &[u8],
    policy: &Policy,
    attributes: Option<&Attributes>,
) -> Result<Object, KmipError> {
    let mut attributes = attributes
        .map(|att| {
            let mut att = att.clone();
            att.object_type = ObjectType::PublicKey;
            att
        })
        .unwrap_or_else(|| Attributes::new(ObjectType::PublicKey));
    upsert_policy_in_attributes(&mut attributes, policy)?;
    Ok(Object::PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::ABE,
            key_format_type: KeyFormatType::AbeMasterPublicKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
                key_material: KeyMaterial::ByteString(key.to_vec()),
                attributes: Some(attributes),
            },
            cryptographic_length: key.len() as i32,
            key_wrapping_data: None,
        },
    })
}
