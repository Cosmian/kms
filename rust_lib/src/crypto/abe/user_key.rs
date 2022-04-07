use abe_gpsw::core::{
    bilinear_map::bls12_381::Bls12_381,
    gpsw::{AbeScheme, AsBytes, Gpsw},
    policy::{AccessPolicy, Policy},
    Engine,
};
use cosmian_kms_common::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_operations::ErrorReason,
    kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType},
};
use tracing::trace;

use crate::{
    crypto::abe::attributes::{access_policy_from_attributes, upsert_access_policy_in_attributes},
    error::LibError,
    lib_error,
    result::{LibResult, LibResultHelper},
};

/// Create a User Decryption Key Object from the passed master private key bytes,
/// Policy, Access Policy and optional additional attributes
///
/// see `abe_unwrap_user_decryption_key` for the reverse operation
pub fn create_user_decryption_key_object(
    master_private_key_bytes: &[u8],
    policy: &Policy,
    access_policy: &AccessPolicy,
    attributes: Option<&Attributes>,
) -> LibResult<Object> {
    //
    // Generate a fresh user decryption key
    //
    let engine = Engine::<Gpsw<Bls12_381>>::new();
    let master_private_key =
        <Gpsw<Bls12_381> as AbeScheme>::MasterPrivateKey::from_bytes(master_private_key_bytes)?;
    let uk = engine.generate_user_key(policy, &master_private_key, access_policy)?;
    trace!(
        "Created user decryption key {} with access policy: {:?}",
        &uk,
        &access_policy
    );
    let user_decryption_key_bytes = uk.as_bytes()?;
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
            cryptographic_algorithm: CryptographicAlgorithm::ABE,
            key_format_type: KeyFormatType::AbeUserDecryptionKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
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
/// see `abe_create_user_decryption_key_object` for the reverse operation
pub(crate) fn unwrap_user_decryption_key_object(
    user_decryption_key: &Object,
) -> LibResult<(Vec<u8>, AccessPolicy, Attributes)> {
    let key_block = match &user_decryption_key {
        Object::PrivateKey { key_block } => key_block.clone(),
        _ => {
            return Err(LibError::Error("Expected a KMIP Private Key".to_owned()))
                .reason(ErrorReason::Invalid_Object_Type)
        }
    };
    if key_block.key_format_type != KeyFormatType::AbeUserDecryptionKey {
        return Err(LibError::Error(
            "Expected an ABE User Decryption Key".to_owned(),
        ))
        .reason(ErrorReason::Invalid_Object_Type)
    }
    let (key_material, attributes) = key_block
        .key_value
        .plaintext()
        .ok_or_else(|| LibError::Error("invalid Plain Text".to_owned()))?;
    let bytes = match key_material {
        KeyMaterial::ByteString(b) => b.clone(),
        x => {
            return Err(lib_error!(
                "Invalid Key Material for the ABE User Decryption Key: {:?}",
                x
            ))
            .reason(ErrorReason::Invalid_Object_Type)
        }
    };
    let attributes = attributes
        .as_ref()
        .context("The ABE Master private key should have attributes")
        .reason(ErrorReason::Attribute_Not_Found)?
        .clone();
    let access_policy = access_policy_from_attributes(&attributes)?;
    Ok((bytes, access_policy, attributes))
}
