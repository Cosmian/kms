use std::convert::TryFrom;

use abe_gpsw::core::{
    bilinear_map::bls12_381::Bls12_381,
    gpsw::{AbeScheme, AsBytes, Gpsw},
    policy::{AccessPolicy, Attribute as PolicyAttribute},
    Engine,
};
use cosmian_crypto_base::symmetric_crypto::aes_256_gcm_pure;
use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial},
    kmip_objects::{Object, ObjectType},
    kmip_operations::{ErrorReason, GetResponse},
    kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::{
    crypto::abe::attributes::{access_policy_as_vendor_attribute, policy_from_attributes},
    error::LibError,
    kmip_utils::key_bytes_and_attributes_from_key_block,
    lib_ensure,
    result::{LibResult, LibResultHelper},
};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// ABE setup parameters for KMIP //////////////////
///////////////////////////////////////////////////////////////////////////////

/// The whole Key Value structure is wrapped
/// A reference to the ABE master public key is kept to access to policy later
/// when locating symmetric keys
pub fn wrapped_secret_key(
    public_key_response: &GetResponse,
    access_policy: &AccessPolicy,
    abe_header_uid: &[u8],
) -> LibResult<Object> {
    let sk = prepare_symmetric_key(
        public_key_response,
        &access_policy.attributes(),
        abe_header_uid,
    )?;
    // Since KMIP 2.1 does not plan to locate wrapped key, we Serialize vendor
    // attributes and symmetric key consecutively
    let wrapped_key_attributes = Attributes {
        vendor_attributes: Some(vec![access_policy_as_vendor_attribute(access_policy)?]),
        ..Attributes::new(ObjectType::SymmetricKey)
    };
    Ok(Object::SymmetricKey {
        key_block: KeyBlock::to_wrapped_key_block(
            &sk.encrypted_symmetric_key,
            None,
            KeyFormatType::AbeSymmetricKey,
            &wrapped_key_attributes,
        )?,
    })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ABESymmetricKey {
    pub symmetric_key: Vec<u8>,
    pub uid: Vec<u8>,
    pub encrypted_symmetric_key: Vec<u8>,
}

fn prepare_symmetric_key(
    public_key_response: &GetResponse,
    policy_attributes: &[PolicyAttribute],
    abe_header_uid: &[u8],
) -> LibResult<ABESymmetricKey> {
    trace!("Starting create secret key");

    let (public_key_bytes, public_key_attributes) = key_bytes_and_attributes_from_key_block(
        public_key_response.object.key_block()?,
        &public_key_response.unique_identifier,
    )?;
    let public_key =
        <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey::from_bytes(&public_key_bytes)?;

    let policy = policy_from_attributes(&public_key_attributes.ok_or_else(|| {
        LibError::InvalidKmipObject(
            ErrorReason::Attribute_Not_Found,
            "the master public key does not have attributes with the Policy".to_string(),
        )
    })?)?;

    let engine = Engine::<Gpsw<Bls12_381>>::new();
    let (sk, sk_enc) = engine.generate_symmetric_key(
        &policy,
        &public_key,
        policy_attributes,
        aes_256_gcm_pure::KEY_LENGTH,
    )?;

    debug!("Generate symmetric key for ABE OK");
    Ok(ABESymmetricKey {
        uid: abe_header_uid.to_vec(),
        symmetric_key: sk,
        encrypted_symmetric_key: sk_enc,
    })
}

impl TryFrom<&KeyBlock> for ABESymmetricKey {
    type Error = LibError;

    fn try_from(sk: &KeyBlock) -> LibResult<Self> {
        lib_ensure!(
            sk.cryptographic_algorithm == CryptographicAlgorithm::ABE,
            "this Secret Key does not contain an ABE key"
        );
        lib_ensure!(
            sk.key_format_type == KeyFormatType::AbeSymmetricKey,
            "this Secret Key does not contain an ABE Key"
        );
        lib_ensure!(
            sk.key_wrapping_data.is_none(),
            "unwrapping an ABE Secret Key is not yet supported",
        );
        let (key_material, _) = sk
            .key_value
            .plaintext()
            .ok_or_else(|| LibError::Error("invalid Plain Text".to_owned()))?;
        serde_json::from_slice::<ABESymmetricKey>(match key_material {
            KeyMaterial::TransparentSymmetricKey { key } => key,
            other => {
                return Err(LibError::Error(format!(
                    "Invalid key material for an ABE secret key: {:?}",
                    other
                )))
            }
        })
        .context("failed deserializing the ABE Secret Key from the Key Material")
    }
}
