use std::convert::TryFrom;

use abe_gpsw::core::{
    bilinear_map::bls12_381::Bls12_381,
    gpsw::{AbeScheme, AsBytes, Gpsw},
    policy::{AccessPolicy, Attribute as PolicyAttribute},
    Engine,
};
use cosmian_crypto_base::symmetric_crypto::aes_256_gcm_pure;
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial},
        kmip_objects::{Object, ObjectType},
        kmip_operations::{ErrorReason, GetResponse},
        kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType},
    },
};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::{
    crypto::abe::attributes::{access_policy_as_vendor_attribute, policy_from_attributes},
    kmip_utils::key_bytes_and_attributes_from_key_block,
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
) -> Result<Object, KmipError> {
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
) -> Result<ABESymmetricKey, KmipError> {
    trace!("Starting create secret key");

    let (public_key_bytes, public_key_attributes) = key_bytes_and_attributes_from_key_block(
        public_key_response.object.key_block()?,
        &public_key_response.unique_identifier,
    )?;
    let public_key = <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey::from_bytes(&public_key_bytes)
        .map_err(|e| {
            KmipError::InvalidKmipValue(ErrorReason::Invalid_Attribute_Value, e.to_string())
        })?;

    let policy = policy_from_attributes(&public_key_attributes.ok_or_else(|| {
        KmipError::InvalidKmipObject(
            ErrorReason::Attribute_Not_Found,
            "the master public key does not have attributes with the Policy".to_string(),
        )
    })?)?;

    let engine = Engine::<Gpsw<Bls12_381>>::new();
    let (sk, sk_enc) = engine
        .generate_symmetric_key(
            &policy,
            &public_key,
            policy_attributes,
            aes_256_gcm_pure::KEY_LENGTH,
        )
        .map_err(|e| {
            KmipError::InvalidKmipValue(ErrorReason::Invalid_Attribute_Value, e.to_string())
        })?;

    debug!("Generate symmetric key for ABE OK");
    Ok(ABESymmetricKey {
        uid: abe_header_uid.to_vec(),
        symmetric_key: sk,
        encrypted_symmetric_key: sk_enc,
    })
}

impl TryFrom<&KeyBlock> for ABESymmetricKey {
    type Error = KmipError;

    fn try_from(sk: &KeyBlock) -> Result<Self, Self::Error> {
        if sk.cryptographic_algorithm != CryptographicAlgorithm::ABE
            || sk.key_format_type != KeyFormatType::AbeSymmetricKey
        {
            return Err(KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Data_Type,
                "this Secret Key does not contain an ABE key".to_string(),
            ))
        }

        if sk.key_wrapping_data.is_some() {
            return Err(KmipError::KmipNotSupported(
                ErrorReason::Key_Wrap_Type_Not_Supported,
                "unwrapping an ABE Secret Key is not yet supported".to_string(),
            ))
        }
        let (key_material, _) = sk.key_value.plaintext().ok_or_else(|| {
            KmipError::InvalidKmipObject(
                ErrorReason::Invalid_Object_Type,
                "invalid Plain Text".to_owned(),
            )
        })?;
        serde_json::from_slice::<ABESymmetricKey>(match key_material {
            KeyMaterial::TransparentSymmetricKey { key } => key,
            other => {
                return Err(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Object_Type,
                    format!("Invalid key material for an ABE secret key: {:?}", other),
                ))
            }
        })
        .map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed deserializing the ABE Secret Key from the Key Material {e}"),
            )
        })
    }
}
