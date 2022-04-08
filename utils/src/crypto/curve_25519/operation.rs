use cosmian_crypto_base::sodium_bindings;
use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_operations::ErrorReason,
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicDomainParameters, CryptographicParameters,
        CryptographicUsageMask, KeyFormatType, RecommendedCurve,
    },
};
use num_bigint::BigUint;

use crate::{error::LibError, result::LibResult, KeyPair};

pub const SECRET_KEY_LENGTH: usize = sodium_bindings::crypto_box_SECRETKEYBYTES as usize;
pub const PUBLIC_KEY_LENGTH: usize = sodium_bindings::crypto_box_PUBLICKEYBYTES as usize;
pub const Q_LENGTH_BITS: i32 = (sodium_bindings::crypto_box_SECRETKEYBYTES * 8) as i32;

/// convert to a curve 25519 256 bits KMIP Public Key
/// no check performed
pub fn to_curve_25519_256_public_key(bytes: &[u8]) -> Object {
    Object::PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::EC,
            key_format_type: KeyFormatType::TransparentECPublicKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
                key_material: KeyMaterial::TransparentECPublicKey {
                    recommended_curve: RecommendedCurve::CURVE25519,
                    q_string: bytes.to_vec(),
                },
                attributes: Some(Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
                    cryptographic_length: Some(Q_LENGTH_BITS),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
                    vendor_attributes: None,
                    key_format_type: Some(KeyFormatType::TransparentECPublicKey),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
                        ..CryptographicParameters::default()
                    }),
                    cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                        q_length: Some(Q_LENGTH_BITS),
                        recommended_curve: Some(RecommendedCurve::CURVE25519),
                    }),
                    ..Attributes::new(ObjectType::PublicKey)
                }),
            },
            cryptographic_length: Q_LENGTH_BITS,
            key_wrapping_data: None,
        },
    }
}

/// convert to a curve 25519 256 bits KMIP Private Key
/// no check performed
pub fn to_curve_25519_256_private_key(bytes: &[u8]) -> Object {
    Object::PrivateKey {
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::EC,
            key_format_type: KeyFormatType::TransparentECPrivateKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
                key_material: KeyMaterial::TransparentECPrivateKey {
                    recommended_curve: RecommendedCurve::CURVE25519,
                    d: BigUint::from_bytes_be(bytes),
                },
                attributes: Some(Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
                    cryptographic_length: Some(Q_LENGTH_BITS),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
                    vendor_attributes: None,
                    key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
                        ..CryptographicParameters::default()
                    }),
                    cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                        q_length: Some(Q_LENGTH_BITS),
                        recommended_curve: Some(RecommendedCurve::CURVE25519),
                    }),
                    ..Attributes::new(ObjectType::PrivateKey)
                }),
            },
            cryptographic_length: Q_LENGTH_BITS,
            key_wrapping_data: None,
        },
    }
}

/// Generate a key CURVE 25519 Key Pair
pub fn generate_key_pair() -> LibResult<KeyPair> {
    let mut pk = [0_u8; PUBLIC_KEY_LENGTH];
    let mut sk = [0_u8; SECRET_KEY_LENGTH];
    if unsafe { sodium_bindings::crypto_kx_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) } != 0 {
        return Err(
            LibError::Error("Failed to create a curve 25519 key pair".to_owned())
                .reason(ErrorReason::Invalid_Message),
        )
    }
    let public_key = to_curve_25519_256_public_key(&pk);
    let private_key = to_curve_25519_256_private_key(&sk);
    Ok(KeyPair((private_key, public_key)))
}
