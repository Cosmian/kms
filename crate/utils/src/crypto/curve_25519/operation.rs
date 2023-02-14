use cosmian_crypto_core::{
    asymmetric_crypto::{
        curve25519::{X25519KeyPair, X25519_PRIVATE_KEY_LENGTH, X25519_PUBLIC_KEY_LENGTH},
        DhKeyPair,
    },
    CsRng, KeyTrait,
};
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicDomainParameters,
            CryptographicParameters, CryptographicUsageMask, KeyFormatType, RecommendedCurve,
        },
    },
};
use num_bigint::BigUint;
use rand_core::SeedableRng;

use crate::KeyPair;

pub const SECRET_KEY_LENGTH: usize = X25519_PRIVATE_KEY_LENGTH;
pub const PUBLIC_KEY_LENGTH: usize = X25519_PUBLIC_KEY_LENGTH;
pub const Q_LENGTH_BITS: i32 = X25519_PRIVATE_KEY_LENGTH as i32;

/// convert to a curve 25519 256 bits KMIP Public Key
/// no check performed
pub fn to_curve_25519_256_public_key(bytes: &[u8]) -> Object {
    Object::PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::EC,
            key_format_type: KeyFormatType::TransparentECPublicKey,
            key_compression_type: None,
            key_value: KeyValue {
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
            key_value: KeyValue {
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
pub fn generate_key_pair() -> Result<KeyPair, KmipError> {
    let mut rng = CsRng::from_entropy();
    let key_pair = X25519KeyPair::new(&mut rng);
    let public_key = to_curve_25519_256_public_key(&key_pair.public_key().to_bytes());
    let private_key = to_curve_25519_256_private_key(&key_pair.private_key().to_bytes());
    Ok(KeyPair((private_key, public_key)))
}
