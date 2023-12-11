use cloudproof::reexport::crypto_core::{
    reexport::rand_core::CryptoRngCore, Ed25519PrivateKey, Ed25519PublicKey, X25519PrivateKey,
    X25519PublicKey, CURVE_25519_SECRET_LENGTH,
};
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicDomainParameters,
            CryptographicParameters, CryptographicUsageMask, KeyFormatType, Link, LinkType,
            LinkedObjectIdentifier, RecommendedCurve,
        },
    },
};
use num_bigint_dig::BigUint;

use crate::KeyPair;

pub const SECRET_KEY_LENGTH: usize = CURVE_25519_SECRET_LENGTH;
pub const Q_LENGTH_BITS: i32 = 253;

/// convert to a X25519 256 bits KMIP Public Key
/// no check performed
#[must_use]
pub fn to_curve_25519_256_public_key(bytes: &[u8], private_key_uid: &str) -> Object {
    Object::PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
            key_format_type: KeyFormatType::TransparentECPublicKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentECPublicKey {
                    recommended_curve: RecommendedCurve::CURVE25519,
                    q_string: bytes.to_vec(),
                },
                attributes: Some(Attributes {
                    object_type: Some(ObjectType::PublicKey),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                    cryptographic_length: Some(Q_LENGTH_BITS),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
                    vendor_attributes: None,
                    key_format_type: Some(KeyFormatType::TransparentECPublicKey),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                        ..CryptographicParameters::default()
                    }),
                    cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                        q_length: Some(Q_LENGTH_BITS),
                        recommended_curve: Some(RecommendedCurve::CURVE25519),
                    }),
                    link: Some(vec![Link {
                        link_type: LinkType::PrivateKeyLink,
                        linked_object_identifier: LinkedObjectIdentifier::TextString(
                            private_key_uid.to_string(),
                        ),
                    }]),
                    ..Attributes::default()
                }),
            },
            cryptographic_length: Some(Q_LENGTH_BITS),
            key_wrapping_data: None,
        },
    }
}

/// convert to a curve 25519 256 bits KMIP Private Key
/// no check performed
#[must_use]
pub fn to_curve_25519_256_private_key(bytes: &[u8], public_key_uid: &str) -> Object {
    Object::PrivateKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
            key_format_type: KeyFormatType::TransparentECPrivateKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentECPrivateKey {
                    recommended_curve: RecommendedCurve::CURVE25519,
                    d: BigUint::from_bytes_be(bytes),
                },
                attributes: Some(Attributes {
                    object_type: Some(ObjectType::PrivateKey),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                    cryptographic_length: Some(Q_LENGTH_BITS),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
                    vendor_attributes: None,
                    key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                        ..CryptographicParameters::default()
                    }),
                    cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                        q_length: Some(Q_LENGTH_BITS),
                        recommended_curve: Some(RecommendedCurve::CURVE25519),
                    }),
                    link: Some(vec![Link {
                        link_type: LinkType::PublicKeyLink,
                        linked_object_identifier: LinkedObjectIdentifier::TextString(
                            public_key_uid.to_string(),
                        ),
                    }]),
                    ..Attributes::default()
                }),
            },
            cryptographic_length: Some(Q_LENGTH_BITS),
            key_wrapping_data: None,
        },
    }
}

/// Generate a X25519 Key Pair
pub fn create_x25519_key_pair<R>(
    rng: &mut R,
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipError>
where
    R: CryptoRngCore,
{
    let private_key = X25519PrivateKey::new(rng);
    let public_key = X25519PublicKey::from(&private_key);

    let private_key = to_curve_25519_256_private_key(private_key.as_bytes(), public_key_uid);
    let public_key = to_curve_25519_256_public_key(public_key.as_bytes(), private_key_uid);
    Ok(KeyPair::new(private_key, public_key))
}

/// Generate a key CURVE Ed25519 Key Pair
pub fn create_ed25519_key_pair<R>(
    rng: &mut R,
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipError>
where
    R: CryptoRngCore,
{
    let private_key = Ed25519PrivateKey::new(rng);
    let public_key = Ed25519PublicKey::from(&private_key);

    let private_key = to_curve_25519_256_private_key(private_key.as_bytes(), public_key_uid);
    let public_key = to_curve_25519_256_public_key(public_key.as_bytes(), private_key_uid);
    Ok(KeyPair::new(private_key, public_key))
}

#[cfg(test)]
mod tests {
    use cloudproof::reexport::crypto_core::{reexport::rand_core::SeedableRng, CsRng};
    use cosmian_kmip::kmip::kmip_data_structures::KeyMaterial;
    use openssl::pkey::{Id, PKey};

    use crate::crypto::curve_25519::operation::create_x25519_key_pair;

    #[test]
    fn test_x25519_conversions() {
        let mut rng = CsRng::from_entropy();

        // Create a Key pair
        // - the private key is a TransparentEcPrivateKey where the key value is the bytes of the scalar
        // - the public key is a TransparentEcPublicKey where the key value is the bytes of the Montgomery point
        let wrap_key_pair = create_x25519_key_pair(&mut rng, "sk_uid", "pk_uid").unwrap();

        //
        // public key
        //
        let original_public_key_value = &wrap_key_pair.public_key().key_block().unwrap().key_value;
        let original_public_key_bytes = match &original_public_key_value.key_material {
            KeyMaterial::TransparentECPublicKey { q_string, .. } => q_string,
            _ => panic!("Not a transparent public key"),
        };
        // try to convert to openssl
        let p_key = PKey::public_key_from_raw_bytes(original_public_key_bytes, Id::X25519).unwrap();
        // convert back to bytes
        let raw_bytes = p_key.raw_public_key().unwrap();
        assert_eq!(&raw_bytes, original_public_key_bytes);

        //
        // private key
        //
        let original_private_key_value =
            &wrap_key_pair.private_key().key_block().unwrap().key_value;
        let original_private_key_bytes = match &original_private_key_value.key_material {
            KeyMaterial::TransparentECPrivateKey { d, .. } => d.to_bytes_be(),
            _ => panic!("Not a transparent private key"),
        };
        // try to convert to openssl
        let p_key =
            PKey::private_key_from_raw_bytes(&original_private_key_bytes, Id::X25519).unwrap();
        // convert back to bytes
        let raw_bytes = p_key.raw_private_key().unwrap();
        assert_eq!(raw_bytes, original_private_key_bytes);
        // get public key from private
        let raw_public_key_bytes = p_key.raw_public_key().unwrap();
        assert_eq!(&raw_public_key_bytes, original_public_key_bytes);
    }
}
