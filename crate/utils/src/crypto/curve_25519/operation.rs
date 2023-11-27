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
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    nid::Nid,
    pkey::PKey,
};

use crate::KeyPair;

pub const ED25519_SECRET_LENGTH: usize = 0x20;
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 0x20;
pub const Q_LENGTH_BITS: i32 = 253;

/// convert to a X25519 256 bits KMIP Public Key
/// no check performed
#[must_use]
pub fn to_ec_public_key(bytes: &[u8], private_key_uid: &str, curve: RecommendedCurve) -> Object {
    Object::PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
            key_format_type: KeyFormatType::TransparentECPublicKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentECPublicKey {
                    recommended_curve: curve,
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
                        recommended_curve: Some(curve),
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
pub fn to_ec_private_key(bytes: &[u8], public_key_uid: &str, curve: RecommendedCurve) -> Object {
    Object::PrivateKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
            key_format_type: KeyFormatType::TransparentECPrivateKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentECPrivateKey {
                    recommended_curve: curve,
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
                        recommended_curve: Some(curve),
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

/// Generate an X25519 Key Pair. Not FIPS 140-3 compliant.
#[cfg(not(feature = "fips"))]
pub fn create_x25519_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipError> {
    let keypair = PKey::generate_x25519()?;

    let public_key = to_ec_public_key(
        &keypair.raw_public_key()?,
        private_key_uid,
        RecommendedCurve::CURVE25519,
    );
    let private_key = to_ec_private_key(
        &keypair.raw_private_key()?,
        public_key_uid,
        RecommendedCurve::CURVE25519,
    );
    Ok(KeyPair::new(private_key, public_key))
}

/// Generate an Ed25519 Key Pair. FIPS 140-3 compliant **for digital signature
/// only**.
///
/// Sources:
/// - NIST.SP.800-186 - Section 3.2.3
/// - NIST.FIPS.186-5 - Section 3.2.3
pub fn create_ed25519_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipError> {
    let keypair = PKey::generate_ed25519()?;

    let public_key = to_ec_public_key(
        &keypair.raw_public_key()?,
        private_key_uid,
        RecommendedCurve::CURVEED25519,
    );
    let private_key = to_ec_private_key(
        &keypair.raw_private_key()?,
        public_key_uid,
        RecommendedCurve::CURVEED25519,
    );
    Ok(KeyPair::new(private_key, public_key))
}

fn create_p_curve_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
    curve: EcGroup,
) -> Result<KeyPair, KmipError> {
    let ec_privkey = EcKey::generate(&curve)?;
    let ec_pubkey = EcKey::from_public_key(&curve, ec_privkey.public_key())?;

    let private_key = to_ec_private_key(
        &ec_privkey.private_key().to_vec(),
        public_key_uid,
        RecommendedCurve::SECP192K1,
    );

    let mut ctx = BigNumContext::new()?;

    let public_key = to_ec_public_key(
        &ec_pubkey
            .public_key()
            .to_bytes(&curve, PointConversionForm::UNCOMPRESSED, &mut ctx)?,
        private_key_uid,
        RecommendedCurve::SECP192K1,
    );

    Ok(KeyPair::new(private_key, public_key))
}

/// Generate a P-192 Key Pair. Not FIPS-140-3 compliant. **This curve is for
/// legacy-use only**.
#[cfg(not(feature = "fips"))]
pub fn create_p192_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipError> {
    create_p_curve_key_pair(
        private_key_uid,
        public_key_uid,
        EcGroup::from_curve_name(Nid::X9_62_PRIME192V1)?,
    )
}

/// Generate a P-224 Key Pair. FIPS-140-3 compliant for key agreement and
/// digital signature.
pub fn create_p224_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipError> {
    create_p_curve_key_pair(
        private_key_uid,
        public_key_uid,
        EcGroup::from_curve_name(Nid::SECP224R1)?,
    )
}

/// Generate a P-256 Key Pair. FIPS-140-3 compliant for key agreement and
/// digital signature.
pub fn create_p256_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipError> {
    create_p_curve_key_pair(
        private_key_uid,
        public_key_uid,
        EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?,
    )
}

/// Generate a P-384 Key Pair. FIPS-140-3 compliant for key agreement and
/// digital signature.
pub fn create_p384_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipError> {
    create_p_curve_key_pair(
        private_key_uid,
        public_key_uid,
        EcGroup::from_curve_name(Nid::SECP384R1)?,
    )
}

/// Generate a P-521 Key Pair. FIPS-140-3 compliant for key agreement and
/// digital signature.
pub fn create_p521_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipError> {
    create_p_curve_key_pair(
        private_key_uid,
        public_key_uid,
        EcGroup::from_curve_name(Nid::SECP521R1)?,
    )
}

#[cfg(test)]
#[cfg(not(feature = "fips"))]
// TODO: add FIPS tests.
mod tests {
    use cosmian_kmip::kmip::kmip_data_structures::KeyMaterial;
    use openssl::pkey::{Id, PKey};

    use crate::crypto::curve_25519::operation::create_x25519_key_pair;

    #[test]
    fn test_x25519_conversions() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        // Create a Key pair
        // - the private key is a TransparentEcPrivateKey where the key value is the bytes of the scalar
        // - the public key is a TransparentEcPublicKey where the key value is the bytes of the Montgomery point
        let wrap_key_pair = create_x25519_key_pair("sk_uid", "pk_uid").unwrap();

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
