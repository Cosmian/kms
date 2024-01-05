use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicDomainParameters, CryptographicParameters,
        CryptographicUsageMask, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
        RecommendedCurve,
    },
};
use num_bigint_dig::BigUint;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    nid::Nid,
    pkey::PKey,
};

use crate::{error::KmipUtilsError, kmip_utils_bail, KeyPair};

pub const X25519_PRIVATE_KEY_LENGTH: usize = 0x20;
pub const X25519_PUBLIC_KEY_LENGTH: usize = 0x20;
pub const ED25519_PRIVATE_KEY_LENGTH: usize = 0x20;
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
// TODO - #[cfg(not(feature = "fips"))]
pub fn create_x25519_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipUtilsError> {
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
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
/// - NIST.FIPS.186-5
pub fn create_ed25519_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipUtilsError> {
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
    curve_nid: Nid,
) -> Result<KeyPair, KmipUtilsError> {
    let curve = EcGroup::from_curve_name(curve_nid)?;
    let kmip_curve = match curve_nid {
        Nid::X9_62_PRIME192V1 => RecommendedCurve::P192,
        Nid::SECP224R1 => RecommendedCurve::P224,
        Nid::X9_62_PRIME256V1 => RecommendedCurve::P256,
        Nid::SECP384R1 => RecommendedCurve::P384,
        Nid::SECP521R1 => RecommendedCurve::P521,
        other => kmip_utils_bail!("Curve Nid {:?} not supported by KMS.", other),
    };

    let ec_privkey = EcKey::generate(&curve)?;
    let ec_pubkey = EcKey::from_public_key(&curve, ec_privkey.public_key())?;

    let private_key = to_ec_private_key(
        &ec_privkey.private_key().to_vec(),
        public_key_uid,
        kmip_curve,
    );

    let mut ctx = BigNumContext::new()?;

    let public_key = to_ec_public_key(
        &ec_pubkey
            .public_key()
            .to_bytes(&curve, PointConversionForm::HYBRID, &mut ctx)?,
        private_key_uid,
        kmip_curve,
    );

    Ok(KeyPair::new(private_key, public_key))
}

/// Generate a P-192 Key Pair. Not FIPS-140-3 compliant. **This curve is for
/// legacy-use only** as it provides less than 112 bits of security.
///
/// Sources:
/// - NIST.SP.800-186 - Section 3.2.1.1
#[cfg(not(feature = "fips"))]
pub fn create_p192_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipUtilsError> {
    create_p_curve_key_pair(private_key_uid, public_key_uid, Nid::X9_62_PRIME192V1)
}

/// Generate a P-224 Key Pair. FIPS-140-3 compliant for key agreement and
/// digital signature.
///
/// Sources:
/// - NIST.SP.800-56Ar3 - Appendix D.
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
pub fn create_p224_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipUtilsError> {
    create_p_curve_key_pair(private_key_uid, public_key_uid, Nid::SECP224R1)
}

/// Generate a P-256 Key Pair. FIPS-140-3 compliant for key agreement and
/// digital signature.
///
/// Sources:
/// - NIST.SP.800-56Ar3 - Appendix D.
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
pub fn create_p256_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipUtilsError> {
    create_p_curve_key_pair(private_key_uid, public_key_uid, Nid::X9_62_PRIME256V1)
}

/// Generate a P-384 Key Pair. FIPS-140-3 compliant for key agreement and
/// digital signature.
///
/// Sources:
/// - NIST.SP.800-56Ar3 - Appendix D.
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
pub fn create_p384_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipUtilsError> {
    create_p_curve_key_pair(private_key_uid, public_key_uid, Nid::SECP384R1)
}

/// Generate a P-521 Key Pair. FIPS-140-3 compliant for key agreement and
/// digital signature.
///
/// Sources:
/// - NIST.SP.800-56Ar3 - Appendix D.
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
pub fn create_p521_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
) -> Result<KeyPair, KmipUtilsError> {
    create_p_curve_key_pair(private_key_uid, public_key_uid, Nid::SECP521R1)
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "fips"))]
    use cosmian_kmip::kmip::kmip_data_structures::KeyMaterial;
    #[cfg(not(feature = "fips"))]
    use cosmian_kmip::openssl::pad_be_bytes;
    use cosmian_kmip::openssl::{kmip_private_key_to_openssl, kmip_public_key_to_openssl};
    #[cfg(not(feature = "fips"))]
    use openssl::pkey::{Id, PKey};

    #[cfg(not(feature = "fips"))]
    use super::X25519_PRIVATE_KEY_LENGTH;
    use super::{
        create_ed25519_key_pair, create_p224_key_pair, create_p256_key_pair, create_p384_key_pair,
        create_p521_key_pair,
    };
    #[cfg(not(feature = "fips"))]
    use super::{create_p192_key_pair, create_x25519_key_pair};

    #[test]
    fn test_ed25519_keypair_generation() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let keypair1 = create_ed25519_key_pair("sk_uid1", "pk_uid1").unwrap();
        let keypair2 = create_ed25519_key_pair("sk_uid2", "pk_uid2").unwrap();

        let privkey1 = kmip_private_key_to_openssl(keypair1.private_key()).unwrap();
        let privkey2 = kmip_private_key_to_openssl(keypair2.private_key()).unwrap();

        assert_ne!(
            privkey1.private_key_to_der().unwrap(),
            privkey2.private_key_to_der().unwrap()
        );

        let pubkey1 = kmip_public_key_to_openssl(keypair1.public_key()).unwrap();
        let pubkey2 = kmip_public_key_to_openssl(keypair2.public_key()).unwrap();

        assert_ne!(
            pubkey1.public_key_to_der().unwrap(),
            pubkey2.public_key_to_der().unwrap()
        );
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_p192_keypair_generation() {
        let keypair1 = create_p192_key_pair("sk_uid1", "pk_uid1").unwrap();
        let keypair2 = create_p192_key_pair("sk_uid2", "pk_uid2").unwrap();

        let privkey1 = kmip_private_key_to_openssl(keypair1.private_key()).unwrap();
        let privkey2 = kmip_private_key_to_openssl(keypair2.private_key()).unwrap();

        assert_ne!(
            privkey1.private_key_to_der().unwrap(),
            privkey2.private_key_to_der().unwrap()
        );

        let pubkey1 = kmip_public_key_to_openssl(keypair1.public_key()).unwrap();
        let pubkey2 = kmip_public_key_to_openssl(keypair2.public_key()).unwrap();

        assert_ne!(
            pubkey1.public_key_to_der().unwrap(),
            pubkey2.public_key_to_der().unwrap()
        );
    }

    #[test]
    fn test_p224_keypair_generation() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let keypair1 = create_p224_key_pair("sk_uid1", "pk_uid1").unwrap();
        let keypair2 = create_p224_key_pair("sk_uid2", "pk_uid2").unwrap();

        let privkey1 = kmip_private_key_to_openssl(keypair1.private_key()).unwrap();
        let privkey2 = kmip_private_key_to_openssl(keypair2.private_key()).unwrap();

        assert_ne!(
            privkey1.private_key_to_der().unwrap(),
            privkey2.private_key_to_der().unwrap()
        );

        let pubkey1 = kmip_public_key_to_openssl(keypair1.public_key()).unwrap();
        let pubkey2 = kmip_public_key_to_openssl(keypair2.public_key()).unwrap();

        assert_ne!(
            pubkey1.public_key_to_der().unwrap(),
            pubkey2.public_key_to_der().unwrap()
        );
    }

    #[test]
    fn test_p256_keypair_generation() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let keypair1 = create_p256_key_pair("sk_uid1", "pk_uid1").unwrap();
        let keypair2 = create_p256_key_pair("sk_uid2", "pk_uid2").unwrap();

        let privkey1 = kmip_private_key_to_openssl(keypair1.private_key()).unwrap();
        let privkey2 = kmip_private_key_to_openssl(keypair2.private_key()).unwrap();

        assert_ne!(
            privkey1.private_key_to_der().unwrap(),
            privkey2.private_key_to_der().unwrap()
        );

        let pubkey1 = kmip_public_key_to_openssl(keypair1.public_key()).unwrap();
        let pubkey2 = kmip_public_key_to_openssl(keypair2.public_key()).unwrap();

        assert_ne!(
            pubkey1.public_key_to_der().unwrap(),
            pubkey2.public_key_to_der().unwrap()
        );
    }

    #[test]
    fn test_p384_keypair_generation() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let keypair1 = create_p384_key_pair("sk_uid1", "pk_uid1").unwrap();
        let keypair2 = create_p384_key_pair("sk_uid2", "pk_uid2").unwrap();

        let privkey1 = kmip_private_key_to_openssl(keypair1.private_key()).unwrap();
        let privkey2 = kmip_private_key_to_openssl(keypair2.private_key()).unwrap();

        assert_ne!(
            privkey1.private_key_to_der().unwrap(),
            privkey2.private_key_to_der().unwrap()
        );

        let pubkey1 = kmip_public_key_to_openssl(keypair1.public_key()).unwrap();
        let pubkey2 = kmip_public_key_to_openssl(keypair2.public_key()).unwrap();

        assert_ne!(
            pubkey1.public_key_to_der().unwrap(),
            pubkey2.public_key_to_der().unwrap()
        );
    }

    #[test]
    fn test_p521_keypair_generation() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let keypair1 = create_p521_key_pair("sk_uid1", "pk_uid1").unwrap();
        let keypair2 = create_p521_key_pair("sk_uid2", "pk_uid2").unwrap();

        let privkey1 = kmip_private_key_to_openssl(keypair1.private_key()).unwrap();
        let privkey2 = kmip_private_key_to_openssl(keypair2.private_key()).unwrap();

        assert_ne!(
            privkey1.private_key_to_der().unwrap(),
            privkey2.private_key_to_der().unwrap()
        );

        let pubkey1 = kmip_public_key_to_openssl(keypair1.public_key()).unwrap();
        let pubkey2 = kmip_public_key_to_openssl(keypair2.public_key()).unwrap();

        assert_ne!(
            pubkey1.public_key_to_der().unwrap(),
            pubkey2.public_key_to_der().unwrap()
        );
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_x25519_conversions() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        // Create a Key pair
        // - the private key is a TransparentEcPrivateKey where the key value is the bytes of the scalar
        // - the public key is a TransparentEcPublicKey where the key value is the bytes of the Montgomery point
        let wrap_key_pair = create_x25519_key_pair("sk_uid", "pk_uid")
            .expect("failed to create x25519 key pair in test_x25519_conversions");

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
        let mut original_private_key_bytes = match &original_private_key_value.key_material {
            KeyMaterial::TransparentECPrivateKey { d, .. } => d.to_bytes_be(),
            _ => panic!("Not a transparent private key"),
        };
        pad_be_bytes(&mut original_private_key_bytes, X25519_PRIVATE_KEY_LENGTH);
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
