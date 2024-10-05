use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    nid::Nid,
    pkey::PKey,
};
use tracing::trace;
use zeroize::Zeroizing;

#[cfg(feature = "fips")]
use crate::crypto::elliptic_curves::{
    FIPS_PRIVATE_ECC_MASK_ECDH, FIPS_PRIVATE_ECC_MASK_SIGN, FIPS_PRIVATE_ECC_MASK_SIGN_ECDH,
    FIPS_PUBLIC_ECC_MASK_ECDH, FIPS_PUBLIC_ECC_MASK_SIGN, FIPS_PUBLIC_ECC_MASK_SIGN_ECDH,
};
use crate::{
    crypto::{secret::SafeBigUint, KeyPair},
    error::{result::KmipResult, KmipError},
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicDomainParameters,
            CryptographicParameters, CryptographicUsageMask, KeyFormatType, Link, LinkType,
            LinkedObjectIdentifier, RecommendedCurve,
        },
    },
    kmip_bail,
};

#[cfg(feature = "fips")]
/// Check that bits set in `mask` are only bits set in `flags`. If any bit set
/// in `mask` is not set in `flags`, raise an error.
///
/// If `mask` is None, raise error.
fn check_ecc_mask_against_flags(
    mask: Option<CryptographicUsageMask>,
    flags: CryptographicUsageMask,
) -> Result<(), KmipError> {
    if (flags & CryptographicUsageMask::Unrestricted).bits() != 0 {
        kmip_bail!(
            "Unrestricted CryptographicUsageMask for elliptic curves is too permissive for FIPS \
             mode."
        )
    }

    let Some(mask) = mask else {
        // Mask is `None` but FIPS mode is restrictive so it's considered too
        // permissive.
        kmip_bail!(
            "EC: forbidden CryptographicUsageMask value, got None but expected among {:#010X} in \
             FIPS mode.",
            flags.bits()
        )
    };

    if (mask & !flags).bits() != 0 {
        kmip_bail!(
            "EC: forbidden CryptographicUsageMask flag set: {:#010X}, expected among {:#010X} in \
             FIPS mode.",
            mask.bits(),
            flags.bits()
        )
    }
    Ok(())
}

#[cfg(feature = "fips")]
/// Check that
/// - `algorithm` is among `allowed` algorithms.
/// - `algorithm` is compliant with usage mask provided for private and public key components.
///
/// For example `ECDH` and `Sign` are incompatible together since ECDH is for key agreement.
///
/// If `algorithm` is None, raise error.
fn check_ecc_mask_algorithm_compliance(
    private_key_mask: Option<CryptographicUsageMask>,
    public_key_mask: Option<CryptographicUsageMask>,
    algorithm: Option<CryptographicAlgorithm>,
    allowed_algorithms: &[CryptographicAlgorithm],
) -> Result<(), KmipError> {
    let Some(algorithm) = algorithm else {
        // Algorithm is None but FIPS mode is restrictive so it's considered too permissive.
        kmip_bail!(
            "EC: forbidden CryptographicAlgorithm value, got `None` but expected precise \
             algorithm."
        )
    };
    if !allowed_algorithms.contains(&algorithm) {
        kmip_bail!("EC: forbidden CryptographicAlgorithm value in FIPS mode.")
    }
    match algorithm {
        CryptographicAlgorithm::ECDH => {
            check_ecc_mask_against_flags(private_key_mask, FIPS_PRIVATE_ECC_MASK_ECDH)?;
            check_ecc_mask_against_flags(public_key_mask, FIPS_PUBLIC_ECC_MASK_ECDH)?;
        }
        CryptographicAlgorithm::ECDSA
        | CryptographicAlgorithm::Ed25519
        | CryptographicAlgorithm::Ed448 => {
            check_ecc_mask_against_flags(private_key_mask, FIPS_PRIVATE_ECC_MASK_SIGN)?;
            check_ecc_mask_against_flags(public_key_mask, FIPS_PUBLIC_ECC_MASK_SIGN)?;
        }
        CryptographicAlgorithm::EC => {
            check_ecc_mask_against_flags(private_key_mask, FIPS_PRIVATE_ECC_MASK_SIGN_ECDH)?;
            check_ecc_mask_against_flags(public_key_mask, FIPS_PUBLIC_ECC_MASK_SIGN_ECDH)?;
        }
        // If `allowed` parameter is set correctly, should never fall in this case.
        _ => kmip_bail!("Invalid CryptographicAlgorithm value."),
    }
    Ok(())
}

/// Convert to an Elliptic Curve KMIP Public Key.
/// Supported curves are:
/// X25519, Ed25519, X448, Ed448, P-192, P-224, P-256, P-384, P-521.
///
/// `pkey_bits_number` is passed independently from `len(bytes)` since some key
/// sizes are not multiple of 8 thus it cannot be computed by taking the byte
/// array length.
///
/// No check performed.
pub fn to_ec_public_key(
    bytes: &[u8],
    pkey_bits_number: u32,
    private_key_uid: &str,
    curve: RecommendedCurve,
    algorithm: Option<CryptographicAlgorithm>,
    public_key_mask: Option<CryptographicUsageMask>,
) -> KmipResult<Object> {
    let cryptographic_length = Some(i32::try_from(bytes.len())? * 8);
    trace!(
        "to_ec_public_key: bytes len: {:?}, bits: {}",
        cryptographic_length,
        pkey_bits_number
    );

    let q_length = Some(i32::try_from(pkey_bits_number)?);
    Ok(Object::PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: algorithm,
            key_format_type: KeyFormatType::TransparentECPublicKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentECPublicKey {
                    recommended_curve: curve,
                    q_string: bytes.to_vec(),
                },
                attributes: Some(Box::new(Attributes {
                    object_type: Some(ObjectType::PublicKey),
                    cryptographic_algorithm: algorithm,
                    cryptographic_length,
                    cryptographic_usage_mask: public_key_mask,
                    vendor_attributes: None,
                    key_format_type: Some(KeyFormatType::TransparentECPublicKey),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: algorithm,
                        ..CryptographicParameters::default()
                    }),
                    cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                        q_length,
                        recommended_curve: Some(curve),
                    }),
                    link: Some(vec![Link {
                        link_type: LinkType::PrivateKeyLink,
                        linked_object_identifier: LinkedObjectIdentifier::TextString(
                            private_key_uid.to_owned(),
                        ),
                    }]),
                    ..Attributes::default()
                })),
            },
            cryptographic_length,
            key_wrapping_data: None,
        },
    })
}

/// Convert to an Elliptic Curve KMIP Private Key.
/// Supported curves are:
/// X25519, Ed25519, X448, Ed448, P-192, P-224, P-256, P-384, P-521.
///
/// `pkey_bits_number` is passed independently from `len(bytes)` since some key
/// sizes are not multiple of 8 thus it cannot be computed by taking the byte
/// array length.
///
/// No check performed.
pub fn to_ec_private_key(
    bytes: &[u8],
    pkey_bits_number: u32,
    public_key_uid: &str,
    curve: RecommendedCurve,
    algorithm: Option<CryptographicAlgorithm>,
    private_key_mask: Option<CryptographicUsageMask>,
) -> KmipResult<Object> {
    let cryptographic_length = Some(i32::try_from(bytes.len())? * 8);

    trace!(
        "to_ec_private_key: bytes len: {:?}, bits: {}",
        cryptographic_length,
        pkey_bits_number
    );

    let q_length = Some(i32::try_from(pkey_bits_number)?);
    Ok(Object::PrivateKey {
        key_block: KeyBlock {
            cryptographic_algorithm: algorithm,
            key_format_type: KeyFormatType::TransparentECPrivateKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentECPrivateKey {
                    recommended_curve: curve,
                    d: Box::new(SafeBigUint::from_bytes_be(bytes)),
                },
                attributes: Some(Box::new(Attributes {
                    object_type: Some(ObjectType::PrivateKey),
                    cryptographic_algorithm: algorithm,
                    cryptographic_length,
                    cryptographic_usage_mask: private_key_mask,
                    vendor_attributes: None,
                    key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: algorithm,
                        ..CryptographicParameters::default()
                    }),
                    cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                        q_length,
                        recommended_curve: Some(curve),
                    }),
                    link: Some(vec![Link {
                        link_type: LinkType::PublicKeyLink,
                        linked_object_identifier: LinkedObjectIdentifier::TextString(
                            public_key_uid.to_owned(),
                        ),
                    }]),
                    ..Attributes::default()
                })),
            },
            cryptographic_length,
            key_wrapping_data: None,
        },
    })
}

/// Generate an X25519 Key Pair. Not FIPS 140-3 compliant.
#[cfg(not(feature = "fips"))]
pub fn create_x25519_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
    algorithm: Option<CryptographicAlgorithm>,
    private_key_mask: Option<CryptographicUsageMask>,
    public_key_mask: Option<CryptographicUsageMask>,
) -> Result<KeyPair, KmipError> {
    let private_key = PKey::generate_x25519()?;

    let public_key = to_ec_public_key(
        &private_key.raw_public_key()?,
        private_key.bits(),
        private_key_uid,
        RecommendedCurve::CURVE25519,
        algorithm,
        public_key_mask,
    )?;

    let private_key = to_ec_private_key(
        &Zeroizing::from(private_key.raw_private_key()?),
        private_key.bits(),
        public_key_uid,
        RecommendedCurve::CURVE25519,
        algorithm,
        private_key_mask,
    )?;

    Ok(KeyPair::new(private_key, public_key))
}

/// Generate an X448 Key Pair. Not FIPS 140-3 compliant.
#[cfg(not(feature = "fips"))]
pub fn create_x448_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
    algorithm: Option<CryptographicAlgorithm>,
    private_key_mask: Option<CryptographicUsageMask>,
    public_key_mask: Option<CryptographicUsageMask>,
) -> Result<KeyPair, KmipError> {
    let private_key = PKey::generate_x448()?;

    let public_key = to_ec_public_key(
        &private_key.raw_public_key()?,
        private_key.bits(),
        private_key_uid,
        RecommendedCurve::CURVE448,
        algorithm,
        public_key_mask,
    )?;

    let private_key = to_ec_private_key(
        &Zeroizing::from(private_key.raw_private_key()?),
        private_key.bits(),
        public_key_uid,
        RecommendedCurve::CURVE448,
        algorithm,
        private_key_mask,
    )?;

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
    algorithm: Option<CryptographicAlgorithm>,
    private_key_mask: Option<CryptographicUsageMask>,
    public_key_mask: Option<CryptographicUsageMask>,
) -> Result<KeyPair, KmipError> {
    #[cfg(feature = "fips")]
    // Validate FIPS algorithm and mask.
    check_ecc_mask_algorithm_compliance(
        private_key_mask,
        public_key_mask,
        algorithm,
        &[CryptographicAlgorithm::Ed25519],
    )?;

    let private_key = PKey::generate_ed25519()?;
    trace!("create_ed25519_key_pair: keypair OK");

    let public_key = to_ec_public_key(
        &private_key.raw_public_key()?,
        private_key.bits(),
        private_key_uid,
        RecommendedCurve::CURVEED25519,
        algorithm,
        public_key_mask,
    )?;
    trace!("create_ed25519_key_pair: public_key OK");

    let private_key = to_ec_private_key(
        &Zeroizing::from(private_key.raw_private_key()?),
        private_key.bits(),
        public_key_uid,
        RecommendedCurve::CURVEED25519,
        algorithm,
        private_key_mask,
    )?;
    trace!("create_ed25519_key_pair: private_key OK");

    Ok(KeyPair::new(private_key, public_key))
}

/// Generate an Ed448 Key Pair. FIPS 140-3 compliant **for digital signature
/// only**.
///
/// Sources:
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
/// - NIST.FIPS.186-5
pub fn create_ed448_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
    algorithm: Option<CryptographicAlgorithm>,
    private_key_mask: Option<CryptographicUsageMask>,
    public_key_mask: Option<CryptographicUsageMask>,
) -> Result<KeyPair, KmipError> {
    #[cfg(feature = "fips")]
    // Validate FIPS algorithm and mask.
    check_ecc_mask_algorithm_compliance(
        private_key_mask,
        public_key_mask,
        algorithm,
        &[CryptographicAlgorithm::Ed448],
    )?;

    let private_key = PKey::generate_ed448()?;
    trace!("create_ed448_key_pair: keypair OK");

    let public_key = to_ec_public_key(
        &private_key.raw_public_key()?,
        private_key.bits(),
        private_key_uid,
        RecommendedCurve::CURVEED448,
        algorithm,
        public_key_mask,
    )?;
    trace!("create_ed448_key_pair: public_key OK");

    let private_key = to_ec_private_key(
        &Zeroizing::from(private_key.raw_private_key()?),
        private_key.bits(),
        public_key_uid,
        RecommendedCurve::CURVEED448,
        algorithm,
        private_key_mask,
    )?;
    trace!("create_ed448_key_pair: private_key OK");

    Ok(KeyPair::new(private_key, public_key))
}

pub fn create_approved_ecc_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
    curve: RecommendedCurve,
    algorithm: Option<CryptographicAlgorithm>,
    private_key_mask: Option<CryptographicUsageMask>,
    public_key_mask: Option<CryptographicUsageMask>,
) -> Result<KeyPair, KmipError> {
    #[cfg(feature = "fips")]
    // Validate FIPS algorithms and mask.
    check_ecc_mask_algorithm_compliance(
        private_key_mask,
        public_key_mask,
        algorithm,
        &[
            CryptographicAlgorithm::EC,
            CryptographicAlgorithm::ECDSA,
            CryptographicAlgorithm::ECDH,
        ],
    )?;

    let curve_nid = match curve {
        #[cfg(not(feature = "fips"))]
        RecommendedCurve::P192 => Nid::X9_62_PRIME192V1,
        RecommendedCurve::P224 => Nid::SECP224R1,
        RecommendedCurve::P256 => Nid::X9_62_PRIME256V1,
        RecommendedCurve::P384 => Nid::SECP384R1,
        RecommendedCurve::P521 => Nid::SECP521R1,
        other => kmip_bail!("Curve Nid {:?} not supported by KMS", other),
    };

    let group = EcGroup::from_curve_name(curve_nid)?;
    let ec_private_key = EcKey::generate(&group)?;

    trace!("create_approved_ecc_key_pair: ec key OK");

    let pkey_bits_number = u32::try_from(ec_private_key.private_key().num_bits())?;
    let private_key = to_ec_private_key(
        &Zeroizing::from(ec_private_key.private_key().to_vec()),
        pkey_bits_number,
        public_key_uid,
        curve,
        algorithm,
        private_key_mask,
    )?;
    trace!("create_approved_ecc_key_pair: private key converted OK");

    let mut ctx = BigNumContext::new()?;
    let public_key = to_ec_public_key(
        &ec_private_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)?,
        pkey_bits_number,
        private_key_uid,
        curve,
        algorithm,
        public_key_mask,
    )?;
    trace!("create_approved_ecc_key_pair: public key converted OK");

    Ok(KeyPair::new(private_key, public_key))
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    #[cfg(not(feature = "fips"))]
    use openssl::pkey::{Id, PKey};
    // Load FIPS provider module from OpenSSL.
    #[cfg(feature = "fips")]
    use openssl::provider::Provider;

    #[cfg(feature = "fips")]
    use super::{check_ecc_mask_against_flags, check_ecc_mask_algorithm_compliance};
    use super::{create_approved_ecc_key_pair, create_ed25519_key_pair};
    #[cfg(not(feature = "fips"))]
    use super::{create_x25519_key_pair, create_x448_key_pair};
    #[cfg(feature = "fips")]
    use crate::crypto::elliptic_curves::{
        operation::create_ed448_key_pair,
        {
            FIPS_PRIVATE_ECC_MASK_ECDH, FIPS_PRIVATE_ECC_MASK_SIGN,
            FIPS_PRIVATE_ECC_MASK_SIGN_ECDH, FIPS_PUBLIC_ECC_MASK_ECDH, FIPS_PUBLIC_ECC_MASK_SIGN,
            FIPS_PUBLIC_ECC_MASK_SIGN_ECDH,
        },
    };
    #[cfg(not(feature = "fips"))]
    use crate::crypto::elliptic_curves::{X25519_PRIVATE_KEY_LENGTH, X448_PRIVATE_KEY_LENGTH};
    #[cfg(not(feature = "fips"))]
    use crate::kmip::kmip_data_structures::KeyMaterial;
    #[cfg(not(feature = "fips"))]
    use crate::pad_be_bytes;
    use crate::{
        kmip::kmip_types::{CryptographicAlgorithm, CryptographicUsageMask, RecommendedCurve},
        openssl::{kmip_private_key_to_openssl, kmip_public_key_to_openssl},
    };

    #[test]
    fn test_ed25519_keypair_generation() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let algorithm = Some(CryptographicAlgorithm::Ed25519);
        let private_key_mask = Some(CryptographicUsageMask::Sign);
        let public_key_mask = Some(CryptographicUsageMask::Verify);

        let keypair1 = create_ed25519_key_pair(
            "sk_uid1",
            "pk_uid1",
            algorithm,
            private_key_mask,
            public_key_mask,
        )
        .unwrap();
        let keypair2 = create_ed25519_key_pair(
            "sk_uid2",
            "pk_uid2",
            algorithm,
            private_key_mask,
            public_key_mask,
        )
        .unwrap();

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
        // Create a Key pair
        // - the private key is a TransparentEcPrivateKey where the key value is the bytes of the scalar
        // - the public key is a TransparentEcPublicKey where the key value is the bytes of the Montgomery point
        let algorithm = Some(CryptographicAlgorithm::EC);
        let private_key_mask = Some(CryptographicUsageMask::Unrestricted);
        let public_key_mask = Some(CryptographicUsageMask::Unrestricted);
        let wrap_key_pair = create_x25519_key_pair(
            "sk_uid",
            "pk_uid",
            algorithm,
            private_key_mask,
            public_key_mask,
        )
        .expect("failed to create x25519 key pair in test_x25519_conversions");

        //
        // public key
        //
        let original_public_key_value = &wrap_key_pair.public_key().key_block().unwrap().key_value;
        let KeyMaterial::TransparentECPublicKey {
            q_string: original_public_key_bytes,
            ..
        } = &original_public_key_value.key_material
        else {
            panic!("Not a transparent public key")
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

    fn keypair_generation(curve: RecommendedCurve) {
        let algorithm = Some(CryptographicAlgorithm::EC);
        let private_key_mask = Some(CryptographicUsageMask::Sign);
        let public_key_mask = Some(CryptographicUsageMask::Verify);

        let keypair1 = create_approved_ecc_key_pair(
            "sk_uid1",
            "pk_uid1",
            curve,
            algorithm,
            private_key_mask,
            public_key_mask,
        )
        .unwrap();
        let keypair2 = create_approved_ecc_key_pair(
            "sk_uid2",
            "pk_uid2",
            curve,
            algorithm,
            private_key_mask,
            public_key_mask,
        )
        .unwrap();

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
        keypair_generation(RecommendedCurve::P192);
    }

    #[test]
    fn test_approved_ecc_keypair_generation() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        // P-CURVES
        keypair_generation(RecommendedCurve::P224);
        keypair_generation(RecommendedCurve::P256);
        keypair_generation(RecommendedCurve::P384);
        keypair_generation(RecommendedCurve::P521);
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_x448_conversions() {
        // Create a Key pair
        // - the private key is a TransparentEcPrivateKey where the key value is the bytes of the scalar
        // - the public key is a TransparentEcPublicKey where the key value is the bytes of the Montgomery point
        let algorithm = Some(CryptographicAlgorithm::Ed448);
        let private_key_mask = Some(CryptographicUsageMask::Sign);
        let public_key_mask = Some(CryptographicUsageMask::Verify);
        let wrap_key_pair = create_x448_key_pair(
            "sk_uid",
            "pk_uid",
            algorithm,
            private_key_mask,
            public_key_mask,
        )
        .expect("failed to create x25519 key pair in test_x448_conversions");

        //
        // public key
        //
        let original_public_key_value = &wrap_key_pair.public_key().key_block().unwrap().key_value;
        let KeyMaterial::TransparentECPublicKey {
            q_string: original_public_key_bytes,
            ..
        } = &original_public_key_value.key_material
        else {
            panic!("Not a transparent public key")
        };
        // try to convert to openssl
        let p_key = PKey::public_key_from_raw_bytes(original_public_key_bytes, Id::X448).unwrap();
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
        pad_be_bytes(&mut original_private_key_bytes, X448_PRIVATE_KEY_LENGTH);
        // try to convert to openssl
        let p_key =
            PKey::private_key_from_raw_bytes(&original_private_key_bytes, Id::X448).unwrap();
        // convert back to bytes
        let raw_bytes = p_key.raw_private_key().unwrap();
        assert_eq!(raw_bytes, original_private_key_bytes);
        // get public key from private
        let raw_public_key_bytes = p_key.raw_public_key().unwrap();
        assert_eq!(&raw_public_key_bytes, original_public_key_bytes);
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_mask_flags_exact() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mask = CryptographicUsageMask::Sign
            | CryptographicUsageMask::Verify
            | CryptographicUsageMask::Encrypt
            | CryptographicUsageMask::Decrypt;

        let flags = CryptographicUsageMask::Sign
            | CryptographicUsageMask::Verify
            | CryptographicUsageMask::Encrypt
            | CryptographicUsageMask::Decrypt;

        let res = check_ecc_mask_against_flags(Some(mask), flags);

        res.unwrap();
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_mask_flags_correct() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mask = CryptographicUsageMask::Authenticate;

        let flags = CryptographicUsageMask::Sign
            | CryptographicUsageMask::Verify
            | CryptographicUsageMask::CertificateSign
            | CryptographicUsageMask::CRLSign
            | CryptographicUsageMask::Authenticate;

        let res = check_ecc_mask_against_flags(Some(mask), flags);

        res.unwrap();
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_mask_flags_none() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let flags = CryptographicUsageMask::Unrestricted;

        let res = check_ecc_mask_against_flags(None, flags);

        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_mask_flags_all() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mask = FIPS_PRIVATE_ECC_MASK_SIGN;

        let flags = CryptographicUsageMask::Sign
            | CryptographicUsageMask::Verify
            | CryptographicUsageMask::Encrypt
            | CryptographicUsageMask::Decrypt
            | CryptographicUsageMask::WrapKey
            | CryptographicUsageMask::UnwrapKey
            | CryptographicUsageMask::MACGenerate
            | CryptographicUsageMask::MACVerify
            | CryptographicUsageMask::DeriveKey
            | CryptographicUsageMask::KeyAgreement
            | CryptographicUsageMask::CertificateSign
            | CryptographicUsageMask::CRLSign
            | CryptographicUsageMask::Authenticate;

        let res = check_ecc_mask_against_flags(Some(mask), flags);

        res.unwrap();
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_mask_flags_fips_sign() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mask = CryptographicUsageMask::Sign;
        let res = check_ecc_mask_against_flags(Some(mask), FIPS_PRIVATE_ECC_MASK_SIGN);

        res.unwrap();

        let mask = CryptographicUsageMask::Verify;
        let res = check_ecc_mask_against_flags(Some(mask), FIPS_PUBLIC_ECC_MASK_SIGN);

        res.unwrap();
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_mask_flags_fips_dh() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mask = CryptographicUsageMask::KeyAgreement;
        let res = check_ecc_mask_against_flags(Some(mask), FIPS_PRIVATE_ECC_MASK_ECDH);

        res.unwrap();

        let mask = CryptographicUsageMask::KeyAgreement;
        let res = check_ecc_mask_against_flags(Some(mask), FIPS_PUBLIC_ECC_MASK_ECDH);

        res.unwrap();

        let mask = CryptographicUsageMask::CRLSign
            | CryptographicUsageMask::CertificateSign
            | CryptographicUsageMask::KeyAgreement;
        let res = check_ecc_mask_against_flags(Some(mask), FIPS_PRIVATE_ECC_MASK_SIGN_ECDH);

        res.unwrap();

        let mask = CryptographicUsageMask::Verify | CryptographicUsageMask::KeyAgreement;
        let res = check_ecc_mask_against_flags(Some(mask), FIPS_PUBLIC_ECC_MASK_SIGN_ECDH);

        res.unwrap();
    }

    #[test]
    #[cfg(feature = "fips")]
    /// This test should fail for unrestricted should not happen in FIPS mode.
    fn test_mask_flags_unrestricted1() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mask = CryptographicUsageMask::Unrestricted;
        let flags = CryptographicUsageMask::Unrestricted;

        let res = check_ecc_mask_against_flags(Some(mask), flags);

        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "fips")]
    /// This test should fail for unrestricted should not happen in FIPS mode.
    fn test_mask_flags_unrestricted2() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mask = CryptographicUsageMask::Sign
            | CryptographicUsageMask::Verify
            | CryptographicUsageMask::Encrypt
            | CryptographicUsageMask::Decrypt;
        let flags = CryptographicUsageMask::Unrestricted;

        let res = check_ecc_mask_against_flags(Some(mask), flags);

        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "fips")]
    /// This test should fail for unrestricted should not happen in FIPS mode.
    fn test_mask_flags_incorrect1() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mask = CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt;
        let flags = CryptographicUsageMask::Encrypt;

        let res = check_ecc_mask_against_flags(Some(mask), flags);

        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "fips")]
    /// This test should fail for unrestricted should not happen in FIPS mode.
    fn test_mask_flags_incorrect2() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mask = CryptographicUsageMask::WrapKey;
        let flags = CryptographicUsageMask::UnwrapKey;

        let res = check_ecc_mask_against_flags(Some(mask), flags);

        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "fips")]
    /// This test should fail for unrestricted should not happen in FIPS mode.
    fn test_mask_flags_incorrect3() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let mask = CryptographicUsageMask::Sign
            | CryptographicUsageMask::Verify
            | CryptographicUsageMask::Encrypt
            | CryptographicUsageMask::Decrypt;
        let flags = CryptographicUsageMask::Sign
            | CryptographicUsageMask::Verify
            | CryptographicUsageMask::CRLSign
            | CryptographicUsageMask::Decrypt;

        let res = check_ecc_mask_against_flags(Some(mask), flags);

        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_check_ecc_algo_none() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let private_key_mask = CryptographicUsageMask::Sign;
        let public_key_mask = CryptographicUsageMask::Verify;

        let allowed = &[CryptographicAlgorithm::Ed25519];
        let res = check_ecc_mask_algorithm_compliance(
            Some(private_key_mask),
            Some(public_key_mask),
            None,
            allowed,
        );

        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_check_ecc_algo_contains() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let private_key_mask = CryptographicUsageMask::KeyAgreement;
        let public_key_mask = CryptographicUsageMask::KeyAgreement;

        let algorithm = CryptographicAlgorithm::ECDH;
        let allowed = &[
            CryptographicAlgorithm::ECDH,
            CryptographicAlgorithm::ECDSA,
            CryptographicAlgorithm::EC,
        ];
        let res = check_ecc_mask_algorithm_compliance(
            Some(private_key_mask),
            Some(public_key_mask),
            Some(algorithm),
            allowed,
        );

        res.unwrap();
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_check_ecc_algo_not_contains() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let private_key_mask = CryptographicUsageMask::KeyAgreement;
        let public_key_mask = CryptographicUsageMask::KeyAgreement;

        let algorithm = CryptographicAlgorithm::ECDH;
        let allowed = &[CryptographicAlgorithm::ECDSA, CryptographicAlgorithm::EC];
        let res = check_ecc_mask_algorithm_compliance(
            Some(private_key_mask),
            Some(public_key_mask),
            Some(algorithm),
            allowed,
        );

        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_create_ecc_keys_bad_mask() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let algorithm = CryptographicAlgorithm::EC;
        let private_key_mask = CryptographicUsageMask::Decrypt;
        let public_key_mask = CryptographicUsageMask::Encrypt;
        let res = create_approved_ecc_key_pair(
            "pubkey01",
            "privkey01",
            RecommendedCurve::P256,
            Some(algorithm),
            Some(private_key_mask),
            Some(public_key_mask),
        );

        assert!(res.is_err());

        let algorithm = CryptographicAlgorithm::ECDSA;
        let private_key_mask = CryptographicUsageMask::Unrestricted;
        let public_key_mask = CryptographicUsageMask::Unrestricted;
        let res = create_approved_ecc_key_pair(
            "pubkey02",
            "privkey02",
            RecommendedCurve::P384,
            Some(algorithm),
            Some(private_key_mask),
            Some(public_key_mask),
        );

        assert!(res.is_err());

        let algorithm = CryptographicAlgorithm::ECDH;
        let public_key_mask = CryptographicUsageMask::KeyAgreement;
        let res = create_approved_ecc_key_pair(
            "pubkey03",
            "privkey03",
            RecommendedCurve::P521,
            Some(algorithm),
            None,
            Some(public_key_mask),
        );

        assert!(res.is_err());

        let algorithm = CryptographicAlgorithm::ECDH;
        let private_key_mask = CryptographicUsageMask::KeyAgreement;
        let res = create_approved_ecc_key_pair(
            "pubkey04",
            "privkey04",
            RecommendedCurve::P521,
            Some(algorithm),
            Some(private_key_mask),
            None,
        );

        assert!(res.is_err());

        let algorithm = CryptographicAlgorithm::Ed448;
        let private_key_mask = CryptographicUsageMask::Sign;
        let public_key_mask = CryptographicUsageMask::Verify | CryptographicUsageMask::KeyAgreement;
        let res = create_ed448_key_pair(
            "pubkey05",
            "privkey05",
            Some(algorithm),
            Some(private_key_mask),
            Some(public_key_mask),
        );

        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_create_ecc_keys_bad_algorithm() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let algorithm = CryptographicAlgorithm::Ed25519;
        let private_key_mask = CryptographicUsageMask::Sign;
        let public_key_mask = CryptographicUsageMask::Verify;
        let res = create_approved_ecc_key_pair(
            "pubkey01",
            "privkey01",
            RecommendedCurve::P256,
            Some(algorithm),
            Some(private_key_mask),
            Some(public_key_mask),
        );

        assert!(res.is_err());

        let private_key_mask = CryptographicUsageMask::Sign;
        let public_key_mask = CryptographicUsageMask::Verify;

        let res = create_approved_ecc_key_pair(
            "pubkey02",
            "privkey02",
            RecommendedCurve::P256,
            None,
            Some(private_key_mask),
            Some(public_key_mask),
        );

        assert!(res.is_err());

        let algorithm = CryptographicAlgorithm::Ed25519;
        let private_key_mask = CryptographicUsageMask::Sign;
        let public_key_mask = CryptographicUsageMask::Verify;
        let res = create_ed448_key_pair(
            "pubkey01",
            "privkey01",
            Some(algorithm),
            Some(private_key_mask),
            Some(public_key_mask),
        );

        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_create_ecc_keys_incorrect_mask_and_algorithm_ecdh() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        // ECDH algorithm should not have Sign and Verify masks;
        let algorithm = CryptographicAlgorithm::ECDH;
        let private_key_mask = CryptographicUsageMask::Sign
            | CryptographicUsageMask::KeyAgreement
            | CryptographicUsageMask::DeriveKey;
        let public_key_mask = CryptographicUsageMask::Verify
            | CryptographicUsageMask::KeyAgreement
            | CryptographicUsageMask::DeriveKey;
        let res = create_approved_ecc_key_pair(
            "pubkey01",
            "privkey01",
            RecommendedCurve::P256,
            Some(algorithm),
            Some(private_key_mask),
            Some(public_key_mask),
        );

        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_create_ecc_keys_incorrect_mask_and_algorithm_ecdsa() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        // ECDSA algorithm should not have KeyAgreement mask;
        let algorithm = CryptographicAlgorithm::ECDSA;
        let private_key_mask = CryptographicUsageMask::Sign;
        let public_key_mask = CryptographicUsageMask::Verify | CryptographicUsageMask::KeyAgreement;
        let res = create_approved_ecc_key_pair(
            "pubkey01",
            "privkey01",
            RecommendedCurve::P256,
            Some(algorithm),
            Some(private_key_mask),
            Some(public_key_mask),
        );

        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_create_ecc_keys_incorrect_private_mask() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let algorithm = CryptographicAlgorithm::ECDSA;
        let private_key_mask = CryptographicUsageMask::Sign | CryptographicUsageMask::Verify;
        let public_key_mask = CryptographicUsageMask::Verify;
        let res = create_approved_ecc_key_pair(
            "pubkey01",
            "privkey01",
            RecommendedCurve::P256,
            Some(algorithm),
            Some(private_key_mask),
            Some(public_key_mask),
        );

        assert!(res.is_err());
    }

    #[test]
    #[cfg(feature = "fips")]
    fn test_create_ecc_keys_incorrect_public_mask() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let algorithm = CryptographicAlgorithm::ECDSA;
        let private_key_mask = CryptographicUsageMask::Sign;
        let public_key_mask = CryptographicUsageMask::Sign;
        let res = create_approved_ecc_key_pair(
            "pubkey01",
            "privkey01",
            RecommendedCurve::P256,
            Some(algorithm),
            Some(private_key_mask),
            Some(public_key_mask),
        );

        assert!(res.is_err());
    }
}
