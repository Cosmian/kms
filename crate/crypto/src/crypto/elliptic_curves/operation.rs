#[cfg(not(feature = "non-fips"))]
use cosmian_kmip::kmip_2_1::extra::fips::{
    FIPS_PRIVATE_ECC_MASK_SIGN, FIPS_PRIVATE_ECC_MASK_SIGN_ECDH, FIPS_PUBLIC_ECC_MASK_SIGN,
    FIPS_PUBLIC_ECC_MASK_SIGN_ECDH,
};
use cosmian_kmip::{
    SafeBigInt,
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PrivateKey, PublicKey},
        kmip_types::{
            CryptographicAlgorithm, CryptographicDomainParameters, CryptographicParameters,
            KeyFormatType, Link, LinkType, LinkedObjectIdentifier, RecommendedCurve,
            UniqueIdentifier,
        },
    },
};
use cosmian_logger::trace;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    nid::Nid,
    pkey::PKey,
};
use zeroize::Zeroizing;

use crate::{
    crypto::KeyPair,
    crypto_bail,
    error::{CryptoError, result::CryptoResult},
};

#[cfg(not(feature = "non-fips"))]
/// Check that bits set in `mask` are only bits set in `flags`. If any bit set
/// in `mask` is not set in `flags`, raise an error.
///
/// If `mask` is None, raise an error.
fn check_ecc_mask_against_flags(
    mask: Option<CryptographicUsageMask>,
    flags: CryptographicUsageMask,
) -> Result<(), CryptoError> {
    if (flags & CryptographicUsageMask::Unrestricted).bits() != 0 {
        crypto_bail!(
            "Unrestricted CryptographicUsageMask for elliptic curves is too permissive for FIPS \
             mode."
        )
    }

    let Some(mask) = mask else {
        // Mask is `None` but FIPS mode is restrictive, so it's considered too
        // permissive.
        crypto_bail!(
            "EC: forbidden CryptographicUsageMask value, got None but expected among {:#010X} in \
             FIPS mode.",
            flags.bits()
        )
    };

    if (mask & !flags).bits() != 0 {
        crypto_bail!(
            "EC: forbidden CryptographicUsageMask flag set: {:#010X}, expected among {:#010X} in \
             FIPS mode.",
            mask.bits(),
            flags.bits()
        )
    }
    Ok(())
}

#[cfg(not(feature = "non-fips"))]
/// Check that
/// - `algorithm` is among `allowed` algorithms.
/// - `algorithm` is compliant with usage mask provided for private and public key components.
///
/// For example, `ECDH` and `Sign` are incompatible together since ECDH is for key agreement.
///
/// If `algorithm` is None, raise error.
fn check_ecc_mask_algorithm_compliance(
    private_key_mask: Option<CryptographicUsageMask>,
    public_key_mask: Option<CryptographicUsageMask>,
    algorithm: CryptographicAlgorithm,
    allowed_algorithms: &[CryptographicAlgorithm],
) -> Result<(), CryptoError> {
    if !allowed_algorithms.contains(&algorithm) {
        crypto_bail!("EC: forbidden CryptographicAlgorithm value in FIPS mode.")
    }
    match algorithm {
        CryptographicAlgorithm::ECDH | CryptographicAlgorithm::EC => {
            check_ecc_mask_against_flags(private_key_mask, FIPS_PRIVATE_ECC_MASK_SIGN_ECDH)?;
            check_ecc_mask_against_flags(public_key_mask, FIPS_PUBLIC_ECC_MASK_SIGN_ECDH)?;
        }
        CryptographicAlgorithm::ECDSA
        | CryptographicAlgorithm::Ed25519
        | CryptographicAlgorithm::Ed448 => {
            check_ecc_mask_against_flags(private_key_mask, FIPS_PRIVATE_ECC_MASK_SIGN)?;
            check_ecc_mask_against_flags(public_key_mask, FIPS_PUBLIC_ECC_MASK_SIGN)?;
        }
        // If `allowed` parameter is set correctly, should never fall in this case.
        _ => crypto_bail!("Invalid CryptographicAlgorithm value."),
    }
    Ok(())
}

/// Convert to an Elliptic Curve KMIP Public Key.
/// Supported curves are:
/// X25519, Ed25519, X448, Ed448, P-192, P-224, P-256, P-384, P-521.
///
/// `pkey_bits_number` is passed independently of `len(bytes)` since some key
/// sizes are not multiple of 8, thus it cannot be computed by taking the byte
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
) -> CryptoResult<Object> {
    let cryptographic_length = Some(i32::try_from(bytes.len())? * 8);
    trace!(
        "bytes len: {:?}, bits: {}",
        cryptographic_length, pkey_bits_number
    );

    let q_length = Some(i32::try_from(pkey_bits_number)?);
    Ok(Object::PublicKey(PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: algorithm,
            key_format_type: KeyFormatType::TransparentECPublicKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentECPublicKey {
                    recommended_curve: curve,
                    q_string: bytes.to_vec(),
                },
                attributes: Some(Attributes {
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
                        qlength: q_length,
                        recommended_curve: Some(curve),
                    }),
                    link: Some(vec![Link {
                        link_type: LinkType::PrivateKeyLink,
                        linked_object_identifier: LinkedObjectIdentifier::TextString(
                            private_key_uid.to_owned(),
                        ),
                    }]),
                    ..Attributes::default()
                }),
            }),
            cryptographic_length,
            key_wrapping_data: None,
        },
    }))
}

/// Convert to an Elliptic Curve KMIP Private Key.
/// Supported curves are:
/// X25519, Ed25519, X448, Ed448, P-192, P-224, P-256, P-384, P-521.
///
/// `pkey_bits_number` is passed independently of `len(bytes)` since some key
/// sizes are not multiple of 8, thus it cannot be computed by taking the byte
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
    sensitive: bool,
) -> CryptoResult<Object> {
    let cryptographic_length = Some(i32::try_from(bytes.len())? * 8);

    trace!(
        "bytes len: {:?}, bits: {}",
        cryptographic_length, pkey_bits_number
    );

    let q_length = Some(i32::try_from(pkey_bits_number)?);
    Ok(Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            cryptographic_algorithm: algorithm,
            key_format_type: KeyFormatType::TransparentECPrivateKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentECPrivateKey {
                    recommended_curve: curve,
                    d: Box::new(SafeBigInt::from_bytes_be(bytes)),
                },
                attributes: Some(Attributes {
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
                        qlength: q_length,
                        recommended_curve: Some(curve),
                    }),
                    link: Some(vec![Link {
                        link_type: LinkType::PublicKeyLink,
                        linked_object_identifier: LinkedObjectIdentifier::TextString(
                            public_key_uid.to_owned(),
                        ),
                    }]),
                    sensitive: sensitive.then_some(true),
                    ..Attributes::default()
                }),
            }),
            cryptographic_length,
            key_wrapping_data: None,
        },
    }))
}

/// Generate an X25519 Key Pair. Not FIPS 140-3 compliant.
#[cfg(feature = "non-fips")]
pub fn create_x25519_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
    cryptographic_algorithm: &CryptographicAlgorithm,
    common_attributes: Attributes,
    private_key_attributes: Option<Attributes>,
    public_key_attributes: Option<Attributes>,
) -> Result<KeyPair, CryptoError> {
    let private_key = PKey::generate_x25519()?;

    let private_key_bytes = Zeroizing::from(private_key.raw_private_key()?);
    let private_key_num_bits = private_key.bits();
    let public_key_bytes = private_key.raw_public_key()?;

    create_ec_key_pair(
        &private_key_bytes,
        private_key_num_bits,
        &public_key_bytes,
        private_key_uid,
        public_key_uid,
        RecommendedCurve::CURVE25519,
        *cryptographic_algorithm,
        common_attributes,
        private_key_attributes,
        public_key_attributes,
    )
}

/// Generate a SEC 2 Key Pair. Not FIPS 140-3 compliant.
/// SEC 2: Recommended Elliptic Curve Domain Parameters: <https://www.secg.org/sec2-v2.pdf>
#[cfg(feature = "non-fips")]
pub fn create_secp_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
    curve: RecommendedCurve,
    cryptographic_algorithm: &CryptographicAlgorithm,
    common_attributes: Attributes,
    private_key_attributes: Option<Attributes>,
    public_key_attributes: Option<Attributes>,
) -> Result<KeyPair, CryptoError> {
    let curve_nid = match curve {
        RecommendedCurve::SECP224K1 => Nid::SECP224K1,
        RecommendedCurve::SECP256K1 => Nid::SECP256K1,

        other => crypto_bail!("Curve {:?} not supported by secp_key key generation", other),
    };

    // 1. Get the secp_key curve group
    let group = EcGroup::from_curve_name(curve_nid)?;
    // 2. Generate a new EC keypair
    let ec_key = EcKey::generate(&group)?;
    // 3. Extract the private and public key bytes
    let private_key_bytes = Zeroizing::from(ec_key.private_key().to_vec());
    let private_key_num_bits = u32::try_from(ec_key.private_key().num_bits())?;
    let mut ctx = BigNumContext::new()?;
    let public_key_bytes =
        ec_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)?;

    create_ec_key_pair(
        &private_key_bytes,
        private_key_num_bits,
        &public_key_bytes,
        private_key_uid,
        public_key_uid,
        curve,
        *cryptographic_algorithm,
        common_attributes,
        private_key_attributes,
        public_key_attributes,
    )
}

/// Generate an X448 Key Pair. Not FIPS 140-3 compliant.
#[cfg(feature = "non-fips")]
pub fn create_x448_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
    cryptographic_algorithm: &CryptographicAlgorithm,
    common_attributes: Attributes,
    private_key_attributes: Option<Attributes>,
    public_key_attributes: Option<Attributes>,
) -> Result<KeyPair, CryptoError> {
    let private_key = PKey::generate_x448()?;

    let private_key_bytes = Zeroizing::from(private_key.raw_private_key()?);
    let private_key_num_bits = private_key.bits();
    let public_key_bytes = private_key.raw_public_key()?;

    create_ec_key_pair(
        &private_key_bytes,
        private_key_num_bits,
        &public_key_bytes,
        private_key_uid,
        public_key_uid,
        RecommendedCurve::CURVE448,
        *cryptographic_algorithm,
        common_attributes,
        private_key_attributes,
        public_key_attributes,
    )
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
    common_attributes: Attributes,
    private_key_attributes: Option<Attributes>,
    public_key_attributes: Option<Attributes>,
) -> Result<KeyPair, CryptoError> {
    #[cfg(not(feature = "non-fips"))]
    {
        // Cryptographic Usage Masks
        let private_key_mask = private_key_attributes
            .as_ref()
            .and_then(|attr| attr.cryptographic_usage_mask);
        let public_key_mask = public_key_attributes
            .as_ref()
            .and_then(|attr| attr.cryptographic_usage_mask);

        // Validate FIPS algorithms and mask.
        check_ecc_mask_algorithm_compliance(
            private_key_mask,
            public_key_mask,
            CryptographicAlgorithm::Ed25519,
            &[CryptographicAlgorithm::Ed25519],
        )?;
    }

    let private_key = PKey::generate_ed25519()?;
    let private_key_bytes = Zeroizing::from(private_key.raw_private_key()?);
    let private_key_num_bits = private_key.bits();
    let public_key_bytes = private_key.raw_public_key()?;

    create_ec_key_pair(
        &private_key_bytes,
        private_key_num_bits,
        &public_key_bytes,
        private_key_uid,
        public_key_uid,
        RecommendedCurve::CURVEED25519,
        CryptographicAlgorithm::Ed25519,
        common_attributes,
        private_key_attributes,
        public_key_attributes,
    )
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
    common_attributes: Attributes,
    private_key_attributes: Option<Attributes>,
    public_key_attributes: Option<Attributes>,
) -> Result<KeyPair, CryptoError> {
    #[cfg(not(feature = "non-fips"))]
    {
        // Cryptographic Usage Masks
        let private_key_mask = private_key_attributes
            .as_ref()
            .and_then(|attr| attr.cryptographic_usage_mask);
        let public_key_mask = public_key_attributes
            .as_ref()
            .and_then(|attr| attr.cryptographic_usage_mask);

        // Validate FIPS algorithms and mask.
        check_ecc_mask_algorithm_compliance(
            private_key_mask,
            public_key_mask,
            CryptographicAlgorithm::Ed448,
            &[CryptographicAlgorithm::Ed448],
        )?;
    }

    let private_key = PKey::generate_ed448()?;
    let private_key_bytes = Zeroizing::from(private_key.raw_private_key()?);
    let private_key_num_bits = private_key.bits();
    let public_key_bytes = private_key.raw_public_key()?;

    create_ec_key_pair(
        &private_key_bytes,
        private_key_num_bits,
        &public_key_bytes,
        private_key_uid,
        public_key_uid,
        RecommendedCurve::CURVEED448,
        CryptographicAlgorithm::Ed448,
        common_attributes,
        private_key_attributes,
        public_key_attributes,
    )
}

pub fn create_approved_ecc_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
    curve: RecommendedCurve,
    cryptographic_algorithm: &CryptographicAlgorithm,
    common_attributes: Attributes,
    private_key_attributes: Option<Attributes>,
    public_key_attributes: Option<Attributes>,
) -> Result<KeyPair, CryptoError> {
    #[cfg(not(feature = "non-fips"))]
    {
        // Cryptographic Usage Masks
        let private_key_mask = private_key_attributes
            .as_ref()
            .and_then(|attr| attr.cryptographic_usage_mask);
        let public_key_mask = public_key_attributes
            .as_ref()
            .and_then(|attr| attr.cryptographic_usage_mask);

        // Validate FIPS algorithms and mask.
        check_ecc_mask_algorithm_compliance(
            private_key_mask,
            public_key_mask,
            *cryptographic_algorithm,
            &[
                CryptographicAlgorithm::EC,
                CryptographicAlgorithm::ECDSA,
                CryptographicAlgorithm::ECDH,
            ],
        )?;
    }

    let curve_nid = match curve {
        #[cfg(feature = "non-fips")]
        RecommendedCurve::P192 => Nid::X9_62_PRIME192V1,
        RecommendedCurve::P224 => Nid::SECP224R1,
        RecommendedCurve::P256 => Nid::X9_62_PRIME256V1,
        RecommendedCurve::P384 => Nid::SECP384R1,
        RecommendedCurve::P521 => Nid::SECP521R1,
        #[cfg(feature = "non-fips")]
        RecommendedCurve::SECP256K1 => Nid::SECP256K1,
        #[cfg(feature = "non-fips")]
        RecommendedCurve::SECP224K1 => Nid::SECP224K1,
        other => crypto_bail!("Curve Nid {:?} not supported by KMS", other),
    };

    let group = EcGroup::from_curve_name(curve_nid)?;
    let ec_private_key = EcKey::generate(&group)?;

    let private_key_bytes = Zeroizing::from(ec_private_key.private_key().to_vec());
    let private_key_num_bits = u32::try_from(ec_private_key.private_key().num_bits())?;
    let mut ctx = BigNumContext::new()?;
    let public_key_bytes =
        ec_private_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)?;
    create_ec_key_pair(
        &private_key_bytes,
        private_key_num_bits,
        &public_key_bytes,
        private_key_uid,
        public_key_uid,
        curve,
        *cryptographic_algorithm,
        common_attributes,
        private_key_attributes,
        public_key_attributes,
    )
}

// Re-export sign helper from elliptic_curves module root
pub use crate::crypto::elliptic_curves::sign::ecdsa_sign;

#[expect(clippy::too_many_arguments)]
fn create_ec_key_pair(
    private_key_bytes: &Zeroizing<Vec<u8>>,
    private_key_num_bits: u32,
    public_key_bytes: &[u8],
    private_key_uid: &str,
    public_key_uid: &str,
    curve: RecommendedCurve,
    cryptographic_algorithm: CryptographicAlgorithm,
    mut common_attributes: Attributes,
    private_key_attributes: Option<Attributes>,
    public_key_attributes: Option<Attributes>,
) -> Result<KeyPair, CryptoError> {
    // Cryptographic Usage Masks
    let private_key_mask = private_key_attributes
        .as_ref()
        .and_then(|attr| attr.cryptographic_usage_mask);
    let public_key_mask = public_key_attributes
        .as_ref()
        .and_then(|attr| attr.cryptographic_usage_mask);

    // recover tags and clean them up from the common attributes
    let tags = common_attributes.remove_tags().unwrap_or_default();
    Attributes::check_user_tags(&tags)?;

    // Generate  KMIP private Key
    let mut private_key_attributes = private_key_attributes.unwrap_or_default();
    private_key_attributes.merge(&common_attributes, false);
    let mut private_key = to_ec_private_key(
        private_key_bytes,
        private_key_num_bits,
        public_key_uid,
        curve,
        Some(cryptographic_algorithm),
        private_key_mask,
        private_key_attributes.sensitive.unwrap_or_default(),
    )?;
    // Merge the created object attributes
    private_key_attributes.merge(private_key.attributes()?, true);
    // Set the private key UID
    private_key_attributes.unique_identifier =
        Some(UniqueIdentifier::TextString(private_key_uid.to_owned()));
    // Add the tags
    let mut sk_tags = tags.clone();
    sk_tags.insert("_sk".to_owned());
    private_key_attributes.set_tags(sk_tags)?;
    // and set them on the object
    *private_key.key_block_mut()?.attributes_mut()? = private_key_attributes;
    trace!("private key converted OK");

    // Generate  KMIP public Key
    let mut public_key_attributes = public_key_attributes.unwrap_or_default();
    public_key_attributes.merge(&common_attributes, false);
    let mut public_key = to_ec_public_key(
        public_key_bytes,
        private_key_num_bits,
        private_key_uid,
        curve,
        Some(cryptographic_algorithm),
        public_key_mask,
    )?;
    // Merge the created object attributes
    public_key_attributes.merge(public_key.attributes()?, true);
    // Set the public key UID
    public_key_attributes.unique_identifier =
        Some(UniqueIdentifier::TextString(public_key_uid.to_owned()));
    // Add the tags
    let mut pk_tags = tags;
    pk_tags.insert("_pk".to_owned());
    public_key_attributes.set_tags(pk_tags)?;
    // and set them on the object
    *public_key.key_block_mut()?.attributes_mut()? = public_key_attributes;
    trace!("public key converted OK");

    Ok(KeyPair::new(private_key, public_key))
}

#[expect(clippy::unwrap_used)]
#[cfg(test)]
mod tests {

    #[cfg(not(feature = "non-fips"))]
    use cosmian_kmip::kmip_2_1::extra::fips::{
        FIPS_PRIVATE_ECC_MASK_ECDH, FIPS_PRIVATE_ECC_MASK_SIGN, FIPS_PRIVATE_ECC_MASK_SIGN_ECDH,
        FIPS_PUBLIC_ECC_MASK_ECDH, FIPS_PUBLIC_ECC_MASK_SIGN, FIPS_PUBLIC_ECC_MASK_SIGN_ECDH,
    };
    #[cfg(feature = "non-fips")]
    use cosmian_kmip::kmip_2_1::kmip_data_structures::KeyMaterial;
    use cosmian_kmip::{
        kmip_0::kmip_types::CryptographicUsageMask,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_types::{CryptographicAlgorithm, RecommendedCurve},
        },
    };
    #[cfg(feature = "non-fips")]
    use openssl::pkey::{Id, PKey};
    // Load FIPS provider module from OpenSSL.
    #[cfg(not(feature = "non-fips"))]
    use openssl::provider::Provider;

    #[cfg(not(feature = "non-fips"))]
    use super::{check_ecc_mask_against_flags, check_ecc_mask_algorithm_compliance};
    use super::{create_approved_ecc_key_pair, create_ed25519_key_pair};
    #[cfg(feature = "non-fips")]
    use super::{create_x448_key_pair, create_x25519_key_pair};
    #[cfg(not(feature = "non-fips"))]
    use crate::crypto::elliptic_curves::operation::create_ed448_key_pair;
    #[cfg(feature = "non-fips")]
    use crate::crypto::elliptic_curves::{X448_PRIVATE_KEY_LENGTH, X25519_PRIVATE_KEY_LENGTH};
    use crate::openssl::{kmip_private_key_to_openssl, kmip_public_key_to_openssl};
    #[cfg(feature = "non-fips")]
    use crate::pad_be_bytes;

    #[test]
    fn test_ed25519_keypair_generation() {
        #[cfg(not(feature = "non-fips"))]
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Sign),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Verify),
            ..Attributes::default()
        };

        let keypair1 = create_ed25519_key_pair(
            "sk_uid1",
            "pk_uid1",
            Attributes::default(),
            Some(private_key_attributes.clone()),
            Some(public_key_attributes.clone()),
        )
        .unwrap();
        let keypair2 = create_ed25519_key_pair(
            "sk_uid2",
            "pk_uid2",
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
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

    #[expect(clippy::expect_used, clippy::panic)]
    #[test]
    #[cfg(feature = "non-fips")]
    fn test_x25519_conversions() {
        // Create a Key pair
        // - the private key is a TransparentEcPrivateKey where the key value is the bytes of the scalar
        // - the public key is a TransparentEcPublicKey where the key value is the bytes of the Montgomery point

        use cosmian_kmip::kmip_2_1::kmip_data_structures::KeyValue;
        let algorithm = CryptographicAlgorithm::ECDH;
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
            ..Attributes::default()
        };
        let wrap_key_pair = create_x25519_key_pair(
            "sk_uid",
            "pk_uid",
            &algorithm,
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
        )
        .expect("failed to create x25519 key pair in test_x25519_conversions");

        // public key
        //
        let Some(KeyValue::Structure { key_material, .. }) =
            &wrap_key_pair.public_key().key_block().unwrap().key_value
        else {
            panic!("failed to get key value from public key in test_x25519_conversions")
        };
        let KeyMaterial::TransparentECPublicKey {
            q_string: original_public_key_bytes,
            ..
        } = key_material
        else {
            panic!("Not a transparent public key")
        };
        // try to convert to openssl
        let p_key = PKey::public_key_from_raw_bytes(original_public_key_bytes, Id::X25519).unwrap();
        // convert back to bytes
        let raw_bytes = p_key.raw_public_key().unwrap();
        assert_eq!(&raw_bytes, original_public_key_bytes);

        // private key
        //
        let Some(KeyValue::Structure { key_material, .. }) =
            &wrap_key_pair.private_key().key_block().unwrap().key_value
        else {
            panic!("failed to get key value from public key in test_x25519_conversions")
        };
        let mut original_private_key_bytes = match key_material {
            KeyMaterial::TransparentECPrivateKey { d, .. } => d.to_bytes_be().1,
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
        let algorithm = CryptographicAlgorithm::ECDH;
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Sign),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Verify),
            ..Attributes::default()
        };

        let keypair1 = create_approved_ecc_key_pair(
            "sk_uid1",
            "pk_uid1",
            curve,
            &algorithm,
            Attributes::default(),
            Some(private_key_attributes.clone()),
            Some(public_key_attributes.clone()),
        )
        .unwrap();
        let keypair2 = create_approved_ecc_key_pair(
            "sk_uid2",
            "pk_uid2",
            curve,
            &algorithm,
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
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
    #[cfg(feature = "non-fips")]
    fn test_p192_keypair_generation() {
        keypair_generation(RecommendedCurve::P192);
    }

    #[test]
    fn test_approved_ecc_keypair_generation() {
        #[cfg(not(feature = "non-fips"))]
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        // P-CURVES
        keypair_generation(RecommendedCurve::P224);
        keypair_generation(RecommendedCurve::P256);
        keypair_generation(RecommendedCurve::P384);
        keypair_generation(RecommendedCurve::P521);
    }

    #[expect(clippy::expect_used, clippy::panic)]
    #[test]
    #[cfg(feature = "non-fips")]
    fn test_x448_conversions() {
        // Create a Key pair
        // - the private key is a TransparentEcPrivateKey where the key value is the bytes of the scalar
        // - the public key is a TransparentEcPublicKey where the key value is the bytes of the Montgomery point

        use cosmian_kmip::kmip_2_1::kmip_data_structures::KeyValue;
        let algorithm = CryptographicAlgorithm::Ed448;
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Sign),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Verify),
            ..Attributes::default()
        };
        let wrap_key_pair = create_x448_key_pair(
            "sk_uid",
            "pk_uid",
            &algorithm,
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
        )
        .expect("failed to create x25519 key pair in test_x448_conversions");

        // public key
        //
        let Some(KeyValue::Structure { key_material, .. }) = wrap_key_pair
            .public_key()
            .key_block()
            .unwrap()
            .key_value
            .as_ref()
        else {
            panic!("Key value not found in public key");
        };
        let KeyMaterial::TransparentECPublicKey {
            q_string: original_public_key_bytes,
            ..
        } = key_material
        else {
            panic!("Not a transparent public key")
        };
        // try to convert to openssl
        let p_key = PKey::public_key_from_raw_bytes(original_public_key_bytes, Id::X448).unwrap();
        // convert back to bytes
        let raw_bytes = p_key.raw_public_key().unwrap();
        assert_eq!(&raw_bytes, original_public_key_bytes);

        // private key
        //
        let Some(KeyValue::Structure { key_material, .. }) = wrap_key_pair
            .private_key()
            .key_block()
            .unwrap()
            .key_value
            .as_ref()
        else {
            panic!("Key value not found in private key");
        };
        let mut original_private_key_bytes = match key_material {
            KeyMaterial::TransparentECPrivateKey { d, .. } => d.to_bytes_be().1,
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
    #[cfg(not(feature = "non-fips"))]
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
    #[cfg(not(feature = "non-fips"))]
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
    #[cfg(not(feature = "non-fips"))]
    fn test_mask_flags_none() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let flags = CryptographicUsageMask::Unrestricted;

        let res = check_ecc_mask_against_flags(None, flags);

        assert!(res.is_err());
    }

    #[test]
    #[cfg(not(feature = "non-fips"))]
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
    #[cfg(not(feature = "non-fips"))]
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
    #[cfg(not(feature = "non-fips"))]
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
    #[cfg(not(feature = "non-fips"))]
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
    #[cfg(not(feature = "non-fips"))]
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
    #[cfg(not(feature = "non-fips"))]
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
    #[cfg(not(feature = "non-fips"))]
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
    #[cfg(not(feature = "non-fips"))]
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
    #[cfg(not(feature = "non-fips"))]
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
            algorithm,
            allowed,
        );

        res.unwrap();
    }

    #[test]
    #[cfg(not(feature = "non-fips"))]
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
            algorithm,
            allowed,
        );

        assert!(res.is_err());
    }

    #[test]
    #[cfg(not(feature = "non-fips"))]
    fn test_create_ecc_keys_bad_mask() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let algorithm = CryptographicAlgorithm::ECDH;
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Decrypt),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
            ..Attributes::default()
        };
        let res = create_approved_ecc_key_pair(
            "pubkey01",
            "privkey01",
            RecommendedCurve::P256,
            &algorithm,
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());

        let algorithm = CryptographicAlgorithm::ECDSA;
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
            ..Attributes::default()
        };
        let res = create_approved_ecc_key_pair(
            "pubkey02",
            "privkey02",
            RecommendedCurve::P384,
            &algorithm,
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());

        let algorithm = CryptographicAlgorithm::ECDH;
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::KeyAgreement),
            ..Attributes::default()
        };
        let res = create_approved_ecc_key_pair(
            "pubkey03",
            "privkey03",
            RecommendedCurve::P521,
            &algorithm,
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());

        let algorithm = CryptographicAlgorithm::ECDH;
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::KeyAgreement),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
            ..Attributes::default()
        };
        let res = create_approved_ecc_key_pair(
            "pubkey04",
            "privkey04",
            RecommendedCurve::P521,
            &algorithm,
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());

        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Sign),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Verify | CryptographicUsageMask::KeyAgreement,
            ),
            ..Attributes::default()
        };
        let res = create_ed448_key_pair(
            "pubkey05",
            "privkey05",
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());
    }

    #[test]
    #[cfg(not(feature = "non-fips"))]
    fn test_create_ecc_keys_bad_algorithm() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let algorithm = CryptographicAlgorithm::Ed25519;
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Sign),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Verify),
            ..Attributes::default()
        };
        let res = create_approved_ecc_key_pair(
            "pubkey01",
            "privkey01",
            RecommendedCurve::P256,
            &algorithm,
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());
    }

    #[test]
    #[cfg(not(feature = "non-fips"))]
    fn test_create_ecc_keys_incorrect_mask_and_algorithm_ecdh() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        // ECDH algorithm should not have the Unrestricted mask;
        let algorithm = CryptographicAlgorithm::ECDH;
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Sign
                    | CryptographicUsageMask::KeyAgreement
                    | CryptographicUsageMask::DeriveKey
                    | CryptographicUsageMask::Unrestricted,
            ),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Verify
                    | CryptographicUsageMask::KeyAgreement
                    | CryptographicUsageMask::DeriveKey,
            ),
            ..Attributes::default()
        };
        let res = create_approved_ecc_key_pair(
            "pubkey01",
            "privkey01",
            RecommendedCurve::P256,
            &algorithm,
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());
    }

    #[test]
    #[cfg(not(feature = "non-fips"))]
    fn test_create_ecc_keys_incorrect_mask_and_algorithm_ecdsa() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        // ECDSA algorithm should not have KeyAgreement mask;
        let algorithm = CryptographicAlgorithm::ECDSA;
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Sign),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Verify | CryptographicUsageMask::KeyAgreement,
            ),
            ..Attributes::default()
        };

        let res = create_approved_ecc_key_pair(
            "pubkey01",
            "privkey01",
            RecommendedCurve::P256,
            &algorithm,
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());
    }

    #[test]
    #[cfg(not(feature = "non-fips"))]
    fn test_create_ecc_keys_incorrect_private_mask() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let algorithm = CryptographicAlgorithm::ECDSA;
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            ),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Verify),
            ..Attributes::default()
        };
        let res = create_approved_ecc_key_pair(
            "pubkey01",
            "privkey01",
            RecommendedCurve::P256,
            &algorithm,
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());
    }

    #[test]
    #[cfg(not(feature = "non-fips"))]
    fn test_create_ecc_keys_incorrect_public_mask() {
        // Load FIPS provider module from OpenSSL.
        Provider::load(None, "fips").unwrap();

        let algorithm = CryptographicAlgorithm::ECDSA;
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Sign),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Sign),
            ..Attributes::default()
        };
        let res = create_approved_ecc_key_pair(
            "pubkey01",
            "privkey01",
            RecommendedCurve::P256,
            &algorithm,
            Attributes::default(),
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());
    }
}
