#[cfg(not(feature = "non-fips"))]
use crate::kmip_2_1::extra::fips::{FIPS_PRIVATE_RSA_MASK, FIPS_PUBLIC_RSA_MASK};
use crate::{
    KmipError,
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::CreateKeyPair,
        kmip_types::{
            CryptographicAlgorithm, CryptographicDomainParameters, KeyFormatType, RecommendedCurve,
            UniqueIdentifier,
        },
    },
};
#[cfg(not(feature = "non-fips"))]
use crate::{
    kmip_2_1::extra::fips::{
        FIPS_PRIVATE_ECC_MASK_SIGN, FIPS_PRIVATE_ECC_MASK_SIGN_ECDH, FIPS_PUBLIC_ECC_MASK_SIGN,
        FIPS_PUBLIC_ECC_MASK_SIGN_ECDH,
    },
    kmip_2_1_bail,
};

/// Build a `CreateKeyPairRequest` for a RSA key pair.
pub fn create_rsa_key_pair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    private_key_id: Option<UniqueIdentifier>,
    tags: T,
    cryptographic_length: usize,
    sensitive: bool,
    wrapping_key_id: Option<&String>,
) -> Result<CreateKeyPair, KmipError> {
    #[cfg(not(feature = "non-fips"))]
    let private_key_mask = FIPS_PRIVATE_RSA_MASK;
    #[cfg(not(feature = "non-fips"))]
    let public_key_mask = FIPS_PUBLIC_RSA_MASK;

    #[cfg(feature = "non-fips")]
    let private_key_mask = CryptographicUsageMask::Unrestricted;
    #[cfg(feature = "non-fips")]
    let public_key_mask = CryptographicUsageMask::Unrestricted;

    let algorithm = CryptographicAlgorithm::RSA;
    let cryptographic_length = Some(i32::try_from(cryptographic_length)?);
    let mut common_attributes = Attributes {
        cryptographic_algorithm: Some(algorithm),
        cryptographic_length,
        cryptographic_domain_parameters: None,
        cryptographic_parameters: None,
        cryptographic_usage_mask: Some(private_key_mask | public_key_mask),
        key_format_type: Some(KeyFormatType::TransparentRSAPrivateKey),
        object_type: Some(ObjectType::PrivateKey),
        ..Attributes::default()
    };
    if let Some(wrap_key_id) = wrapping_key_id {
        common_attributes.set_wrapping_key_id(wrap_key_id);
    }

    // Add the tags.
    common_attributes.set_tags(tags)?;

    // Differentiating private key and public key attributes to differentiate
    // public key and private key usage masks on key creation.
    let private_key_attributes = Attributes {
        cryptographic_algorithm: Some(algorithm),
        cryptographic_length,
        cryptographic_domain_parameters: None,
        cryptographic_parameters: None,
        cryptographic_usage_mask: Some(private_key_mask),
        key_format_type: Some(KeyFormatType::TransparentRSAPrivateKey),
        object_type: Some(ObjectType::PrivateKey),
        unique_identifier: private_key_id,
        sensitive: if sensitive { Some(true) } else { None },
        ..Attributes::default()
    };

    let public_key_attributes = Attributes {
        cryptographic_algorithm: Some(algorithm),
        cryptographic_length,
        cryptographic_domain_parameters: None,
        cryptographic_parameters: None,
        cryptographic_usage_mask: Some(public_key_mask),
        key_format_type: Some(KeyFormatType::TransparentRSAPrivateKey),
        object_type: Some(ObjectType::PrivateKey),
        ..Attributes::default()
    };

    Ok(CreateKeyPair {
        common_attributes: Some(common_attributes),
        private_key_attributes: Some(private_key_attributes),
        public_key_attributes: Some(public_key_attributes),
        ..CreateKeyPair::default()
    })
}

/// Builds the correct usage mask depending on the curve. In FIPS mode, curves are
/// restricted to certain usage.
///
/// For more information see documents
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
/// - NIST.FIPS.186-5
#[cfg(not(feature = "non-fips"))]
fn build_mask_from_curve(
    curve: RecommendedCurve,
    is_private_mask: bool,
) -> Result<CryptographicUsageMask, KmipError> {
    let mask = match (is_private_mask, curve) {
        (
            true,
            RecommendedCurve::P224
            | RecommendedCurve::P256
            | RecommendedCurve::P384
            | RecommendedCurve::P521
            | RecommendedCurve::SECP256K1
            | RecommendedCurve::SECP224K1,
        ) => FIPS_PRIVATE_ECC_MASK_SIGN_ECDH,
        (
            false,
            RecommendedCurve::P224
            | RecommendedCurve::P256
            | RecommendedCurve::P384
            | RecommendedCurve::P521
            | RecommendedCurve::SECP256K1
            | RecommendedCurve::SECP224K1,
        ) => FIPS_PUBLIC_ECC_MASK_SIGN_ECDH,
        (true, RecommendedCurve::CURVEED25519 | RecommendedCurve::CURVEED448) => {
            FIPS_PRIVATE_ECC_MASK_SIGN
        }
        (false, RecommendedCurve::CURVEED25519 | RecommendedCurve::CURVEED448) => {
            FIPS_PUBLIC_ECC_MASK_SIGN
        }
        (_, other) => kmip_2_1_bail!(
            "Building mask from unsupported curve in FIPS mode: curve {}",
            other
        ),
    };

    Ok(mask)
}

/// Builds correct usage mask depending on the curve. In non-FIPS mode, curves
/// are not restricted to any usage.
///
/// For more information see documents
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
/// - NIST.FIPS.186-5
#[cfg(feature = "non-fips")]
#[allow(clippy::unnecessary_wraps)]
const fn build_mask_from_curve(
    _curve: RecommendedCurve,
    _is_private_mask: bool,
) -> Result<CryptographicUsageMask, KmipError> {
    Ok(CryptographicUsageMask::Unrestricted)
}

/// Builds correct algorithm depending on the curve. In FIPS mode, curves are
/// restricted to certain algorithms.
///
/// For more information see documents
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
/// - NIST.FIPS.186-5
///
/// TODO - Discriminate between EC, ECDH and ECDSA.
const fn build_algorithm_from_curve(curve: RecommendedCurve) -> CryptographicAlgorithm {
    match curve {
        RecommendedCurve::CURVEED25519 => CryptographicAlgorithm::Ed25519,
        RecommendedCurve::CURVEED448 => CryptographicAlgorithm::Ed448,
        _ => CryptographicAlgorithm::ECDH,
    }
}

/// Build a `CreateKeyPairRequest` for an elliptic curve
pub fn create_ec_key_pair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    private_key_id: Option<UniqueIdentifier>,
    tags: T,
    recommended_curve: RecommendedCurve,
    sensitive: bool,
    wrapping_key_id: Option<&String>,
) -> Result<CreateKeyPair, KmipError> {
    let private_key_mask = build_mask_from_curve(recommended_curve, true)?;
    let public_key_mask = build_mask_from_curve(recommended_curve, false)?;
    let algorithm = build_algorithm_from_curve(recommended_curve);

    let mut common_attributes = Attributes {
        cryptographic_algorithm: Some(algorithm),
        cryptographic_domain_parameters: Some(CryptographicDomainParameters {
            recommended_curve: Some(recommended_curve),
            ..CryptographicDomainParameters::default()
        }),
        cryptographic_usage_mask: Some(private_key_mask | public_key_mask),
        key_format_type: Some(KeyFormatType::ECPrivateKey),
        object_type: Some(ObjectType::PrivateKey),
        ..Attributes::default()
    };
    if let Some(wrap_key_id) = wrapping_key_id {
        common_attributes.set_wrapping_key_id(wrap_key_id);
    }

    // Add the tags.
    common_attributes.set_tags(tags)?;

    let private_key_attributes = Attributes {
        cryptographic_algorithm: Some(algorithm),
        cryptographic_domain_parameters: Some(CryptographicDomainParameters {
            recommended_curve: Some(recommended_curve),
            ..CryptographicDomainParameters::default()
        }),
        cryptographic_usage_mask: Some(private_key_mask),
        key_format_type: Some(KeyFormatType::ECPrivateKey),
        object_type: Some(ObjectType::PrivateKey),
        unique_identifier: private_key_id,
        sensitive: if sensitive { Some(true) } else { None },
        ..Attributes::default()
    };

    // Differentiating private key and public key attributes to differentiate
    // public key and private key usage masks on key creation.
    let public_key_attributes = Attributes {
        cryptographic_algorithm: Some(algorithm),
        cryptographic_domain_parameters: Some(CryptographicDomainParameters {
            recommended_curve: Some(recommended_curve),
            ..CryptographicDomainParameters::default()
        }),
        cryptographic_usage_mask: Some(public_key_mask),
        key_format_type: Some(KeyFormatType::ECPrivateKey),
        object_type: Some(ObjectType::PrivateKey),
        ..Attributes::default()
    };

    Ok(CreateKeyPair {
        common_attributes: Some(common_attributes),
        private_key_attributes: Some(private_key_attributes),
        public_key_attributes: Some(public_key_attributes),
        ..CreateKeyPair::default()
    })
}
