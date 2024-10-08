#[cfg(feature = "fips")]
use super::{
    FIPS_PRIVATE_ECC_MASK_SIGN, FIPS_PRIVATE_ECC_MASK_SIGN_ECDH, FIPS_PUBLIC_ECC_MASK_SIGN,
    FIPS_PUBLIC_ECC_MASK_SIGN_ECDH,
};
#[cfg(feature = "fips")]
use crate::kmip_bail;
use crate::{
    error::KmipError,
    kmip::{
        kmip_objects::ObjectType,
        kmip_operations::{CreateKeyPair, Get},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicDomainParameters,
            CryptographicUsageMask, KeyFormatType, RecommendedCurve, UniqueIdentifier,
        },
    },
};

/// Builds correct usage mask depending on the curve. In FIPS mode, curves are
/// restricted to certain usage.
///
/// For more information see documents
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
/// - NIST.FIPS.186-5
#[cfg(feature = "fips")]
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
            | RecommendedCurve::P521,
        ) => FIPS_PRIVATE_ECC_MASK_SIGN_ECDH,
        (
            false,
            RecommendedCurve::P224
            | RecommendedCurve::P256
            | RecommendedCurve::P384
            | RecommendedCurve::P521,
        ) => FIPS_PUBLIC_ECC_MASK_SIGN_ECDH,
        (true, RecommendedCurve::CURVEED25519 | RecommendedCurve::CURVEED448) => {
            FIPS_PRIVATE_ECC_MASK_SIGN
        }
        (false, RecommendedCurve::CURVEED25519 | RecommendedCurve::CURVEED448) => {
            FIPS_PUBLIC_ECC_MASK_SIGN
        }
        (_, other) => kmip_bail!(
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
#[cfg(not(feature = "fips"))]
#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
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
        _ => CryptographicAlgorithm::EC,
    }
}

/// Build a `CreateKeyPairRequest` for an  elliptic curve
pub fn create_ec_key_pair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    private_key_id: Option<UniqueIdentifier>,
    tags: T,
    recommended_curve: RecommendedCurve,
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

#[must_use]
pub fn get_private_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
        ..Get::default()
    }
}

#[must_use]
pub fn get_public_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        key_format_type: Some(KeyFormatType::TransparentECPublicKey),
        ..Get::default()
    }
}
