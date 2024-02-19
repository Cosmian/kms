#[cfg(feature = "fips")]
use super::{FIPS_ECC_USAGE_MASK_SIGN, FIPS_ECC_USAGE_MASK_SIGN_AND_DH};
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

// `unused_variables` is on because when FIPS features is disabled, `curve` is
// unused.
#[allow(unused_variables)]
/// Builds correct usage mask depending on the curve. In FIPS mode, curves are
/// restricted to certain usage.
///
/// For more information see documents
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
/// - NIST.FIPS.186-5
fn build_mask_from_curve(curve: RecommendedCurve) -> Result<CryptographicUsageMask, KmipError> {
    #[cfg(feature = "fips")]
    let mask = match curve {
        RecommendedCurve::P192
        | RecommendedCurve::P224
        | RecommendedCurve::P256
        | RecommendedCurve::P384
        | RecommendedCurve::P521 => FIPS_ECC_USAGE_MASK_SIGN_AND_DH,
        RecommendedCurve::CURVEED25519 | RecommendedCurve::CURVEED448 => FIPS_ECC_USAGE_MASK_SIGN,
        other => kmip_bail!(
            "Building mask from unsupported curve in FIPS mode: curve {}",
            other
        ),
    };
    #[cfg(not(feature = "fips"))]
    let mask = CryptographicUsageMask::Unrestricted;

    Ok(mask)
}

/// Builds correct algorithm depending on the curve. In FIPS mode, curves are
/// restricted to certain algorithms.
///
/// For more information see documents
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
/// - NIST.FIPS.186-5
///
/// TODO - Discrimine between EC, ECDH and ECDSA.
fn build_algorithm_from_curve(
    curve: RecommendedCurve,
) -> Result<CryptographicAlgorithm, KmipError> {
    let algorithm = match curve {
        RecommendedCurve::P192
        | RecommendedCurve::P224
        | RecommendedCurve::P256
        | RecommendedCurve::P384
        | RecommendedCurve::P521
        | RecommendedCurve::CURVE25519
        | RecommendedCurve::CURVE448 => CryptographicAlgorithm::EC,
        RecommendedCurve::CURVEED25519 => CryptographicAlgorithm::Ed25519,
        RecommendedCurve::CURVEED448 => CryptographicAlgorithm::Ed448,
        _ => CryptographicAlgorithm::EC,
    };

    Ok(algorithm)
}

/// Build a `CreateKeyPairRequest` for an  elliptic curve
pub fn create_ec_key_pair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    tags: T,
    recommended_curve: RecommendedCurve,
) -> Result<CreateKeyPair, KmipError> {
    let mask = build_mask_from_curve(recommended_curve)?;
    let algorithm = build_algorithm_from_curve(recommended_curve)?;

    let mut attributes = Attributes {
        cryptographic_algorithm: Some(algorithm),
        cryptographic_domain_parameters: Some(CryptographicDomainParameters {
            recommended_curve: Some(recommended_curve),
            ..CryptographicDomainParameters::default()
        }),
        cryptographic_usage_mask: Some(mask),
        key_format_type: Some(KeyFormatType::ECPrivateKey),
        object_type: Some(ObjectType::PrivateKey),
        ..Attributes::default()
    };
    // add the tags
    attributes.set_tags(tags)?;
    Ok(CreateKeyPair {
        common_attributes: Some(attributes),
        ..CreateKeyPair::default()
    })
}

#[must_use]
pub fn get_private_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_string())),
        key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
        ..Get::default()
    }
}

#[must_use]
pub fn get_public_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_string())),
        key_format_type: Some(KeyFormatType::TransparentECPublicKey),
        ..Get::default()
    }
}
