use std::fmt;

use clap::ValueEnum;
use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        extra::VENDOR_ID_COSMIAN,
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::CreateKeyPair,
        kmip_types::{
            CryptographicAlgorithm, CryptographicDomainParameters, CryptographicParameters,
            KeyFormatType, RecommendedCurve, VendorAttribute, VendorAttributeValue,
        },
    },
    time_normalize,
};

use crate::{cover_crypt_utils::VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE, error::UtilsError};

/// KEM algorithm variants available for configurable KEM key pair generation.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    /// ML-KEM-512 (post-quantum lattice-based)
    #[clap(name = "ml-kem-512")]
    MlKem512,
    /// ML-KEM-768 (post-quantum lattice-based)
    #[clap(name = "ml-kem-768")]
    MlKem768,
    /// NIST P-256 (elliptic curve)
    #[clap(name = "p256")]
    P256,
    /// Curve25519
    #[clap(name = "curve25519")]
    Curve25519,
    /// ML-KEM-512 hybridized with P-256
    #[clap(name = "ml-kem-512-p256")]
    MlKem512P256,
    /// ML-KEM-768 hybridized with P-256
    #[clap(name = "ml-kem-768-p256")]
    MlKem768P256,
    /// ML-KEM-512 hybridized with Curve25519
    #[clap(name = "ml-kem-512-curve25519")]
    MlKem512Curve25519,
    /// ML-KEM-768 hybridized with Curve25519
    #[clap(name = "ml-kem-768-curve25519")]
    MlKem768Curve25519,
    /// `CoverCrypt` (attribute-based encryption)
    #[clap(name = "cover-crypt")]
    CoverCrypt,
}

impl fmt::Display for KemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MlKem512 => write!(f, "ML-KEM-512"),
            Self::MlKem768 => write!(f, "ML-KEM-768"),
            Self::P256 => write!(f, "P-256"),
            Self::Curve25519 => write!(f, "Curve25519"),
            Self::MlKem512P256 => write!(f, "ML-KEM-512/P-256"),
            Self::MlKem768P256 => write!(f, "ML-KEM-768/P-256"),
            Self::MlKem512Curve25519 => write!(f, "ML-KEM-512/Curve25519"),
            Self::MlKem768Curve25519 => write!(f, "ML-KEM-768/Curve25519"),
            Self::CoverCrypt => write!(f, "CoverCrypt"),
        }
    }
}

/// Build a configurable KEM `CreateKeyPair`.
pub fn build_create_configurable_kem_keypair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    access_structure: Option<&str>,
    tags: T,
    kem_algorithm: KemAlgorithm,
    sensitive: bool,
    wrapping_key_id: Option<&String>,
) -> Result<CreateKeyPair, UtilsError> {
    let (cryptographic_domain_parameters, cryptographic_parameters) = match kem_algorithm {
        KemAlgorithm::MlKem512 => Ok((
            None,
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_512),
                ..Default::default()
            }),
        )),
        KemAlgorithm::MlKem768 => Ok((
            None,
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_768),
                ..Default::default()
            }),
        )),
        KemAlgorithm::P256 => Ok((
            Some(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::P256),
            }),
            None,
        )),
        KemAlgorithm::Curve25519 => Ok((
            Some(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::CURVE25519),
            }),
            None,
        )),
        KemAlgorithm::MlKem512P256 => Ok((
            Some(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::P256),
            }),
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_512),
                ..Default::default()
            }),
        )),
        KemAlgorithm::MlKem768P256 => Ok((
            Some(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::P256),
            }),
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_768),
                ..Default::default()
            }),
        )),
        KemAlgorithm::MlKem512Curve25519 => Ok((
            Some(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::CURVE25519),
            }),
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_512),
                ..Default::default()
            }),
        )),
        KemAlgorithm::MlKem768Curve25519 => Ok((
            Some(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::CURVE25519),
            }),
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_768),
                ..Default::default()
            }),
        )),
        KemAlgorithm::CoverCrypt => {
            if access_structure.is_none() {
                Err(UtilsError::Default(
                    "access structure must be given to generate a CoverCrypt key-pair".to_owned(),
                ))
            } else {
                Ok((
                    None,
                    Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
                        ..Default::default()
                    }),
                ))
            }
        }
    }?;

    let vendor_attributes = access_structure.map(|access_structure| {
        vec![VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE.to_owned(),
            attribute_value: VendorAttributeValue::ByteString(access_structure.as_bytes().to_vec()),
        }]
    });

    let mut attributes = Attributes {
        object_type: Some(ObjectType::PrivateKey),
        cryptographic_algorithm: Some(CryptographicAlgorithm::ConfigurableKEM),
        key_format_type: Some(KeyFormatType::ConfigurableKEMSecretKey),
        vendor_attributes,
        cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
        sensitive: sensitive.then_some(true),
        activation_date: Some(time_normalize().map_err(|e| UtilsError::Default(e.to_string()))?),
        cryptographic_domain_parameters,
        cryptographic_parameters,
        ..Attributes::default()
    };
    attributes.set_tags(tags)?;

    if let Some(wrap_key_id) = wrapping_key_id {
        attributes.set_wrapping_key_id(wrap_key_id);
    }

    let request = CreateKeyPair {
        common_attributes: Some(attributes),
        ..CreateKeyPair::default()
    };

    Ok(request)
}
