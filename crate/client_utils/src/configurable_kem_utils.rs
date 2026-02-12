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

/// Build a `CreateKeyPair` request for an `CoverCrypt` Master Key
pub fn build_create_configurable_kem_keypair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    access_structure: Option<&str>,
    tags: T,
    kem_tag: usize,
    sensitive: bool,
    wrapping_key_id: Option<&String>,
) -> Result<CreateKeyPair, UtilsError> {
    let (cryptographic_domain_parameters, cryptographic_parameters) = match kem_tag {
        0 => Ok((
            None,
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_512),
                ..Default::default()
            }),
        )),
        1 => Ok((
            None,
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_768),
                ..Default::default()
            }),
        )),
        10 => Ok((
            Some(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::P256),
            }),
            None,
        )),
        11 => Ok((
            Some(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::CURVE25519),
            }),
            None,
        )),
        100 => Ok((
            Some(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::P256),
            }),
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_512),
                ..Default::default()
            }),
        )),
        101 => Ok((
            Some(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::P256),
            }),
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_768),
                ..Default::default()
            }),
        )),
        110 => Ok((
            Some(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::CURVE25519),
            }),
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_512),
                ..Default::default()
            }),
        )),
        111 => Ok((
            Some(CryptographicDomainParameters {
                qlength: Some(256),
                recommended_curve: Some(RecommendedCurve::CURVE25519),
            }),
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::MLKEM_768),
                ..Default::default()
            }),
        )),
        1000 => {
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
        n => Err(UtilsError::Default(format!(
            "{n} is not a valid Configurable-KEM tag"
        ))),
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
        key_format_type: Some(KeyFormatType::ConfigurableKEM),
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
