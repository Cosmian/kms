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

/// Build a `CreateKeyPairRequest` for an  elliptic curve
pub fn create_ec_key_pair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    tags: T,
    recommended_curve: RecommendedCurve,
) -> Result<CreateKeyPair, KmipError> {
    let mut attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
        cryptographic_domain_parameters: Some(CryptographicDomainParameters {
            recommended_curve: Some(recommended_curve),
            ..CryptographicDomainParameters::default()
        }),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::KeyAgreement,
        ),
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
