use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{CreateKeyPair, Get},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicDomainParameters, CryptographicUsageMask,
        KeyFormatType, RecommendedCurve, UniqueIdentifier,
    },
};
use cosmian_kms_utils::tagging::set_tags;

use crate::{elliptic_curves::operation::Q_LENGTH_BITS, error::KmsCryptoError};

/// Build a `CreateKeyPairRequest` for a curve 25519 key pair
pub fn create_curve_25519_key_pair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    tags: T,
    recommended_curve: RecommendedCurve,
) -> Result<CreateKeyPair, KmsCryptoError> {
    let mut attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
        cryptographic_length: Some(Q_LENGTH_BITS),
        cryptographic_domain_parameters: Some(CryptographicDomainParameters {
            q_length: Some(Q_LENGTH_BITS),
            recommended_curve: Some(recommended_curve),
        }),
        cryptographic_parameters: None,
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
    set_tags(&mut attributes, tags)?;
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
