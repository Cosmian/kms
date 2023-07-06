use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{CreateKeyPair, Get},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicDomainParameters, CryptographicUsageMask,
        KeyFormatType, RecommendedCurve,
    },
};

use crate::{
    crypto::{curve_25519::operation::Q_LENGTH_BITS, error::CryptoError},
    tagging::set_tags,
};

/// Build a `CreateKeyPairRequest` for a curve 25519 key pair
pub fn create_key_pair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    tags: T,
) -> Result<CreateKeyPair, CryptoError> {
    let mut attributes = Attributes {
        activation_date: None,
        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
        cryptographic_length: Some(Q_LENGTH_BITS),
        cryptographic_domain_parameters: Some(CryptographicDomainParameters {
            q_length: Some(Q_LENGTH_BITS),
            recommended_curve: Some(RecommendedCurve::CURVE25519),
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
        link: None,
        object_type: ObjectType::PrivateKey,
        vendor_attributes: None,
    };
    // add the tags
    set_tags(&mut attributes, tags)?;
    Ok(CreateKeyPair {
        common_attributes: Some(attributes),
        private_key_attributes: None,
        public_key_attributes: None,
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
    })
}

#[must_use]
pub fn get_private_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(uid.to_string()),
        key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
        key_wrap_type: None,
        key_compression_type: None,
        key_wrapping_data: None,
    }
}

#[must_use]
pub fn get_public_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(uid.to_string()),
        key_format_type: Some(KeyFormatType::TransparentECPublicKey),
        key_wrap_type: None,
        key_compression_type: None,
        key_wrapping_data: None,
    }
}
