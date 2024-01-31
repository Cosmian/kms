use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_operations::{CreateKeyPair, Get},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType, UniqueIdentifier,
    },
};

use crate::error::KmsCryptoError;

/// Build a `CreateKeyPairRequest` for a RSA key pair
pub fn create_rsa_key_pair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    tags: T,
    cryptographic_length: usize,
) -> Result<CreateKeyPair, KmsCryptoError> {
    let mut attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        cryptographic_length: Some(cryptographic_length as i32),
        cryptographic_domain_parameters: None,
        cryptographic_parameters: None,
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::KeyAgreement,
        ),
        key_format_type: Some(KeyFormatType::TransparentRSAPrivateKey),
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
        key_format_type: Some(KeyFormatType::TransparentRSAPrivateKey),
        ..Get::default()
    }
}

#[must_use]
pub fn get_public_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_string())),
        key_format_type: Some(KeyFormatType::TransparentRSAPublicKey),
        ..Get::default()
    }
}
