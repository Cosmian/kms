#[cfg(feature = "fips")]
use super::{FIPS_PRIVATE_RSA_MASK, FIPS_PUBLIC_RSA_MASK};
#[cfg(not(feature = "fips"))]
use crate::kmip::kmip_types::CryptographicUsageMask;
use crate::{
    error::KmipError,
    kmip::{
        kmip_objects::ObjectType,
        kmip_operations::{CreateKeyPair, Get},
        kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType, UniqueIdentifier},
    },
};

/// Build a `CreateKeyPairRequest` for a RSA key pair.
pub fn create_rsa_key_pair_request<T: IntoIterator<Item = impl AsRef<str>>>(
    private_key_id: Option<UniqueIdentifier>,
    tags: T,
    cryptographic_length: usize,
    sensitive: bool,
) -> Result<CreateKeyPair, KmipError> {
    #[cfg(feature = "fips")]
    let private_key_mask = FIPS_PRIVATE_RSA_MASK;
    #[cfg(feature = "fips")]
    let public_key_mask = FIPS_PUBLIC_RSA_MASK;

    #[cfg(not(feature = "fips"))]
    let private_key_mask = CryptographicUsageMask::Unrestricted;
    #[cfg(not(feature = "fips"))]
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
        sensitive,
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

#[must_use]
pub fn get_private_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        key_format_type: Some(KeyFormatType::TransparentRSAPrivateKey),
        ..Get::default()
    }
}

#[must_use]
pub fn get_public_key_request(uid: &str) -> Get {
    Get {
        unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
        key_format_type: Some(KeyFormatType::TransparentRSAPublicKey),
        ..Get::default()
    }
}
