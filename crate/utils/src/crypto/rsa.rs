use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicDomainParameters, CryptographicParameters,
        CryptographicUsageMask, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
    },
};
use num_bigint_dig::BigUint;
use openssl::{pkey::Private, rsa::Rsa};
use tracing::trace;

/// convert to RSA KMIP Public Key
pub fn to_rsa_public_key(
    private_key: &Rsa<Private>,
    pkey_bits_number: u32,
    public_key_uid: &str,
) -> Object {
    let cryptographic_length_in_bits = private_key.e().num_bits();

    trace!(
        "to_rsa_public_key: bytes len: {}, bits: {}",
        cryptographic_length_in_bits,
        pkey_bits_number
    );

    Object::PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::DH),
            key_format_type: KeyFormatType::TransparentRSAPublicKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentRSAPublicKey {
                    modulus: BigUint::from_bytes_be(&private_key.n().to_vec()),
                    public_exponent: BigUint::from_bytes_be(&private_key.e().to_vec()),
                },
                attributes: Some(Attributes {
                    object_type: Some(ObjectType::PublicKey),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::DH),
                    cryptographic_length: Some(cryptographic_length_in_bits),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
                    vendor_attributes: None,
                    key_format_type: Some(KeyFormatType::TransparentRSAPrivateKey),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::DH),
                        ..CryptographicParameters::default()
                    }),
                    cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                        q_length: Some(pkey_bits_number as i32),
                        recommended_curve: None,
                    }),
                    link: Some(vec![Link {
                        link_type: LinkType::PublicKeyLink,
                        linked_object_identifier: LinkedObjectIdentifier::TextString(
                            public_key_uid.to_string(),
                        ),
                    }]),
                    ..Attributes::default()
                }),
            },
            cryptographic_length: Some(cryptographic_length_in_bits),
            key_wrapping_data: None,
        },
    }
}

/// convert to RSA KMIP Private Key
pub fn to_rsa_private_key(
    private_key: &Rsa<Private>,
    pkey_bits_number: u32,
    public_key_uid: &str,
) -> Object {
    let cryptographic_length_in_bits = private_key.d().num_bits();

    trace!(
        "to_rsa_private_key: bytes len: {}, bits: {}",
        cryptographic_length_in_bits,
        pkey_bits_number
    );

    Object::PrivateKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::DH),
            key_format_type: KeyFormatType::TransparentRSAPrivateKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentRSAPrivateKey {
                    modulus: BigUint::from_bytes_be(&private_key.n().to_vec()),
                    private_exponent: Some(BigUint::from_bytes_be(&private_key.d().to_vec())),
                    public_exponent: Some(BigUint::from_bytes_be(&private_key.e().to_vec())),
                    p: private_key.p().map(|p| BigUint::from_bytes_be(&p.to_vec())),
                    q: private_key.q().map(|q| BigUint::from_bytes_be(&q.to_vec())),
                    prime_exponent_p: private_key
                        .dmp1()
                        .map(|dmp1| BigUint::from_bytes_be(&dmp1.to_vec())),
                    prime_exponent_q: private_key
                        .dmq1()
                        .map(|dmq1| BigUint::from_bytes_be(&dmq1.to_vec())),
                    crt_coefficient: private_key
                        .iqmp()
                        .map(|iqmp| BigUint::from_bytes_be(&iqmp.to_vec())),
                },
                attributes: Some(Attributes {
                    object_type: Some(ObjectType::PrivateKey),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::DH),
                    cryptographic_length: Some(cryptographic_length_in_bits),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Decrypt),
                    vendor_attributes: None,
                    key_format_type: Some(KeyFormatType::TransparentRSAPrivateKey),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::DH),
                        ..CryptographicParameters::default()
                    }),
                    cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                        q_length: Some(pkey_bits_number as i32),
                        recommended_curve: None,
                    }),
                    link: Some(vec![Link {
                        link_type: LinkType::PublicKeyLink,
                        linked_object_identifier: LinkedObjectIdentifier::TextString(
                            public_key_uid.to_string(),
                        ),
                    }]),
                    ..Attributes::default()
                }),
            },
            cryptographic_length: Some(cryptographic_length_in_bits),
            key_wrapping_data: None,
        },
    }
}
