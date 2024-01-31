use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicParameters, CryptographicUsageMask,
        KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
    },
};
use cosmian_kms_utils::KeyPair;
use num_bigint_dig::BigUint;
use openssl::{pkey::Private, rsa::Rsa};
use tracing::trace;
use zeroize::Zeroizing;

use crate::error::KmsCryptoError;
#[cfg(feature = "fips")]
use crate::{kms_crypto_bail, wrap::rsa_oaep_aes_kwp::FIPS_MIN_RSA_MODULUS_LENGTH};

/// convert to RSA KMIP Public Key
pub fn to_rsa_public_key(
    private_key: &Rsa<Private>,
    pkey_bits_number: u32,
    private_key_uid: &str,
) -> Object {
    let cryptographic_length_in_bits = private_key.n().num_bits();

    trace!(
        "to_rsa_public_key: bytes len: {}, bits: {}",
        cryptographic_length_in_bits,
        pkey_bits_number
    );

    let output = Object::PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            key_format_type: KeyFormatType::TransparentRSAPublicKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentRSAPublicKey {
                    modulus: BigUint::from_bytes_be(&private_key.n().to_vec()),
                    public_exponent: BigUint::from_bytes_be(&private_key.e().to_vec()),
                },
                attributes: Some(Attributes {
                    object_type: Some(ObjectType::PublicKey),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    cryptographic_length: Some(cryptographic_length_in_bits),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
                    vendor_attributes: None,
                    key_format_type: Some(KeyFormatType::TransparentRSAPublicKey),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                        ..CryptographicParameters::default()
                    }),
                    cryptographic_domain_parameters: None,
                    link: Some(vec![Link {
                        link_type: LinkType::PrivateKeyLink,
                        linked_object_identifier: LinkedObjectIdentifier::TextString(
                            private_key_uid.to_string(),
                        ),
                    }]),
                    ..Attributes::default()
                }),
            },
            cryptographic_length: Some(cryptographic_length_in_bits),
            key_wrapping_data: None,
        },
    };
    trace!("to_rsa_public_key: output object: {:?}", output);
    output
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
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            key_format_type: KeyFormatType::TransparentRSAPrivateKey,
            key_compression_type: None,
            key_value: KeyValue {
                key_material: KeyMaterial::TransparentRSAPrivateKey {
                    modulus: BigUint::from_bytes_be(&private_key.n().to_vec()),
                    private_exponent: Some(BigUint::from_bytes_be(&Zeroizing::from(
                        private_key.d().to_vec(),
                    ))),
                    public_exponent: Some(BigUint::from_bytes_be(&private_key.e().to_vec())),
                    p: private_key
                        .p()
                        .map(|p| BigUint::from_bytes_be(&Zeroizing::from(p.to_vec()))),
                    q: private_key
                        .q()
                        .map(|q| BigUint::from_bytes_be(&Zeroizing::from(q.to_vec()))),
                    prime_exponent_p: private_key
                        .dmp1()
                        .map(|dmp1| BigUint::from_bytes_be(&Zeroizing::from(dmp1.to_vec()))),
                    prime_exponent_q: private_key
                        .dmq1()
                        .map(|dmq1| BigUint::from_bytes_be(&Zeroizing::from(dmq1.to_vec()))),
                    crt_coefficient: private_key
                        .iqmp()
                        .map(|iqmp| BigUint::from_bytes_be(&Zeroizing::from(iqmp.to_vec()))),
                },
                attributes: Some(Attributes {
                    object_type: Some(ObjectType::PrivateKey),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    cryptographic_length: Some(cryptographic_length_in_bits),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Decrypt),
                    vendor_attributes: None,
                    key_format_type: Some(KeyFormatType::TransparentRSAPrivateKey),
                    cryptographic_parameters: Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                        ..CryptographicParameters::default()
                    }),
                    cryptographic_domain_parameters: None,
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

pub fn create_rsa_key_pair(
    key_size_in_bits: u32,
    public_key_uid: &str,
    private_key_uid: &str,
) -> Result<KeyPair, KmsCryptoError> {
    #[cfg(feature = "fips")]
    if key_size_in_bits < FIPS_MIN_RSA_MODULUS_LENGTH * 8 {
        kmip_utils_bail!(
            "FIPS 140 mode requires a minimum key length of {} bits",
            FIPS_MIN_RSA_MODULUS_LENGTH * 8
        )
    }
    let rsa_private = Rsa::generate(key_size_in_bits)?;
    let private_key = to_rsa_private_key(&rsa_private, key_size_in_bits, public_key_uid);
    let public_key = to_rsa_public_key(&rsa_private, key_size_in_bits, private_key_uid);
    Ok(KeyPair::new(private_key, public_key))
}
