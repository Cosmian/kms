use num_bigint_dig::BigUint;
use openssl::{pkey::Private, rsa::Rsa};
use tracing::trace;
use zeroize::Zeroizing;

#[cfg(feature = "fips")]
use super::{FIPS_MIN_RSA_MODULUS_LENGTH, FIPS_PRIVATE_RSA_MASK, FIPS_PUBLIC_RSA_MASK};
use crate::{
    crypto::{secret::SafeBigUint, KeyPair},
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicParameters, CryptographicUsageMask,
            KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
        },
    },
    kmip_bail,
};

#[cfg(feature = "fips")]
/// Check that bits set in `mask` are only bits set in `flags`. If any bit set
/// in `mask` is not set in `flags`, raise an error.
///
/// If `mask` is `None`, raise an error.
fn check_rsa_mask_against_flags(
    mask: Option<CryptographicUsageMask>,
    flags: CryptographicUsageMask,
) -> Result<(), KmipError> {
    if (flags & CryptographicUsageMask::Unrestricted).bits() != 0 {
        kmip_bail!("Unrestricted CryptographicUsageMask for RSA is too permissive for FIPS mode.")
    }

    let Some(mask) = mask else {
        // Mask is `None` but FIPS mode is restrictive so it's considered too
        // permissive.
        kmip_bail!(
            "Fordidden CryptographicUsageMask value, got None but expected among {} in FIPS mode.",
            flags.bits()
        )
    };

    if (mask & !flags).bits() != 0 {
        kmip_bail!(
            "Fordidden CryptographicUsageMask flag set, expected among {} in FIPS mode.",
            flags.bits()
        )
    }

    Ok(())
}

#[cfg(feature = "fips")]
/// Check that `mask` is compliant with FIPS restrictions for private and public
/// key components. For example an RSA pubic key must not be used for decryption
/// in FIPS mode.
fn check_rsa_mask_compliance(
    private_key_mask: Option<CryptographicUsageMask>,
    public_key_mask: Option<CryptographicUsageMask>,
) -> Result<(), KmipError> {
    check_rsa_mask_against_flags(private_key_mask, FIPS_PRIVATE_RSA_MASK)?;
    check_rsa_mask_against_flags(public_key_mask, FIPS_PUBLIC_RSA_MASK)
}

/// Convert to RSA KMIP Public Key.
pub fn to_rsa_public_key(
    private_key: &Rsa<Private>,
    pkey_bits_number: u32,
    private_key_uid: &str,
    public_key_mask: Option<CryptographicUsageMask>,
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
                    cryptographic_usage_mask: public_key_mask,
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

/// Convert to RSA KMIP Private Key.
pub fn to_rsa_private_key(
    private_key: &Rsa<Private>,
    pkey_bits_number: u32,
    public_key_uid: &str,
    private_key_mask: Option<CryptographicUsageMask>,
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
                    private_exponent: Some(SafeBigUint::from_bytes_be(&Zeroizing::from(
                        private_key.d().to_vec(),
                    ))),
                    public_exponent: Some(BigUint::from_bytes_be(&private_key.e().to_vec())),
                    p: private_key
                        .p()
                        .map(|p| SafeBigUint::from_bytes_be(&Zeroizing::from(p.to_vec()))),
                    q: private_key
                        .q()
                        .map(|q| SafeBigUint::from_bytes_be(&Zeroizing::from(q.to_vec()))),
                    prime_exponent_p: private_key
                        .dmp1()
                        .map(|dmp1| SafeBigUint::from_bytes_be(&Zeroizing::from(dmp1.to_vec()))),
                    prime_exponent_q: private_key
                        .dmq1()
                        .map(|dmq1| SafeBigUint::from_bytes_be(&Zeroizing::from(dmq1.to_vec()))),
                    crt_coefficient: private_key
                        .iqmp()
                        .map(|iqmp| SafeBigUint::from_bytes_be(&Zeroizing::from(iqmp.to_vec()))),
                },
                attributes: Some(Attributes {
                    object_type: Some(ObjectType::PrivateKey),
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    cryptographic_length: Some(cryptographic_length_in_bits),
                    cryptographic_usage_mask: private_key_mask,
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
    algorithm: Option<CryptographicAlgorithm>,
    private_key_mask: Option<CryptographicUsageMask>,
    public_key_mask: Option<CryptographicUsageMask>,
) -> Result<KeyPair, KmipError> {
    #[cfg(feature = "fips")]
    if key_size_in_bits < FIPS_MIN_RSA_MODULUS_LENGTH * 8 {
        kmip_bail!(
            "FIPS 140 mode requires a minimum key length of {} bits",
            FIPS_MIN_RSA_MODULUS_LENGTH * 8
        )
    }

    if algorithm != Some(CryptographicAlgorithm::RSA) {
        kmip_bail!("Creation of RSA keys require RSA CryptographicAlgorithm value.")
    }

    #[cfg(feature = "fips")]
    check_rsa_mask_compliance(private_key_mask, public_key_mask)?;

    let rsa_private = Rsa::generate(key_size_in_bits)?;
    let private_key = to_rsa_private_key(
        &rsa_private,
        key_size_in_bits,
        public_key_uid,
        private_key_mask,
    );
    let public_key = to_rsa_public_key(
        &rsa_private,
        key_size_in_bits,
        private_key_uid,
        public_key_mask,
    );

    Ok(KeyPair::new(private_key, public_key))
}

#[test]
#[cfg(feature = "fips")]
fn test_create_rsa_incorrect_mask() {
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let private_key_mask = Some(CryptographicUsageMask::Sign);
    let public_key_mask = Some(CryptographicUsageMask::Sign | CryptographicUsageMask::Verify);

    let res = create_rsa_key_pair(
        2048,
        "pubkey01",
        "privkey01",
        Some(CryptographicAlgorithm::RSA),
        private_key_mask,
        public_key_mask,
    );

    assert!(res.is_err());

    let private_key_mask = Some(CryptographicUsageMask::Decrypt | CryptographicUsageMask::CRLSign);
    let public_key_mask = Some(CryptographicUsageMask::Encrypt | CryptographicUsageMask::Verify);

    let res = create_rsa_key_pair(
        2048,
        "pubkey02",
        "privkey02",
        Some(CryptographicAlgorithm::RSA),
        private_key_mask,
        public_key_mask,
    );

    assert!(res.is_err())
}

#[test]
#[cfg(feature = "fips")]
fn test_create_rsa_incorrect_mask_unrestricted() {
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let private_key_mask = Some(CryptographicUsageMask::Unrestricted);
    let public_key_mask = Some(CryptographicUsageMask::Verify);

    let res = create_rsa_key_pair(
        2048,
        "pubkey01",
        "privkey01",
        Some(CryptographicAlgorithm::RSA),
        private_key_mask,
        public_key_mask,
    );

    assert!(res.is_err());

    let private_key_mask = Some(CryptographicUsageMask::Sign);
    let public_key_mask = Some(CryptographicUsageMask::Unrestricted);

    let res = create_rsa_key_pair(
        2048,
        "pubkey02",
        "privkey02",
        Some(CryptographicAlgorithm::RSA),
        private_key_mask,
        public_key_mask,
    );

    assert!(res.is_err())
}

#[test]
#[cfg(feature = "fips")]
fn test_create_rsa_fips_mask() {
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let algorithm = Some(CryptographicAlgorithm::RSA);

    let res = create_rsa_key_pair(
        2048,
        "pubkey01",
        "privkey01",
        algorithm,
        Some(FIPS_PRIVATE_RSA_MASK),
        Some(FIPS_PUBLIC_RSA_MASK),
    );

    assert!(res.is_ok())
}

#[test]
#[cfg(feature = "fips")]
fn test_create_rsa_incorrect_algorithm() {
    // Load FIPS provider module from OpenSSL.
    openssl::provider::Provider::load(None, "fips").unwrap();

    let private_key_mask = Some(CryptographicUsageMask::Sign);
    let public_key_mask = Some(CryptographicUsageMask::Verify);

    let res = create_rsa_key_pair(
        2048,
        "pubkey01",
        "privkey01",
        Some(CryptographicAlgorithm::AES),
        private_key_mask,
        public_key_mask,
    );

    assert!(res.is_err())
}
