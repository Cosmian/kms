#[cfg(not(feature = "non-fips"))]
use cosmian_kmip::kmip_2_1::extra::fips::{
    FIPS_MIN_RSA_MODULUS_LENGTH, FIPS_PRIVATE_RSA_MASK, FIPS_PUBLIC_RSA_MASK,
};
use cosmian_kmip::{
    SafeBigInt,
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PrivateKey, PublicKey},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, KeyFormatType, Link, LinkType,
            LinkedObjectIdentifier, UniqueIdentifier,
        },
    },
};
use cosmian_logger::{debug, trace};
use num_bigint_dig::{BigInt, Sign};
use openssl::{pkey::Private, rsa::Rsa};
use zeroize::Zeroizing;

#[cfg(not(feature = "non-fips"))]
use crate::crypto_bail;
use crate::{CryptoResultHelper, crypto::KeyPair, error::CryptoError};

#[cfg(not(feature = "non-fips"))]
/// Check that bits set in `mask` are only bits set in `flags`. If any bit set
/// in `mask` is not set in `flags`, raise an error.
///
/// If `mask` is `None`, raise an error.
fn check_rsa_mask_against_flags(
    mask: Option<CryptographicUsageMask>,
    flags: CryptographicUsageMask,
) -> Result<(), CryptoError> {
    if (flags & CryptographicUsageMask::Unrestricted).bits() != 0 {
        crypto_bail!("Unrestricted CryptographicUsageMask for RSA is too permissive for FIPS mode.")
    }

    let Some(mask) = mask else {
        // Mask is `None` but FIPS mode is restrictive, so it's considered too
        // permissive.
        crypto_bail!(
            "RSA: forbidden CryptographicUsageMask value, got None but expected among {:#010X} in \
             FIPS mode.",
            flags.bits()
        )
    };

    if (mask & !flags).bits() != 0 {
        crypto_bail!(
            "RSA: forbidden CryptographicUsageMask flag set: {:#010X}, expected among {:#010X} in \
             FIPS mode.",
            mask.bits(),
            flags.bits()
        )
    }

    Ok(())
}

#[cfg(not(feature = "non-fips"))]
/// Check that `mask` is compliant with FIPS restrictions for private and public
/// key components. For example an RSA pubic key must not be used for decryption
/// in FIPS mode.
fn check_rsa_mask_compliance(
    private_key_mask: Option<CryptographicUsageMask>,
    public_key_mask: Option<CryptographicUsageMask>,
) -> Result<(), CryptoError> {
    check_rsa_mask_against_flags(private_key_mask, FIPS_PRIVATE_RSA_MASK)?;
    check_rsa_mask_against_flags(public_key_mask, FIPS_PUBLIC_RSA_MASK)
}

/// Convert to RSA KMIP Public Key.
pub fn to_rsa_public_key(
    private_key: &Rsa<Private>,
    pkey_bits_number: u32,
    private_key_uid: &str,
    public_key_mask: Option<CryptographicUsageMask>,
) -> Result<Object, CryptoError> {
    let cryptographic_length_in_bits =
        i32::try_from(pkey_bits_number).context("Invalid key size")?;

    trace!(
        "bytes len: {}, bits: {}",
        cryptographic_length_in_bits, pkey_bits_number
    );

    let output = Object::PublicKey(PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            key_format_type: KeyFormatType::TransparentRSAPublicKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentRSAPublicKey {
                    modulus: Box::new(BigInt::from_bytes_be(Sign::Plus, &private_key.n().to_vec())),
                    public_exponent: Box::new(BigInt::from_bytes_be(
                        Sign::Plus,
                        &private_key.e().to_vec(),
                    )),
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
                            private_key_uid.to_owned(),
                        ),
                    }]),
                    ..Attributes::default()
                }),
            }),
            cryptographic_length: Some(cryptographic_length_in_bits),
            key_wrapping_data: None,
        },
    });
    trace!("output object: {output}");
    Ok(output)
}

/// Convert an openssl RSA key to a KMIP RSA Private Key.
pub fn to_rsa_private_key(
    private_key: &Rsa<Private>,
    pkey_bits_number: u32,
    public_key_uid: &str,
    private_key_mask: Option<CryptographicUsageMask>,
    sensitive: bool,
) -> Result<Object, CryptoError> {
    let cryptographic_length_in_bits =
        i32::try_from(pkey_bits_number).context("Invalid private key size")?;

    trace!(
        "bytes len: {}, bits: {}",
        cryptographic_length_in_bits, pkey_bits_number
    );

    Ok(Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            key_format_type: KeyFormatType::TransparentRSAPrivateKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentRSAPrivateKey {
                    modulus: Box::new(BigInt::from_bytes_be(Sign::Plus, &private_key.n().to_vec())),
                    private_exponent: Some(Box::new(SafeBigInt::from_bytes_be(&Zeroizing::from(
                        private_key.d().to_vec(),
                    )))),
                    public_exponent: Some(Box::new(BigInt::from_bytes_be(
                        Sign::Plus,
                        &private_key.e().to_vec(),
                    ))),
                    p: private_key
                        .p()
                        .map(|p| Box::new(SafeBigInt::from_bytes_be(&Zeroizing::from(p.to_vec())))),
                    q: private_key
                        .q()
                        .map(|q| Box::new(SafeBigInt::from_bytes_be(&Zeroizing::from(q.to_vec())))),
                    prime_exponent_p: private_key.dmp1().map(|dmp1| {
                        Box::new(SafeBigInt::from_bytes_be(&Zeroizing::from(dmp1.to_vec())))
                    }),
                    prime_exponent_q: private_key.dmq1().map(|dmq1| {
                        Box::new(SafeBigInt::from_bytes_be(&Zeroizing::from(dmq1.to_vec())))
                    }),
                    c_r_t_coefficient: private_key.iqmp().map(|iqmp| {
                        Box::new(SafeBigInt::from_bytes_be(&Zeroizing::from(iqmp.to_vec())))
                    }),
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
                            public_key_uid.to_owned(),
                        ),
                    }]),
                    sensitive: if sensitive { Some(true) } else { None },
                    ..Attributes::default()
                }),
            }),
            cryptographic_length: Some(cryptographic_length_in_bits),
            key_wrapping_data: None,
        },
    }))
}

pub fn create_rsa_key_pair(
    private_key_uid: &str,
    public_key_uid: &str,
    mut common_attributes: Attributes,
    private_key_attributes: Option<Attributes>,
    public_key_attributes: Option<Attributes>,
) -> Result<KeyPair, CryptoError> {
    let key_size_in_bits = u32::try_from(
        common_attributes
            .cryptographic_length
            .ok_or_else(|| CryptoError::Default("Invalid RSA key size".to_owned()))?,
    )?;
    debug!("RSA key pair generation: size in bits: {key_size_in_bits}");

    #[cfg(not(feature = "non-fips"))]
    if key_size_in_bits < FIPS_MIN_RSA_MODULUS_LENGTH {
        crypto_bail!(
            "FIPS 140 mode requires a minimum key length of {} bits",
            FIPS_MIN_RSA_MODULUS_LENGTH
        )
    }

    let private_key_mask = private_key_attributes
        .as_ref()
        .and_then(|attr| attr.cryptographic_usage_mask);
    let public_key_mask = public_key_attributes
        .as_ref()
        .and_then(|attr| attr.cryptographic_usage_mask);

    #[cfg(not(feature = "non-fips"))]
    check_rsa_mask_compliance(private_key_mask, public_key_mask)?;

    // recover tags and clean them up from the common attributes
    let tags = common_attributes.remove_tags().unwrap_or_default();
    Attributes::check_user_tags(&tags)?;

    // Generate the RSA Key Pair with openssl
    let rsa_private = Rsa::generate(key_size_in_bits)?;

    // Generate the KMIP RSA Private Key
    let mut private_key_attributes = private_key_attributes.unwrap_or_default();
    private_key_attributes.merge(&common_attributes, false);
    // KMIP Object generation
    let mut private_key = to_rsa_private_key(
        &rsa_private,
        key_size_in_bits,
        public_key_uid,
        private_key_mask,
        private_key_attributes.sensitive.unwrap_or_default(),
    )?;
    // Merge the created object attributes
    private_key_attributes.merge(private_key.attributes()?, true);
    // Set the private key UID
    private_key_attributes.unique_identifier =
        Some(UniqueIdentifier::TextString(private_key_uid.to_owned()));
    // Add the tags
    let mut sk_tags = tags.clone();
    sk_tags.insert("_sk".to_owned());
    private_key_attributes.set_tags(sk_tags)?;
    // and set them on the object
    let Some(&mut KeyValue::Structure {
        ref mut attributes, ..
    }) = private_key.key_block_mut()?.key_value.as_mut()
    else {
        return Err(CryptoError::Default(
            "Key value not found in RSA private key".to_owned(),
        ));
    };
    *attributes = Some(private_key_attributes);

    // Generate the KMIP RSA Public Key
    let mut public_key_attributes = public_key_attributes.unwrap_or_default();
    public_key_attributes.merge(&common_attributes, false);
    // KMIP Object generation
    let mut public_key = to_rsa_public_key(
        &rsa_private,
        key_size_in_bits,
        private_key_uid,
        public_key_mask,
    )?;
    // Merge the created object attributes
    public_key_attributes.merge(public_key.attributes()?, true);
    // Set the public key UID
    public_key_attributes.unique_identifier =
        Some(UniqueIdentifier::TextString(public_key_uid.to_owned()));
    // Add the tags
    let mut pk_tags = tags;
    pk_tags.insert("_pk".to_owned());
    public_key_attributes.set_tags(pk_tags)?;
    // and set them on the object
    let Some(&mut KeyValue::Structure {
        ref mut attributes, ..
    }) = public_key.key_block_mut()?.key_value.as_mut()
    else {
        return Err(CryptoError::Default(
            "Key value not found in RSA public key".to_owned(),
        ));
    };
    *attributes = Some(public_key_attributes);

    debug!("RSA key pair generated: private key id: {private_key_uid}");

    Ok(KeyPair::new(private_key, public_key))
}

#[cfg(not(feature = "non-fips"))]
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use cosmian_kmip::{
        kmip_0::kmip_types::CryptographicUsageMask,
        kmip_2_1::{
            extra::fips::{FIPS_PRIVATE_RSA_MASK, FIPS_PUBLIC_RSA_MASK},
            kmip_attributes::Attributes,
        },
    };

    use crate::crypto::rsa::operation::create_rsa_key_pair;

    #[test]
    fn test_create_rsa_incorrect_mask() {
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let common_attributes = Attributes {
            cryptographic_length: Some(2048),
            ..Attributes::default()
        };
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Sign),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Sign | CryptographicUsageMask::Verify,
            ),
            ..Attributes::default()
        };

        let res = create_rsa_key_pair(
            "privkey01",
            "pubkey01",
            common_attributes,
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());

        let common_attributes = Attributes {
            cryptographic_length: Some(2048),
            ..Attributes::default()
        };
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Decrypt | CryptographicUsageMask::CRLSign,
            ),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Verify,
            ),
            ..Attributes::default()
        };

        let res = create_rsa_key_pair(
            "privkey02",
            "pubkey02",
            common_attributes,
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());
    }

    #[test]
    fn test_create_rsa_incorrect_mask_unrestricted() {
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let common_attributes = Attributes {
            cryptographic_length: Some(2048),
            ..Attributes::default()
        };
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Verify),
            ..Attributes::default()
        };

        let res = create_rsa_key_pair(
            "privkey01",
            "pubkey01",
            common_attributes,
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());

        let common_attributes = Attributes {
            cryptographic_length: Some(2048),
            ..Attributes::default()
        };
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Sign),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(CryptographicUsageMask::Unrestricted),
            ..Attributes::default()
        };

        let res = create_rsa_key_pair(
            "privkey02",
            "pubkey02",
            common_attributes,
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        assert!(res.is_err());
    }

    #[test]
    fn test_create_rsa_fips_mask() {
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let common_attributes = Attributes {
            cryptographic_length: Some(2048),
            ..Attributes::default()
        };
        let private_key_attributes = Attributes {
            cryptographic_usage_mask: Some(FIPS_PRIVATE_RSA_MASK),
            ..Attributes::default()
        };
        let public_key_attributes = Attributes {
            cryptographic_usage_mask: Some(FIPS_PUBLIC_RSA_MASK),
            ..Attributes::default()
        };

        let res = create_rsa_key_pair(
            "privkey01",
            "pubkey01",
            common_attributes,
            Some(private_key_attributes),
            Some(public_key_attributes),
        );

        res.unwrap();
    }
}
