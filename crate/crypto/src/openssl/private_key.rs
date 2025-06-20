use cosmian_kmip::{
    SafeBigInt,
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PrivateKey},
        kmip_types::{
            CryptographicAlgorithm, CryptographicDomainParameters, CryptographicParameters,
            KeyFormatType, RecommendedCurve,
        },
    },
};
use num_bigint_dig::{BigInt, BigUint, IntoBigUint, Sign};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::{Id, PKey, Private},
    rsa::{Rsa, RsaPrivateKeyBuilder},
};
use zeroize::Zeroizing;

use crate::{
    crypto::elliptic_curves::{
        ED448_PRIVATE_KEY_LENGTH, ED25519_PRIVATE_KEY_LENGTH, X448_PRIVATE_KEY_LENGTH,
        X25519_PRIVATE_KEY_LENGTH,
    },
    crypto_bail,
    error::{CryptoError, result::CryptoResultHelper},
    pad_be_bytes,
};

/// Convert a KMIP Private key to openssl `PKey<Private>`
///
/// The supported `KeyFormatType` are:
/// * PKCS1
/// * `ECPrivateKey` (SEC1)
/// * PKCS8 (not encrypted only)
/// * `TransparentRSAPrivateKey`
///
/// Note: `TransparentECPrivateKey` is not supported: the current openssl implementation
/// does not allow constructing a private key without the public component.
///
/// # Arguments
///
/// * `private_key` - The KMIP Private key to convert
///
/// # Returns
///
/// * `PKey<Private>` - The openssl Private key
///
pub fn kmip_private_key_to_openssl(private_key: &Object) -> Result<PKey<Private>, CryptoError> {
    let key_block = match private_key {
        Object::PrivateKey(PrivateKey { key_block }) => key_block,
        x => crypto_bail!("Invalid Object: {}. KMIP Private Key expected", x),
    };
    let pk: PKey<Private> = match key_block.key_format_type {
        KeyFormatType::PKCS1 => {
            let key_bytes = key_block.pkcs_der_bytes()?;
            // parse the RSA private key to make sure it is correct
            let rsa_private_key = Rsa::private_key_from_der(&key_bytes)?;
            PKey::from_rsa(rsa_private_key)?
        }
        // This really is a SPKI as specified by RFC 5480
        KeyFormatType::PKCS8 => {
            let key_bytes = key_block.pkcs_der_bytes()?;
            // This key may be an RSA or EC key
            PKey::private_key_from_der(&key_bytes)?
        }
        KeyFormatType::ECPrivateKey => {
            let key_bytes = key_block.pkcs_der_bytes()?;
            // this is the (not so appropriate) value for SEC1
            let ec_key = EcKey::private_key_from_der(&key_bytes)?;
            ec_key.check_key()?;
            PKey::from_ec_key(ec_key)?
        }
        KeyFormatType::TransparentRSAPrivateKey => {
            let Some(KeyValue::Structure { key_material, .. }) = key_block.key_value.as_ref()
            else {
                return Err(CryptoError::Default(
                    "Key value not found in Transparent RSA private key".to_owned(),
                ));
            };
            match key_material {
                KeyMaterial::TransparentRSAPrivateKey {
                    modulus,
                    private_exponent,
                    public_exponent,
                    p,
                    q,
                    prime_exponent_p,
                    prime_exponent_q,
                    c_r_t_coefficient: crt_coefficient,
                } => {
                    let mut rsa_private_key_builder = RsaPrivateKeyBuilder::new(
                        BigNum::from_slice(&modulus.to_bytes_be().1)?,
                        BigNum::from_slice(
                            &public_exponent
                                .clone()
                                .context(
                                    "the public exponent is required for Transparent RSA Private \
                                     Keys",
                                )?
                                .to_bytes_be()
                                .1,
                        )?,
                        BigNum::from_slice(
                            &private_exponent
                                .clone()
                                .context(
                                    "the private exponent is required for Transparent RSA Private \
                                     Keys",
                                )?
                                .to_bytes_be()
                                .1,
                        )?,
                    )?;
                    if let Some(p) = p {
                        if let Some(q) = q {
                            rsa_private_key_builder = rsa_private_key_builder
                                .set_factors(
                                    BigNum::from_slice(&p.clone().to_bytes_be().1)?,
                                    BigNum::from_slice(&q.clone().to_bytes_be().1)?,
                                )
                                .context("Failed to set 'p' and 'q' on the RSA Private key")?;
                        }
                    }
                    if let Some(prime_exponent_p) = prime_exponent_p {
                        if let Some(prime_exponent_q) = prime_exponent_q {
                            if let Some(crt_coefficient) = crt_coefficient {
                                rsa_private_key_builder = rsa_private_key_builder
                                    .set_crt_params(
                                        BigNum::from_slice(
                                            &prime_exponent_p.clone().to_bytes_be().1,
                                        )?,
                                        BigNum::from_slice(
                                            &prime_exponent_q.clone().to_bytes_be().1,
                                        )?,
                                        BigNum::from_slice(
                                            &crt_coefficient.clone().to_bytes_be().1,
                                        )?,
                                    )
                                    .context(
                                        "Failed to set CRT parameters on the RSA Private key",
                                    )?;
                            }
                        }
                    }
                    let rsa_private_key = rsa_private_key_builder.build();
                    PKey::from_rsa(rsa_private_key)?
                }
                _ => crypto_bail!(
                    "Invalid Transparent RSA private key material: TransparentRSAPrivateKey \
                     expected"
                ),
            }
        }
        KeyFormatType::TransparentECPrivateKey => {
            let Some(KeyValue::Structure { key_material, .. }) = key_block.key_value.as_ref()
            else {
                return Err(CryptoError::Default(
                    "Key value not found in Transparent EC private key".to_owned(),
                ));
            };
            match key_material {
                KeyMaterial::TransparentECPrivateKey {
                    d,
                    recommended_curve,
                } => match recommended_curve {
                    RecommendedCurve::CURVE25519 => {
                        let mut privkey_vec = d.to_bytes_be().1;
                        pad_be_bytes(&mut privkey_vec, X25519_PRIVATE_KEY_LENGTH);
                        PKey::private_key_from_raw_bytes(&privkey_vec, Id::X25519)?
                    }
                    RecommendedCurve::CURVE448 => {
                        let mut privkey_vec = d.to_bytes_be().1;
                        pad_be_bytes(&mut privkey_vec, X448_PRIVATE_KEY_LENGTH);
                        PKey::private_key_from_raw_bytes(&privkey_vec, Id::X448)?
                    }
                    RecommendedCurve::CURVEED25519 => {
                        let mut privkey_vec = d.to_bytes_be().1;
                        pad_be_bytes(&mut privkey_vec, ED25519_PRIVATE_KEY_LENGTH);
                        PKey::private_key_from_raw_bytes(&privkey_vec, Id::ED25519)?
                    }
                    RecommendedCurve::CURVEED448 => {
                        let mut privkey_vec = d.to_bytes_be().1;
                        pad_be_bytes(&mut privkey_vec, ED448_PRIVATE_KEY_LENGTH);
                        PKey::private_key_from_raw_bytes(&privkey_vec, Id::ED448)?
                    }
                    other => {
                        let big_i: BigInt = BigInt::from(*d.clone());
                        let big_ui = big_i.into_biguint().ok_or_else(|| {
                            CryptoError::ConversionError(
                                "Failed converting the scalar BigInt to a BigUint".to_owned(),
                            )
                        })?;
                        ec_private_key_from_scalar(&big_ui, *other)?
                    }
                },
                x => crypto_bail!(
                    "KMIP key to openssl: invalid Transparent EC private key material: {}: \
                     TransparentECPrivateKey expected",
                    x
                ),
            }
        }
        f => crypto_bail!(
            "Unsupported key format type: {:?}, for a Transparent EC private key",
            f
        ),
    };
    Ok(pk)
}

//
fn ec_private_key_from_scalar(
    scalar: &BigUint,
    curve: RecommendedCurve,
) -> Result<PKey<Private>, CryptoError> {
    let (nid, privkey_size) = match curve {
        // P-CURVES
        #[cfg(feature = "non-fips")]
        RecommendedCurve::P192 => (Nid::X9_62_PRIME192V1, 24),
        RecommendedCurve::P256 => (Nid::X9_62_PRIME256V1, 32),
        RecommendedCurve::P224 => (Nid::SECP224R1, 28),
        RecommendedCurve::P384 => (Nid::SECP384R1, 48),
        RecommendedCurve::P521 => (Nid::SECP521R1, 66),

        x => crypto_bail!("Unsupported curve: {:?} in this KMIP implementation", x),
    };
    let big_num_context = BigNumContext::new()?;

    let mut scalar_vec = scalar.to_bytes_be();
    pad_be_bytes(&mut scalar_vec, privkey_size);
    let scalar = BigNum::from_slice(&scalar_vec)?;

    let ec_group = EcGroup::from_curve_name(nid)?;
    let mut ec_public_key = EcPoint::new(&ec_group)?;
    ec_public_key.mul_generator(&ec_group, &scalar, &big_num_context)?;
    Ok(PKey::from_ec_key(EcKey::from_private_components(
        &ec_group,
        &scalar,
        &ec_public_key,
    )?)?)
}

/// Convert an openssl private key to a KMIP private Key (`Object::PrivateKey`) of the given `KeyFormatType`
pub fn openssl_private_key_to_kmip(
    private_key: &PKey<Private>,
    #[cfg(feature = "non-fips")] mut key_format_type: KeyFormatType,
    #[cfg(not(feature = "non-fips"))] key_format_type: KeyFormatType,
    cryptographic_usage_mask: Option<CryptographicUsageMask>,
) -> Result<Object, CryptoError> {
    let cryptographic_length = Some(i32::try_from(private_key.bits())?);

    #[cfg(feature = "non-fips")]
    // When not in FIPS mode, None defaults to Unrestricted.
    let cryptographic_usage_mask = if cryptographic_usage_mask.is_none() {
        Some(CryptographicUsageMask::Unrestricted)
    } else {
        cryptographic_usage_mask
    };

    // Legacy PKCS12 is the same as PKCS12 for the private key,
    // which will be exported as PKCS#8
    #[cfg(feature = "non-fips")]
    {
        if key_format_type == KeyFormatType::Pkcs12Legacy {
            key_format_type = KeyFormatType::PKCS12;
        }
    }

    let key_block = match key_format_type {
        KeyFormatType::TransparentRSAPrivateKey => {
            let rsa_private_key = private_key
                .rsa()
                .context("the provided openssl key is not an RSA private key")?;
            let modulus =
                BigInt::from_bytes_be(Sign::Plus, rsa_private_key.n().to_vec().as_slice());
            let public_exponent =
                BigInt::from_bytes_be(Sign::Plus, rsa_private_key.e().to_vec().as_slice());
            let private_exponent =
                BigInt::from_bytes_be(Sign::Plus, rsa_private_key.d().to_vec().as_slice());
            let p = rsa_private_key
                .p()
                .map(|p| BigInt::from_bytes_be(Sign::Plus, p.to_vec().as_slice()));
            let q = rsa_private_key
                .q()
                .map(|q| BigInt::from_bytes_be(Sign::Plus, q.to_vec().as_slice()));
            let prime_exponent_p = rsa_private_key
                .dmp1()
                .map(|dmp1| BigInt::from_bytes_be(Sign::Plus, dmp1.to_vec().as_slice()));
            let prime_exponent_q = rsa_private_key
                .dmq1()
                .map(|dmpq1| BigInt::from_bytes_be(Sign::Plus, dmpq1.to_vec().as_slice()));
            let crt_coefficient = rsa_private_key
                .iqmp()
                .map(|iqmp| BigInt::from_bytes_be(Sign::Plus, iqmp.to_vec().as_slice()));
            KeyBlock {
                key_format_type,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::TransparentRSAPrivateKey {
                        modulus: Box::new(modulus),
                        private_exponent: Some(Box::new(SafeBigInt::from(private_exponent))),
                        public_exponent: Some(Box::new(public_exponent)),
                        p: p.map(|p| Box::new(SafeBigInt::from(p))),
                        q: q.map(|q| Box::new(SafeBigInt::from(q))),
                        prime_exponent_p: prime_exponent_p
                            .map(|pep| Box::new(SafeBigInt::from(pep))),
                        prime_exponent_q: prime_exponent_q
                            .map(|peq| Box::new(SafeBigInt::from(peq))),
                        c_r_t_coefficient: crt_coefficient
                            .map(|crt_coeff| Box::new(SafeBigInt::from(crt_coeff))),
                    },
                    attributes: Some(Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                        cryptographic_length,
                        key_format_type: Some(KeyFormatType::TransparentRSAPrivateKey),
                        object_type: Some(ObjectType::PrivateKey),
                        cryptographic_usage_mask,
                        cryptographic_parameters: Some(CryptographicParameters {
                            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                            ..CryptographicParameters::default()
                        }),
                        ..Attributes::default()
                    }),
                }),
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length,
                key_wrapping_data: None,
                key_compression_type: None,
            }
        }
        KeyFormatType::TransparentECPrivateKey => {
            let (recommended_curve, cryptographic_algorithm, d) = match private_key.id() {
                // This is a likely curve 25519 or 448 keys (i.e., a non-standardized curve)
                Id::EC => {
                    let ec_key = private_key
                        .ec_key()
                        .context("the provided openssl key is not an elliptic curve private key")?;
                    let d = BigUint::from_bytes_be(ec_key.private_key().to_vec().as_slice());
                    let recommended_curve = match ec_key.group().curve_name() {
                        Some(nid) => match nid {
                            // P-CURVES
                            #[cfg(feature = "non-fips")]
                            Nid::X9_62_PRIME192V1 => RecommendedCurve::P192,
                            Nid::SECP224R1 => RecommendedCurve::P224,
                            Nid::X9_62_PRIME256V1 => RecommendedCurve::P256,
                            Nid::SECP384R1 => RecommendedCurve::P384,
                            Nid::SECP521R1 => RecommendedCurve::P521,
                            _ => {
                                crypto_bail!(
                                    "Unsupported openssl curve: {:?} in this KMIP implementation",
                                    nid
                                );
                            }
                        },
                        None => {
                            crypto_bail!(
                                "Unsupported openssl curve: {:?} in this KMIP implementation",
                                ec_key.group().curve_name()
                            );
                        }
                    };
                    (recommended_curve, CryptographicAlgorithm::ECDH, d)
                }

                Id::X25519 => (
                    RecommendedCurve::CURVE25519,
                    CryptographicAlgorithm::ECDH,
                    BigUint::from_bytes_be(private_key.raw_private_key()?.as_slice()),
                ),
                Id::X448 => (
                    RecommendedCurve::CURVE448,
                    CryptographicAlgorithm::ECDH,
                    BigUint::from_bytes_be(private_key.raw_private_key()?.as_slice()),
                ),
                Id::ED25519 => (
                    RecommendedCurve::CURVEED25519,
                    CryptographicAlgorithm::Ed25519,
                    BigUint::from_bytes_be(private_key.raw_private_key()?.as_slice()),
                ),
                Id::ED448 => (
                    RecommendedCurve::CURVEED448,
                    CryptographicAlgorithm::Ed448,
                    BigUint::from_bytes_be(private_key.raw_private_key()?.as_slice()),
                ),
                x => crypto_bail!("Unsupported curve: {:?} in KMIP format", x),
            };
            let cryptographic_length = Some(i32::try_from(private_key.bits())?);
            KeyBlock {
                key_format_type,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::TransparentECPrivateKey {
                        recommended_curve,
                        d: Box::new(SafeBigInt::from(d)),
                    },
                    attributes: Some(Attributes {
                        activation_date: None,
                        certificate_attributes: None,
                        certificate_type: None,
                        certificate_length: None,
                        cryptographic_algorithm: Some(cryptographic_algorithm),
                        cryptographic_length,
                        key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
                        link: None,
                        object_type: Some(ObjectType::PrivateKey),
                        unique_identifier: None,
                        cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                            recommended_curve: Some(recommended_curve),
                            ..CryptographicDomainParameters::default()
                        }),
                        cryptographic_parameters: Some(CryptographicParameters {
                            cryptographic_algorithm: Some(cryptographic_algorithm),
                            ..CryptographicParameters::default()
                        }),
                        cryptographic_usage_mask,
                        ..Attributes::default()
                    }),
                }),
                cryptographic_algorithm: Some(cryptographic_algorithm),
                cryptographic_length,
                key_wrapping_data: None,
                key_compression_type: None,
            }
        }
        KeyFormatType::PKCS8 | KeyFormatType::PKCS12 => {
            let cryptographic_algorithm = match private_key.id() {
                Id::RSA => Some(CryptographicAlgorithm::RSA),
                Id::EC | Id::X25519 | Id::X448 => Some(CryptographicAlgorithm::ECDH),
                Id::ED25519 => Some(CryptographicAlgorithm::Ed25519),
                Id::ED448 => Some(CryptographicAlgorithm::Ed448),
                _ => None,
            };

            KeyBlock {
                key_format_type: KeyFormatType::PKCS8,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(Zeroizing::from(
                        private_key.private_key_to_pkcs8()?,
                    )),
                    attributes: Some(Attributes {
                        cryptographic_algorithm,
                        cryptographic_length,
                        key_format_type: Some(KeyFormatType::PKCS8),
                        object_type: Some(ObjectType::PrivateKey),
                        cryptographic_usage_mask,
                        cryptographic_parameters: Some(CryptographicParameters {
                            cryptographic_algorithm,
                            ..CryptographicParameters::default()
                        }),
                        ..Attributes::default()
                    }),
                }),
                cryptographic_algorithm,
                cryptographic_length,
                key_wrapping_data: None,
                key_compression_type: None,
            }
        }
        // This is SEC1
        KeyFormatType::ECPrivateKey => {
            let ec_key = private_key
                .ec_key()
                .context("the private key is not an openssl EC key")?;
            KeyBlock {
                key_format_type,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(Zeroizing::from(
                        ec_key.private_key_to_der()?,
                    )),
                    attributes: Some(Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                        cryptographic_length,
                        key_format_type: Some(KeyFormatType::ECPrivateKey),
                        object_type: Some(ObjectType::PrivateKey),
                        cryptographic_usage_mask,
                        ..Attributes::default()
                    }),
                }),
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                cryptographic_length,
                key_wrapping_data: None,
                key_compression_type: None,
            }
        }
        KeyFormatType::PKCS1 => {
            let rsa_private_key = private_key
                .rsa()
                .context("the private key is not an openssl RSA key")?;
            KeyBlock {
                key_format_type,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(Zeroizing::from(
                        rsa_private_key.private_key_to_der()?,
                    )),
                    attributes: Some(Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                        cryptographic_length,
                        key_format_type: Some(KeyFormatType::PKCS1),
                        object_type: Some(ObjectType::PrivateKey),
                        cryptographic_usage_mask,
                        ..Attributes::default()
                    }),
                }),
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length,
                key_wrapping_data: None,
                key_compression_type: None,
            }
        }
        f => crypto_bail!(
            "Unsupported key format type: {:?}, for a KMIP private key",
            f
        ),
    };
    Ok(Object::PrivateKey(PrivateKey { key_block }))
}

#[allow(clippy::unwrap_used, clippy::panic)]
#[cfg(test)]
mod tests {
    #[cfg(feature = "non-fips")]
    use cosmian_kmip::kmip_0::kmip_types::CryptographicUsageMask;
    #[cfg(not(feature = "non-fips"))]
    use cosmian_kmip::kmip_2_1::extra::fips::{
        FIPS_PRIVATE_ECC_MASK_SIGN_ECDH, FIPS_PRIVATE_RSA_MASK,
    };
    use cosmian_kmip::kmip_2_1::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, PrivateKey},
        kmip_types::{KeyFormatType, RecommendedCurve},
    };
    use cosmian_logger::log_init;
    use openssl::{
        bn::BigNum,
        ec::{EcGroup, EcKey, EcPoint},
        nid::Nid,
        pkey::{Id, PKey, Private},
        rsa::Rsa,
    };

    use crate::openssl::{
        kmip_private_key_to_openssl,
        private_key::{openssl_private_key_to_kmip, pad_be_bytes},
    };

    fn test_private_key_conversion_pkcs(
        private_key: &PKey<Private>,
        id: Id,
        key_size: u32,
        kft: KeyFormatType,
    ) {
        #[cfg(not(feature = "non-fips"))]
        let mask = Some(FIPS_PRIVATE_RSA_MASK);
        #[cfg(feature = "non-fips")]
        let mask = Some(CryptographicUsageMask::Unrestricted);

        // PKCS#X
        let object = openssl_private_key_to_kmip(private_key, kft, mask).unwrap();
        let object_ = object.clone();
        let Object::PrivateKey(PrivateKey { key_block }) = object else {
            panic!("Invalid key block")
        };
        let KeyBlock {
            key_value:
                Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(key_value),
                    ..
                }),
            ..
        } = key_block
        else {
            panic!("Invalid key block")
        };

        if kft == KeyFormatType::PKCS8 {
            let private_key_ = PKey::private_key_from_pkcs8(&key_value).unwrap();
            assert_eq!(private_key_.id(), id);
            assert_eq!(private_key_.bits(), key_size);
            assert_eq!(
                private_key_.private_key_to_pkcs8().unwrap(),
                key_value.to_vec()
            );
            let private_key_ = kmip_private_key_to_openssl(&object_).unwrap();
            assert_eq!(private_key_.id(), id);
            assert_eq!(private_key_.bits(), key_size);
            assert_eq!(
                private_key_.private_key_to_pkcs8().unwrap(),
                key_value.to_vec()
            );
        } else {
            let private_key_ = PKey::private_key_from_der(&key_value).unwrap();
            assert_eq!(private_key_.id(), id);
            assert_eq!(private_key_.bits(), key_size);
            assert_eq!(
                private_key_.private_key_to_der().unwrap(),
                key_value.to_vec()
            );
            let private_key_ = kmip_private_key_to_openssl(&object_).unwrap();
            assert_eq!(private_key_.id(), id);
            assert_eq!(private_key_.bits(), key_size);
            assert_eq!(
                private_key_.private_key_to_der().unwrap(),
                key_value.to_vec()
            );
        }
    }

    fn test_private_key_conversion_sec1(private_key: &PKey<Private>, id: Id, key_size: u32) {
        #[cfg(not(feature = "non-fips"))]
        let mask = Some(FIPS_PRIVATE_ECC_MASK_SIGN_ECDH);
        #[cfg(feature = "non-fips")]
        let mask = Some(CryptographicUsageMask::Unrestricted);

        // SEC1.
        let object =
            openssl_private_key_to_kmip(private_key, KeyFormatType::ECPrivateKey, mask).unwrap();
        let object_ = object.clone();
        let Object::PrivateKey(PrivateKey { key_block }) = object else {
            panic!("Invalid key block")
        };
        let KeyBlock {
            key_value:
                Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(key_value),
                    ..
                }),
            ..
        } = key_block
        else {
            panic!("Invalid key block")
        };
        let private_key_ =
            PKey::from_ec_key(EcKey::private_key_from_der(&key_value).unwrap()).unwrap();
        assert_eq!(private_key_.id(), id);
        assert_eq!(private_key_.bits(), key_size);
        assert_eq!(
            private_key_.private_key_to_der().unwrap(),
            key_value.to_vec()
        );
        let private_key_ = kmip_private_key_to_openssl(&object_).unwrap();
        assert_eq!(private_key_.id(), id);
        assert_eq!(private_key_.bits(), key_size);
        assert_eq!(
            private_key_.private_key_to_der().unwrap(),
            key_value.to_vec()
        );
    }

    fn test_private_key_conversion_transparent_rsa(
        private_key: &PKey<Private>,
        id: Id,
        key_size: u32,
    ) {
        #[cfg(not(feature = "non-fips"))]
        let mask = Some(FIPS_PRIVATE_RSA_MASK);
        #[cfg(feature = "non-fips")]
        let mask = Some(CryptographicUsageMask::Unrestricted);

        let object =
            openssl_private_key_to_kmip(private_key, KeyFormatType::TransparentRSAPrivateKey, mask)
                .unwrap();
        let object_ = object.clone();
        let Object::PrivateKey(PrivateKey { key_block }) = object else {
            panic!("Invalid key block")
        };
        let KeyBlock {
            key_value:
                Some(KeyValue::Structure {
                    key_material:
                        KeyMaterial::TransparentRSAPrivateKey {
                            modulus,
                            private_exponent,
                            public_exponent,
                            p,
                            q,
                            prime_exponent_p,
                            prime_exponent_q,
                            c_r_t_coefficient: crt_coefficient,
                        },
                    ..
                }),
            ..
        } = key_block
        else {
            panic!("Invalid key block")
        };
        let private_key_ = PKey::from_rsa(
            Rsa::from_private_components(
                BigNum::from_slice(&modulus.to_bytes_be().1).unwrap(),
                BigNum::from_slice(&public_exponent.unwrap().to_bytes_be().1).unwrap(),
                BigNum::from_slice(&private_exponent.unwrap().to_bytes_be().1).unwrap(),
                BigNum::from_slice(&p.unwrap().to_bytes_be().1).unwrap(),
                BigNum::from_slice(&q.unwrap().to_bytes_be().1).unwrap(),
                BigNum::from_slice(&prime_exponent_p.unwrap().to_bytes_be().1).unwrap(),
                BigNum::from_slice(&prime_exponent_q.unwrap().to_bytes_be().1).unwrap(),
                BigNum::from_slice(&crt_coefficient.unwrap().to_bytes_be().1).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(private_key_.id(), id);
        assert_eq!(private_key_.bits(), key_size);
        assert_eq!(
            private_key.private_key_to_der().unwrap(),
            private_key_.private_key_to_der().unwrap()
        );

        let private_key_ = kmip_private_key_to_openssl(&object_).unwrap();
        assert_eq!(private_key_.id(), id);
        assert_eq!(private_key_.bits(), key_size);
        assert_eq!(
            private_key.private_key_to_der().unwrap(),
            private_key_.private_key_to_der().unwrap()
        );
    }

    fn test_private_key_conversion_transparent_ec(
        private_key: &PKey<Private>,
        ec_public_key: Option<&EcPoint>,
        ec_group: Option<&EcGroup>,
        curve: RecommendedCurve,
        id: Id,
        key_size: u32,
    ) {
        #[cfg(not(feature = "non-fips"))]
        let mask = Some(FIPS_PRIVATE_ECC_MASK_SIGN_ECDH);
        #[cfg(feature = "non-fips")]
        let mask = Some(CryptographicUsageMask::Unrestricted);

        // Transparent EC.
        let object =
            openssl_private_key_to_kmip(private_key, KeyFormatType::TransparentECPrivateKey, mask)
                .unwrap();
        let object_ = object.clone();
        let Object::PrivateKey(PrivateKey { key_block }) = object else {
            panic!("Invalid key block")
        };
        let KeyBlock {
            key_value:
                Some(KeyValue::Structure {
                    key_material:
                        KeyMaterial::TransparentECPrivateKey {
                            d,
                            recommended_curve,
                        },
                    ..
                }),
            ..
        } = key_block
        else {
            panic!("Invalid key block")
        };
        assert_eq!(recommended_curve, curve);

        let mut privkey_vec = d.to_bytes_be().1;

        // privkey size on curve.
        let bytes_key_size = 1 + ((usize::try_from(key_size).unwrap() - 1) / 8);

        pad_be_bytes(&mut privkey_vec, bytes_key_size);
        if id == Id::EC {
            let private_key_ = PKey::from_ec_key(
                EcKey::from_private_components(
                    ec_group.unwrap(),
                    &BigNum::from_slice(privkey_vec.as_slice()).unwrap(),
                    ec_public_key.unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(private_key_.id(), id);
            assert_eq!(private_key_.bits(), key_size);
            assert_eq!(
                private_key.private_key_to_der().unwrap(),
                private_key_.private_key_to_der().unwrap()
            );
            let private_key_ = kmip_private_key_to_openssl(&object_).unwrap();
            assert_eq!(private_key_.id(), id);
            assert_eq!(private_key_.bits(), key_size);
            assert_eq!(
                private_key.private_key_to_der().unwrap(),
                private_key_.private_key_to_der().unwrap()
            );
        } else {
            let private_key_ = PKey::private_key_from_raw_bytes(&privkey_vec, id).unwrap();
            assert_eq!(private_key_.id(), id);
            assert_eq!(private_key_.bits(), key_size);
            assert_eq!(
                private_key.raw_private_key().unwrap(),
                private_key_.raw_private_key().unwrap()
            );
            let private_key_ = kmip_private_key_to_openssl(&object_).unwrap();
            assert_eq!(private_key_.id(), id);
            assert_eq!(private_key_.bits(), key_size);
            assert_eq!(
                private_key.raw_private_key().unwrap(),
                private_key_.raw_private_key().unwrap()
            );
        }
    }

    #[test]
    fn test_conversion_rsa_private_key() {
        log_init(option_env!("RUST_LOG"));

        #[cfg(not(feature = "non-fips"))]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 2048;
        let rsa_private_key = Rsa::generate(key_size).unwrap();
        let private_key = PKey::from_rsa(rsa_private_key).unwrap();

        test_private_key_conversion_pkcs(&private_key, Id::RSA, key_size, KeyFormatType::PKCS8);
        test_private_key_conversion_pkcs(&private_key, Id::RSA, key_size, KeyFormatType::PKCS1);
        test_private_key_conversion_transparent_rsa(&private_key, Id::RSA, key_size);
    }

    #[test]
    #[cfg(feature = "non-fips")]
    fn test_conversion_ec_p_192_private_key() {
        log_init(option_env!("RUST_LOG"));

        let key_size = 192;
        let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME192V1).unwrap();
        let ec_key = EcKey::generate(&ec_group).unwrap();
        let ec_public_key = ec_key.public_key().to_owned(&ec_group).unwrap();
        let private_key = PKey::from_ec_key(ec_key).unwrap();

        test_private_key_conversion_pkcs(&private_key, Id::EC, key_size, KeyFormatType::PKCS8);
        test_private_key_conversion_sec1(&private_key, Id::EC, key_size);

        test_private_key_conversion_transparent_ec(
            &private_key,
            Some(&ec_public_key),
            Some(&ec_group),
            RecommendedCurve::P192,
            Id::EC,
            key_size,
        );
    }

    #[test]
    fn test_conversion_ec_p_224_private_key() {
        log_init(option_env!("RUST_LOG"));
        #[cfg(not(feature = "non-fips"))]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 224;
        let ec_group = EcGroup::from_curve_name(Nid::SECP224R1).unwrap();
        let ec_key = EcKey::generate(&ec_group).unwrap();
        let ec_public_key = ec_key.public_key().to_owned(&ec_group).unwrap();
        let private_key = PKey::from_ec_key(ec_key).unwrap();

        test_private_key_conversion_pkcs(&private_key, Id::EC, key_size, KeyFormatType::PKCS8);
        test_private_key_conversion_sec1(&private_key, Id::EC, key_size);

        test_private_key_conversion_transparent_ec(
            &private_key,
            Some(&ec_public_key),
            Some(&ec_group),
            RecommendedCurve::P224,
            Id::EC,
            key_size,
        );
    }

    #[test]
    fn test_conversion_ec_p_256_private_key() {
        log_init(option_env!("RUST_LOG"));

        #[cfg(not(feature = "non-fips"))]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 256;
        let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&ec_group).unwrap();
        let ec_public_key = ec_key.public_key().to_owned(&ec_group).unwrap();
        let private_key = PKey::from_ec_key(ec_key).unwrap();

        test_private_key_conversion_pkcs(&private_key, Id::EC, key_size, KeyFormatType::PKCS8);
        test_private_key_conversion_sec1(&private_key, Id::EC, key_size);

        test_private_key_conversion_transparent_ec(
            &private_key,
            Some(&ec_public_key),
            Some(&ec_group),
            RecommendedCurve::P256,
            Id::EC,
            key_size,
        );
    }

    #[test]
    fn test_conversion_ec_p_384_private_key() {
        log_init(option_env!("RUST_LOG"));

        #[cfg(not(feature = "non-fips"))]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 384;
        let ec_group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let ec_key = EcKey::generate(&ec_group).unwrap();
        let ec_public_key = ec_key.public_key().to_owned(&ec_group).unwrap();
        let private_key = PKey::from_ec_key(ec_key).unwrap();

        test_private_key_conversion_pkcs(&private_key, Id::EC, key_size, KeyFormatType::PKCS8);
        test_private_key_conversion_sec1(&private_key, Id::EC, key_size);

        test_private_key_conversion_transparent_ec(
            &private_key,
            Some(&ec_public_key),
            Some(&ec_group),
            RecommendedCurve::P384,
            Id::EC,
            key_size,
        );
    }

    #[test]
    fn test_conversion_ec_p_521_private_key() {
        log_init(option_env!("RUST_LOG"));

        #[cfg(not(feature = "non-fips"))]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 521;
        let ec_group = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
        let ec_key = EcKey::generate(&ec_group).unwrap();
        let ec_public_key = ec_key.public_key().to_owned(&ec_group).unwrap();
        let private_key = PKey::from_ec_key(ec_key).unwrap();

        test_private_key_conversion_pkcs(&private_key, Id::EC, key_size, KeyFormatType::PKCS8);
        test_private_key_conversion_sec1(&private_key, Id::EC, key_size);

        test_private_key_conversion_transparent_ec(
            &private_key,
            Some(&ec_public_key),
            Some(&ec_group),
            RecommendedCurve::P521,
            Id::EC,
            key_size,
        );
    }

    #[test]
    #[cfg(feature = "non-fips")]
    fn test_conversion_ec_x25519_private_key() {
        log_init(option_env!("RUST_LOG"));

        let key_size = 253;
        let private_key = PKey::generate_x25519().unwrap();

        test_private_key_conversion_pkcs(&private_key, Id::X25519, key_size, KeyFormatType::PKCS8);
        test_private_key_conversion_transparent_ec(
            &private_key,
            None,
            None,
            RecommendedCurve::CURVE25519,
            Id::X25519,
            key_size,
        );
    }

    #[test]
    fn test_conversion_ec_ed25519_private_key() {
        log_init(option_env!("RUST_LOG"));

        #[cfg(not(feature = "non-fips"))]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 256;
        let private_key = PKey::generate_ed25519().unwrap();

        test_private_key_conversion_pkcs(&private_key, Id::ED25519, key_size, KeyFormatType::PKCS8);
        test_private_key_conversion_transparent_ec(
            &private_key,
            None,
            None,
            RecommendedCurve::CURVEED25519,
            Id::ED25519,
            key_size,
        );
    }

    #[test]
    #[cfg(feature = "non-fips")]
    fn test_conversion_ec_x448_private_key() {
        log_init(option_env!("RUST_LOG"));

        let key_size = 448;
        let private_key = PKey::generate_x448().unwrap();

        test_private_key_conversion_pkcs(&private_key, Id::X448, key_size, KeyFormatType::PKCS8);
        test_private_key_conversion_transparent_ec(
            &private_key,
            None,
            None,
            RecommendedCurve::CURVE448,
            Id::X448,
            key_size,
        );
    }

    #[test]
    fn test_conversion_ec_ed448_private_key() {
        log_init(option_env!("RUST_LOG"));

        #[cfg(not(feature = "non-fips"))]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 456;
        let private_key = PKey::generate_ed448().unwrap();

        test_private_key_conversion_pkcs(&private_key, Id::ED448, key_size, KeyFormatType::PKCS8);
        test_private_key_conversion_transparent_ec(
            &private_key,
            None,
            None,
            RecommendedCurve::CURVEED448,
            Id::ED448,
            key_size,
        );
    }
}
