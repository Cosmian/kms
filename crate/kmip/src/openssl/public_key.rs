use num_bigint_dig::BigUint;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
    pkey::{Id, PKey, Public},
    rsa::Rsa,
};
use tracing::trace;
use zeroize::Zeroizing;

use crate::{
    error::{result::KmipResultHelper, KmipError},
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicDomainParameters,
            CryptographicUsageMask, KeyFormatType, RecommendedCurve,
        },
    },
    kmip_bail, kmip_error,
};

/// Convert a KMIP Public key to openssl `PKey<Public>`
///
/// The supported `KeyFormatType` are:
/// * PKCS1
/// * PKCS8: actually a SPKI DER (RFC 5480)
/// * `TransparentRSAPublicKey`
/// * `TransparentECPublicKey`: only the following curves are supported:
///    * P192
///    * P224
///    * P256
///    * P384
///    * P521
///    * CURVE25519
///    * CURVE448
///    * CURVEED25519
///    * CURVEED448
///
/// For the NIST P-curves the `q_string` is expected to be the octet form (as defined in RFC5480 and used in certificates and TLS records):
/// only the content octets are present, the OCTET STRING tag and length are not included.
///
/// For the last 3 curves the `q_string` is expected to be the raw bytes of the public key.
///
/// # Arguments
///
/// * `public_key` - The KMIP Public key to convert
///
/// # Returns
///
/// * `PKey<Public>` - The openssl Public key
///
pub fn kmip_public_key_to_openssl(public_key: &Object) -> Result<PKey<Public>, KmipError> {
    trace!("kmip_public_key_to_openssl: {}", public_key);
    let key_block = match public_key {
        Object::PublicKey { key_block } => key_block,
        x => kmip_bail!("Invalid Object: {}. KMIP Public Key expected", x),
    };
    // Convert the key to the default storage format: SPKI DER (RFC 5480)
    let pk: PKey<Public> = match key_block.key_format_type {
        KeyFormatType::PKCS1 => {
            let key_bytes = key_block.key_bytes()?;
            // parse the RSA public key to make sure it is correct
            let rsa_public_key = Rsa::public_key_from_der_pkcs1(&key_bytes)?;
            PKey::from_rsa(rsa_public_key)?
        }
        // This really is a SPKI as specified by RFC 5480
        KeyFormatType::PKCS8 => {
            let key_bytes = key_block.key_bytes()?;
            // This key may be an RSA or EC key
            PKey::public_key_from_der(&key_bytes)?
        }
        KeyFormatType::TransparentRSAPublicKey => match &key_block.key_value.key_material {
            KeyMaterial::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            } => {
                trace!("Key format type: TransparentRSAPublicKey");
                let rsa_public_key = Rsa::from_public_components(
                    BigNum::from_slice(&modulus.to_bytes_be())?,
                    BigNum::from_slice(&public_exponent.to_bytes_be())?,
                )?;
                trace!("Key format type: convert Rsa<Public> openssl object");
                PKey::from_rsa(rsa_public_key)?
            }
            invalid_key_material => kmip_bail!(
                "Invalid Transparent RSA public key material: expected TransparentRSAPublicKey \
                 but got: {} ",
                invalid_key_material
            ),
        },
        KeyFormatType::TransparentECPublicKey => match &key_block.key_value.key_material {
            KeyMaterial::TransparentECPublicKey {
                recommended_curve,
                q_string,
            } => match recommended_curve {
                // P-CURVES
                #[cfg(not(feature = "fips"))]
                RecommendedCurve::P192 => {
                    ec_public_key_from_point_encoding(q_string, Nid::X9_62_PRIME192V1)?
                }
                RecommendedCurve::P224 => {
                    ec_public_key_from_point_encoding(q_string, Nid::SECP224R1)?
                }
                RecommendedCurve::P256 => {
                    ec_public_key_from_point_encoding(q_string, Nid::X9_62_PRIME256V1)?
                }
                RecommendedCurve::P384 => {
                    ec_public_key_from_point_encoding(q_string, Nid::SECP384R1)?
                }
                RecommendedCurve::P521 => {
                    ec_public_key_from_point_encoding(q_string, Nid::SECP521R1)?
                }

                RecommendedCurve::CURVE25519 => {
                    PKey::public_key_from_raw_bytes(q_string, Id::X25519)?
                }
                RecommendedCurve::CURVE448 => PKey::public_key_from_raw_bytes(q_string, Id::X448)?,
                RecommendedCurve::CURVEED25519 => {
                    PKey::public_key_from_raw_bytes(q_string, Id::ED25519)?
                }
                RecommendedCurve::CURVEED448 => {
                    PKey::public_key_from_raw_bytes(q_string, Id::ED448)?
                }
                unsupported_curve => {
                    kmip_bail!(
                        "Unsupported curve: {:?} for a Transparent EC Public Key",
                        unsupported_curve
                    )
                }
            },
            _ => kmip_bail!(
                "Invalid key material for a Transparent EC public key format: \
                 TransparentECPublicKey expected"
            ),
        },
        f => kmip_bail!(
            "Unsupported key format type: {f:?}, for tr transforming a {} to openssl",
            public_key.object_type()
        ),
    };
    Ok(pk)
}

/// Instantiate an openssl Public Key from the point (`EC_POINT`) encoding on a standardized curve
///
/// The encoding of the `ECPoint` structure is expected to be in the octet form
/// (as defined in RFC5480 and used in certificates and TLS records):
/// only the content octets are present, the OCTET STRING tag and length are not included.
/// The encoding/decoding conforms with Sec. 2.3.3/2.3.4 of the SECG SEC 1 ("Elliptic Curve Cryptography") standard.
fn ec_public_key_from_point_encoding(
    point_encoding: &[u8],
    curve_nid: Nid,
) -> Result<PKey<Public>, KmipError> {
    let group = EcGroup::from_curve_name(curve_nid)?;
    let mut ctx = BigNumContext::new()?;
    let ec_point = EcPoint::from_bytes(&group, point_encoding, &mut ctx)?;
    let key = EcKey::from_public_key(&group, &ec_point)?;
    key.check_key()?;
    Ok(PKey::from_ec_key(key)?)
}

/// Convert an openssl public key to a KMIP public Key (`Object::PublicKey`) of the given `KeyFormatType`
pub fn openssl_public_key_to_kmip(
    public_key: &PKey<Public>,
    key_format_type: KeyFormatType,
    cryptographic_usage_mask: Option<CryptographicUsageMask>,
) -> Result<Object, KmipError> {
    #[cfg(not(feature = "fips"))]
    // When not in FIPS mode, None defaults to Unrestricted.
    let cryptographic_usage_mask = if cryptographic_usage_mask.is_none() {
        Some(CryptographicUsageMask::Unrestricted)
    } else {
        cryptographic_usage_mask
    };

    let cryptographic_length = Some(i32::try_from(public_key.bits())?);
    let key_block = match key_format_type {
        KeyFormatType::PKCS1 => {
            let rsa_public_key = public_key
                .rsa()
                .context("The public key is not an openssl RSA public key")?;
            let cryptographic_length = Some(i32::try_from(rsa_public_key.size())? * 8);
            KeyBlock {
                key_format_type,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(Zeroizing::from(
                        rsa_public_key.public_key_to_der_pkcs1()?,
                    )),
                    attributes: Some(Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                        cryptographic_length,
                        key_format_type: Some(KeyFormatType::PKCS1),
                        object_type: Some(ObjectType::PublicKey),
                        cryptographic_usage_mask,
                        ..Attributes::default()
                    }),
                },
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length,
                key_wrapping_data: None,
                key_compression_type: None,
            }
        }
        KeyFormatType::PKCS8 => {
            let spki_der = Zeroizing::from(public_key.public_key_to_der()?);
            let cryptographic_algorithm = match public_key.id() {
                Id::RSA => Some(CryptographicAlgorithm::RSA),
                Id::EC | Id::X25519 | Id::X448 => Some(CryptographicAlgorithm::ECDH),
                Id::ED25519 => Some(CryptographicAlgorithm::Ed25519),
                Id::ED448 => Some(CryptographicAlgorithm::Ed448),
                _ => None,
            };
            KeyBlock {
                key_format_type,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(spki_der),
                    attributes: Some(Attributes {
                        cryptographic_algorithm,
                        cryptographic_length,
                        key_format_type: Some(KeyFormatType::PKCS8),
                        object_type: Some(ObjectType::PublicKey),
                        cryptographic_usage_mask,
                        ..Attributes::default()
                    }),
                },
                cryptographic_algorithm,
                cryptographic_length,
                key_wrapping_data: None,
                key_compression_type: None,
            }
        }
        KeyFormatType::TransparentRSAPublicKey => {
            let rsa_public_key = public_key
                .rsa()
                .context("The public key is not an openssl RSA public key")?;
            KeyBlock {
                key_format_type,
                key_value: KeyValue {
                    key_material: KeyMaterial::TransparentRSAPublicKey {
                        modulus: Box::new(BigUint::from_bytes_be(&rsa_public_key.n().to_vec())),
                        public_exponent: Box::new(BigUint::from_bytes_be(
                            &rsa_public_key.e().to_vec(),
                        )),
                    },
                    attributes: Some(Attributes {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                        cryptographic_length,
                        key_format_type: Some(KeyFormatType::TransparentRSAPublicKey),
                        object_type: Some(ObjectType::PublicKey),
                        cryptographic_usage_mask,
                        ..Attributes::default()
                    }),
                },
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length,
                key_wrapping_data: None,
                key_compression_type: None,
            }
        }
        KeyFormatType::TransparentECPublicKey => {
            match public_key.id() {
                Id::EC => {
                    let ec_key = public_key
                        .ec_key()
                        .context("The public key is not an openssl EC public key")?;
                    let group = ec_key.group();
                    let mut ctx = BigNumContext::new()?;
                    // Octet form (as defined in RFC5480 and used in certificates and TLS records):
                    let point_encoding = ec_key.public_key().to_bytes(
                        group,
                        PointConversionForm::UNCOMPRESSED,
                        &mut ctx,
                    )?;
                    let recommended_curve = match group
                        .curve_name()
                        .ok_or_else(|| kmip_error!("The EC group has no curve name"))?
                    {
                        // P-CURVES
                        #[cfg(not(feature = "fips"))]
                        Nid::X9_62_PRIME192V1 => RecommendedCurve::P192,
                        Nid::SECP224R1 => RecommendedCurve::P224,
                        Nid::X9_62_PRIME256V1 => RecommendedCurve::P256,
                        Nid::SECP384R1 => RecommendedCurve::P384,
                        Nid::SECP521R1 => RecommendedCurve::P521,
                        unsupported_curve => {
                            kmip_bail!(
                                "Unsupported curve: {:?} for a Transparent EC Public Key",
                                unsupported_curve
                            )
                        }
                    };
                    KeyBlock {
                        key_format_type,
                        key_value: KeyValue {
                            key_material: KeyMaterial::TransparentECPublicKey {
                                recommended_curve,
                                q_string: point_encoding,
                            },
                            attributes: Some(Attributes {
                                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                                cryptographic_length,
                                key_format_type: Some(KeyFormatType::TransparentECPublicKey),
                                object_type: Some(ObjectType::PublicKey),
                                cryptographic_domain_parameters: Some(
                                    CryptographicDomainParameters {
                                        recommended_curve: Some(recommended_curve),
                                        ..CryptographicDomainParameters::default()
                                    },
                                ),
                                cryptographic_usage_mask,
                                ..Attributes::default()
                            }),
                        },
                        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                        cryptographic_length,
                        key_wrapping_data: None,
                        key_compression_type: None,
                    }
                }
                Id::X25519 => {
                    let q_string = public_key.raw_public_key()?;
                    KeyBlock {
                        key_format_type,
                        key_value: KeyValue {
                            key_material: KeyMaterial::TransparentECPublicKey {
                                recommended_curve: RecommendedCurve::CURVE25519,
                                q_string,
                            },
                            attributes: Some(Attributes {
                                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                                cryptographic_length,
                                key_format_type: Some(KeyFormatType::TransparentECPublicKey),
                                object_type: Some(ObjectType::PublicKey),
                                cryptographic_domain_parameters: Some(
                                    CryptographicDomainParameters {
                                        recommended_curve: Some(RecommendedCurve::CURVE25519),
                                        ..CryptographicDomainParameters::default()
                                    },
                                ),
                                cryptographic_usage_mask,
                                ..Attributes::default()
                            }),
                        },
                        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                        cryptographic_length,
                        key_wrapping_data: None,
                        key_compression_type: None,
                    }
                }
                Id::ED25519 => {
                    let q_string = public_key.raw_public_key()?;
                    KeyBlock {
                        key_format_type,
                        key_value: KeyValue {
                            key_material: KeyMaterial::TransparentECPublicKey {
                                recommended_curve: RecommendedCurve::CURVEED25519,
                                q_string,
                            },
                            attributes: Some(Attributes {
                                cryptographic_algorithm: Some(CryptographicAlgorithm::Ed25519),
                                cryptographic_length,
                                key_format_type: Some(KeyFormatType::TransparentECPublicKey),
                                object_type: Some(ObjectType::PublicKey),
                                cryptographic_domain_parameters: Some(
                                    CryptographicDomainParameters {
                                        recommended_curve: Some(RecommendedCurve::CURVEED25519),
                                        ..CryptographicDomainParameters::default()
                                    },
                                ),
                                cryptographic_usage_mask,
                                ..Attributes::default()
                            }),
                        },
                        cryptographic_algorithm: Some(CryptographicAlgorithm::Ed25519),
                        cryptographic_length,
                        key_wrapping_data: None,
                        key_compression_type: None,
                    }
                }
                Id::X448 => {
                    let q_string = public_key.raw_public_key()?;
                    KeyBlock {
                        key_format_type,
                        key_value: KeyValue {
                            key_material: KeyMaterial::TransparentECPublicKey {
                                recommended_curve: RecommendedCurve::CURVE448,
                                q_string,
                            },
                            attributes: Some(Attributes {
                                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                                cryptographic_length,
                                key_format_type: Some(KeyFormatType::TransparentECPublicKey),
                                object_type: Some(ObjectType::PublicKey),
                                cryptographic_domain_parameters: Some(
                                    CryptographicDomainParameters {
                                        recommended_curve: Some(RecommendedCurve::CURVE448),
                                        ..CryptographicDomainParameters::default()
                                    },
                                ),
                                cryptographic_usage_mask,
                                ..Attributes::default()
                            }),
                        },
                        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                        cryptographic_length,
                        key_wrapping_data: None,
                        key_compression_type: None,
                    }
                }
                Id::ED448 => {
                    let q_string = public_key.raw_public_key()?;
                    KeyBlock {
                        key_format_type,
                        key_value: KeyValue {
                            key_material: KeyMaterial::TransparentECPublicKey {
                                recommended_curve: RecommendedCurve::CURVEED448,
                                q_string,
                            },
                            attributes: Some(Attributes {
                                cryptographic_algorithm: Some(CryptographicAlgorithm::Ed448),
                                cryptographic_length,
                                key_format_type: Some(KeyFormatType::TransparentECPublicKey),
                                object_type: Some(ObjectType::PublicKey),
                                cryptographic_domain_parameters: Some(
                                    CryptographicDomainParameters {
                                        recommended_curve: Some(RecommendedCurve::CURVEED448),
                                        ..CryptographicDomainParameters::default()
                                    },
                                ),
                                cryptographic_usage_mask,
                                ..Attributes::default()
                            }),
                        },
                        cryptographic_algorithm: Some(CryptographicAlgorithm::Ed448),
                        cryptographic_length,
                        key_wrapping_data: None,
                        key_compression_type: None,
                    }
                }
                x => kmip_bail!("Unsupported curve key id: {x:?} for a Transparent EC Public Key"),
            }
        }
        kft => kmip_bail!("Unsupported target key format type: {kft:?}, for an openssl public key"),
    };

    Ok(Object::PublicKey { key_block })
}

#[allow(clippy::unwrap_used, clippy::panic, clippy::as_conversions)]
#[cfg(test)]
mod tests {
    use openssl::{
        bn::{BigNum, BigNumContext},
        ec::{EcGroup, EcKey, EcPoint},
        nid::Nid,
        pkey::{Id, PKey, Public},
        rsa::Rsa,
    };

    #[cfg(feature = "fips")]
    use crate::crypto::{
        elliptic_curves::FIPS_PUBLIC_ECC_MASK_SIGN_ECDH, rsa::FIPS_PUBLIC_RSA_MASK,
    };
    #[cfg(not(feature = "fips"))]
    use crate::kmip::kmip_types::CryptographicUsageMask;
    use crate::{
        kmip::{
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::Object,
            kmip_types::{KeyFormatType, RecommendedCurve},
        },
        openssl::{kmip_public_key_to_openssl, public_key::openssl_public_key_to_kmip},
    };

    fn test_public_key_conversion_pkcs(
        public_key: &PKey<Public>,
        id: Id,
        key_size: u32,
        kft: KeyFormatType,
    ) {
        #[cfg(feature = "fips")]
        let mask = Some(FIPS_PUBLIC_RSA_MASK);
        #[cfg(not(feature = "fips"))]
        let mask = Some(CryptographicUsageMask::Unrestricted);

        // SPKI (== KMIP PKCS#8)
        let object = openssl_public_key_to_kmip(public_key, kft, mask).unwrap();
        let object_ = object.clone();
        let Object::PublicKey { key_block } = object else {
            panic!("Invalid key block")
        };
        let KeyBlock {
            key_value:
                KeyValue {
                    key_material: KeyMaterial::ByteString(key_value),
                    ..
                },
            ..
        } = key_block
        else {
            panic!("Invalid key block")
        };
        let public_key_ = if kft == KeyFormatType::PKCS8 {
            PKey::public_key_from_der(&key_value).unwrap()
        } else {
            PKey::from_rsa(Rsa::public_key_from_der_pkcs1(&key_value).unwrap()).unwrap()
        };
        assert_eq!(public_key_.id(), id);
        assert_eq!(public_key_.bits(), key_size);
        if kft == KeyFormatType::PKCS8 {
            assert_eq!(public_key_.public_key_to_der().unwrap(), key_value.to_vec());
        } else {
            assert_eq!(
                public_key_
                    .rsa()
                    .unwrap()
                    .public_key_to_der_pkcs1()
                    .unwrap(),
                key_value.to_vec()
            );
        }
        let public_key_ = kmip_public_key_to_openssl(&object_).unwrap();
        assert_eq!(public_key_.bits(), key_size);
        if kft == KeyFormatType::PKCS8 {
            assert_eq!(public_key_.public_key_to_der().unwrap(), key_value.to_vec());
        } else {
            assert_eq!(
                public_key_
                    .rsa()
                    .unwrap()
                    .public_key_to_der_pkcs1()
                    .unwrap(),
                key_value.to_vec()
            );
        }
    }

    fn test_public_key_conversion_transparent_rsa(
        public_key: &PKey<Public>,
        id: Id,
        key_size: u32,
    ) {
        #[cfg(feature = "fips")]
        let mask = Some(FIPS_PUBLIC_RSA_MASK);
        #[cfg(not(feature = "fips"))]
        let mask = Some(CryptographicUsageMask::Unrestricted);

        // Transparent RSA
        let object =
            openssl_public_key_to_kmip(public_key, KeyFormatType::TransparentRSAPublicKey, mask)
                .unwrap();
        let object_ = object.clone();
        let Object::PublicKey { key_block } = object else {
            panic!("Invalid key block")
        };
        let KeyBlock {
            key_value:
                KeyValue {
                    key_material:
                        KeyMaterial::TransparentRSAPublicKey {
                            modulus,
                            public_exponent,
                        },
                    ..
                },
            ..
        } = key_block
        else {
            panic!("Invalid key block")
        };
        let public_key_ = PKey::from_rsa(
            Rsa::from_public_components(
                BigNum::from_slice(&modulus.to_bytes_be()).unwrap(),
                BigNum::from_slice(&public_exponent.to_bytes_be()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(public_key_.id(), id);
        assert_eq!(public_key_.bits(), key_size);
        assert_eq!(
            public_key.public_key_to_der().unwrap(),
            public_key_.public_key_to_der().unwrap()
        );
        let public_key_ = kmip_public_key_to_openssl(&object_).unwrap();
        assert_eq!(public_key_.id(), id);
        assert_eq!(public_key_.bits(), key_size);
        assert_eq!(
            public_key.public_key_to_der().unwrap(),
            public_key_.public_key_to_der().unwrap()
        );
    }

    fn test_public_key_conversion_transparent_ec(
        public_key: &PKey<Public>,
        ec_group: Option<&EcGroup>,
        curve: RecommendedCurve,
        id: Id,
        key_size: u32,
    ) {
        // Transparent EC.
        #[cfg(feature = "fips")]
        let mask = Some(FIPS_PUBLIC_ECC_MASK_SIGN_ECDH);
        #[cfg(not(feature = "fips"))]
        let mask = Some(CryptographicUsageMask::Unrestricted);
        let object =
            openssl_public_key_to_kmip(public_key, KeyFormatType::TransparentECPublicKey, mask)
                .unwrap();
        let object_ = object.clone();
        let Object::PublicKey { key_block } = object else {
            panic!("Invalid key block")
        };

        let KeyBlock {
            key_value:
                KeyValue {
                    key_material:
                        KeyMaterial::TransparentECPublicKey {
                            q_string,
                            recommended_curve,
                        },
                    ..
                },
            ..
        } = key_block
        else {
            panic!("Invalid key block")
        };
        assert_eq!(recommended_curve, curve);

        if id == Id::EC {
            let ec_point = EcPoint::from_bytes(
                ec_group.unwrap(),
                q_string.as_slice(),
                &mut BigNumContext::new().unwrap(),
            )
            .unwrap();
            let ec_public_key = EcKey::from_public_key(ec_group.unwrap(), &ec_point).unwrap();
            let public_key_ = PKey::from_ec_key(ec_public_key).unwrap();

            assert_eq!(public_key_.id(), id);
            assert_eq!(public_key_.bits(), key_size);
            assert_eq!(
                public_key.public_key_to_der().unwrap(),
                public_key_.public_key_to_der().unwrap()
            );
            let public_key_ = kmip_public_key_to_openssl(&object_).unwrap();
            assert_eq!(public_key_.id(), id);
            assert_eq!(public_key_.bits(), key_size);
            assert_eq!(
                public_key.public_key_to_der().unwrap(),
                public_key_.public_key_to_der().unwrap()
            );
        } else {
            let public_key_ = PKey::public_key_from_raw_bytes(&q_string, id).unwrap();
            assert_eq!(public_key_.id(), id);
            assert_eq!(public_key_.bits(), key_size);
            assert_eq!(
                public_key.raw_public_key().unwrap(),
                public_key_.raw_public_key().unwrap()
            );
            let public_key_ = kmip_public_key_to_openssl(&object_).unwrap();
            assert_eq!(public_key_.id(), id);
            assert_eq!(public_key_.bits(), key_size);
            assert_eq!(
                public_key.raw_public_key().unwrap(),
                public_key_.raw_public_key().unwrap()
            );
        }
    }

    #[test]
    fn test_conversion_rsa_public_key() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 2048;
        let rsa_private_key = Rsa::generate(key_size).unwrap();
        let rsa_public_key = Rsa::from_public_components(
            rsa_private_key.n().to_owned().unwrap(),
            rsa_private_key.e().to_owned().unwrap(),
        )
        .unwrap();
        let public_key = PKey::from_rsa(rsa_public_key).unwrap();

        test_public_key_conversion_pkcs(&public_key, Id::RSA, key_size, KeyFormatType::PKCS8);
        test_public_key_conversion_pkcs(&public_key, Id::RSA, key_size, KeyFormatType::PKCS1);
        test_public_key_conversion_transparent_rsa(&public_key, Id::RSA, key_size);
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_conversion_ec_p_192_public_key() {
        let key_size = 192;
        let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME192V1).unwrap();
        let ec_key = EcKey::generate(&ec_group).unwrap();

        let ec_point = ec_key.public_key().to_owned(&ec_group).unwrap();
        let ec_public_key = EcKey::from_public_key(&ec_group, &ec_point).unwrap();

        let public_key = PKey::from_ec_key(ec_public_key).unwrap();

        test_public_key_conversion_pkcs(&public_key, Id::EC, key_size, KeyFormatType::PKCS8);

        test_public_key_conversion_transparent_ec(
            &public_key,
            Some(&ec_group),
            RecommendedCurve::P192,
            Id::EC,
            key_size,
        );
    }

    #[test]
    fn test_conversion_ec_p_224_public_key() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 224;
        let ec_group = EcGroup::from_curve_name(Nid::SECP224R1).unwrap();
        let ec_key = EcKey::generate(&ec_group).unwrap();

        let ec_point = ec_key.public_key().to_owned(&ec_group).unwrap();
        let ec_public_key = EcKey::from_public_key(&ec_group, &ec_point).unwrap();

        let public_key = PKey::from_ec_key(ec_public_key).unwrap();

        test_public_key_conversion_pkcs(&public_key, Id::EC, key_size, KeyFormatType::PKCS8);

        test_public_key_conversion_transparent_ec(
            &public_key,
            Some(&ec_group),
            RecommendedCurve::P224,
            Id::EC,
            key_size,
        );
    }

    #[test]
    fn test_conversion_ec_p_256_public_key() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 256;
        let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&ec_group).unwrap();

        let ec_point = ec_key.public_key().to_owned(&ec_group).unwrap();
        let ec_public_key = EcKey::from_public_key(&ec_group, &ec_point).unwrap();

        let public_key = PKey::from_ec_key(ec_public_key).unwrap();

        test_public_key_conversion_pkcs(&public_key, Id::EC, key_size, KeyFormatType::PKCS8);

        test_public_key_conversion_transparent_ec(
            &public_key,
            Some(&ec_group),
            RecommendedCurve::P256,
            Id::EC,
            key_size,
        );
    }

    #[test]
    fn test_conversion_ec_p_384_public_key() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 384;
        let ec_group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let ec_key = EcKey::generate(&ec_group).unwrap();

        let ec_point = ec_key.public_key().to_owned(&ec_group).unwrap();
        let ec_public_key = EcKey::from_public_key(&ec_group, &ec_point).unwrap();

        let public_key = PKey::from_ec_key(ec_public_key).unwrap();

        test_public_key_conversion_pkcs(&public_key, Id::EC, key_size, KeyFormatType::PKCS8);

        test_public_key_conversion_transparent_ec(
            &public_key,
            Some(&ec_group),
            RecommendedCurve::P384,
            Id::EC,
            key_size,
        );
    }

    #[test]
    fn test_conversion_ec_p_521_public_key() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 521;
        let ec_group = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
        let ec_key = EcKey::generate(&ec_group).unwrap();

        let ec_point = ec_key.public_key().to_owned(&ec_group).unwrap();
        let ec_public_key = EcKey::from_public_key(&ec_group, &ec_point).unwrap();

        let public_key = PKey::from_ec_key(ec_public_key).unwrap();

        test_public_key_conversion_pkcs(&public_key, Id::EC, key_size, KeyFormatType::PKCS8);

        test_public_key_conversion_transparent_ec(
            &public_key,
            Some(&ec_group),
            RecommendedCurve::P521,
            Id::EC,
            key_size,
        );
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_conversion_ec_x25519_public_key() {
        let key_size = 253;
        let private_key = PKey::generate_x25519().unwrap();
        let public_key =
            PKey::public_key_from_raw_bytes(&private_key.raw_public_key().unwrap(), Id::X25519)
                .unwrap();

        test_public_key_conversion_pkcs(&public_key, Id::X25519, key_size, KeyFormatType::PKCS8);
        test_public_key_conversion_transparent_ec(
            &public_key,
            None,
            RecommendedCurve::CURVE25519,
            Id::X25519,
            key_size,
        );
    }

    #[test]
    fn test_conversion_ec_ed25519_public_key() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 256;
        let private_key = PKey::generate_ed25519().unwrap();
        let public_key =
            PKey::public_key_from_raw_bytes(&private_key.raw_public_key().unwrap(), Id::ED25519)
                .unwrap();

        test_public_key_conversion_pkcs(&public_key, Id::ED25519, key_size, KeyFormatType::PKCS8);
        test_public_key_conversion_transparent_ec(
            &public_key,
            None,
            RecommendedCurve::CURVEED25519,
            Id::ED25519,
            key_size,
        );
    }

    #[test]
    #[cfg(not(feature = "fips"))]
    fn test_conversion_ec_x448_public_key() {
        let key_size = 448;
        let private_key = PKey::generate_x448().unwrap();
        let public_key =
            PKey::public_key_from_raw_bytes(&private_key.raw_public_key().unwrap(), Id::X448)
                .unwrap();

        test_public_key_conversion_pkcs(&public_key, Id::X448, key_size, KeyFormatType::PKCS8);
        test_public_key_conversion_transparent_ec(
            &public_key,
            None,
            RecommendedCurve::CURVE448,
            Id::X448,
            key_size,
        );
    }

    #[test]
    fn test_conversion_ec_ed448_public_key() {
        #[cfg(feature = "fips")]
        // Load FIPS provider module from OpenSSL.
        openssl::provider::Provider::load(None, "fips").unwrap();

        let key_size = 456;
        let private_key = PKey::generate_ed448().unwrap();
        let public_key =
            PKey::public_key_from_raw_bytes(&private_key.raw_public_key().unwrap(), Id::ED448)
                .unwrap();

        test_public_key_conversion_pkcs(&public_key, Id::ED448, key_size, KeyFormatType::PKCS8);
        test_public_key_conversion_transparent_ec(
            &public_key,
            None,
            RecommendedCurve::CURVEED448,
            Id::ED448,
            key_size,
        );
    }
}
