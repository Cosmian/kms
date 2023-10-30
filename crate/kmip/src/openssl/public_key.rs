use num_bigint::BigUint;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
    pkey::{Id, PKey, Public},
    rsa::Rsa,
};

use crate::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::Object,
        kmip_types::{CryptographicAlgorithm, KeyFormatType, RecommendedCurve},
    },
    kmip_bail, kmip_error,
    result::KmipResultHelper,
};

/// Convert a KMIP Public key to openssl `PKey<Public>`
///
/// The supported `KeyFormatType` are:
/// * PKCS1
/// * PKCS8: actually a SPKI DER (RFC 5480)
/// * TransparentRSAPublicKey
/// * TransparentECPublicKey: only the following curves are supported:
///    * P192
///    * P224
///    * P256
///    * P384
///    * P521
///    * CURVE25519
///    * CURVE448
///    * CURVEED25519
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
    let key_block = match public_key {
        Object::PublicKey { key_block } => key_block,
        x => kmip_bail!("Invalid Object: {:?}. KMIP Public Key expected", x),
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
                let rsa_public_key = Rsa::from_public_components(
                    BigNum::from_slice(&modulus.to_bytes_be())?,
                    BigNum::from_slice(&public_exponent.to_bytes_be())?,
                )?;
                PKey::from_rsa(rsa_public_key)?
            }
            _ => kmip_bail!(
                "Invalid Transparent RSA public key material: TransparentRSAPublicKey expected"
            ),
        },
        KeyFormatType::TransparentECPublicKey => match &key_block.key_value.key_material {
            KeyMaterial::TransparentECPublicKey {
                recommended_curve,
                q_string,
            } => match recommended_curve {
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
            "Unsupported key format type: {:?}, for a Transparent EC public key",
            f
        ),
    };
    Ok(pk)
}

/// Instantiate an openssl Public Key from the point (EC_POINT) encoding on a standardized curve
///
/// The encoding of the ECPoint structure is expected to be in the octet form  
/// (as defined in RFC5480 and used in certificates and TLS records):
/// only the content octets are present, the OCTET STRING tag and length are not included.
/// The encoding/decoding conforms with Sec. 2.3.3/2.3.4 of the SECG SEC 1 (“Elliptic Curve Cryptography”) standard.
fn ec_public_key_from_point_encoding(
    point_encoding: &[u8],
    curve_nid: Nid,
) -> Result<PKey<Public>, KmipError> {
    let group = EcGroup::from_curve_name(curve_nid)?;
    let mut ctx = BigNumContext::new()?;
    //# EcKey::generate(&group)?.public_key().to_bytes(&group,
    //# PointConversionForm::COMPRESSED, &mut ctx)?;
    let ec_point = EcPoint::from_bytes(&group, point_encoding, &mut ctx)?;
    let key = EcKey::from_public_key(&group, &ec_point)?;
    key.check_key()?;
    Ok(PKey::from_ec_key(key)?)
}

/// Convert an openssl public key to a KMIP public Key (`Object::PublicKey`) of the given `KeyFormatType`
pub fn openssl_public_key_to_kmip(
    public_key: &PKey<Public>,
    key_format_type: KeyFormatType,
) -> Result<Object, KmipError> {
    let key_block = match key_format_type {
        KeyFormatType::PKCS1 => {
            let rsa_public_key = public_key
                .rsa()
                .context("The public key is not an openssl RSA public key")?;
            KeyBlock {
                key_format_type,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(
                        rsa_public_key.public_key_to_der_pkcs1()?,
                    ),
                    attributes: None,
                },
                cryptographic_algorithm: None,
                cryptographic_length: None,
                key_wrapping_data: None,
                key_compression_type: None,
            }
        }
        KeyFormatType::PKCS8 => {
            let spki_der = public_key.public_key_to_der()?;
            KeyBlock {
                key_format_type,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(spki_der),
                    attributes: None,
                },
                cryptographic_algorithm: None,
                cryptographic_length: None,
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
                        modulus: BigUint::from_bytes_be(&rsa_public_key.n().to_vec()),
                        public_exponent: BigUint::from_bytes_be(&rsa_public_key.e().to_vec()),
                    },
                    attributes: None,
                },
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: Some(public_key.bits() as i32),
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
                            attributes: None,
                        },
                        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                        cryptographic_length: Some(public_key.bits() as i32),
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
                            attributes: None,
                        },
                        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                        cryptographic_length: Some(public_key.bits() as i32),
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
                            attributes: None,
                        },
                        cryptographic_algorithm: Some(CryptographicAlgorithm::Ed25519),
                        cryptographic_length: Some(public_key.bits() as i32),
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
                            attributes: None,
                        },
                        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
                        cryptographic_length: Some(public_key.bits() as i32),
                        key_wrapping_data: None,
                        key_compression_type: None,
                    }
                }
                x => kmip_bail!(
                    "Unsupported curve key id: {:?} for a Transparent EC Public Key",
                    x
                ),
            }
        }
        kft => kmip_bail!(
            "Unsupported key format type: {:?}, for a Transparent EC public key",
            kft
        ),
    };

    Ok(Object::PublicKey { key_block })
}

#[cfg(test)]
mod tests {

    use openssl::{
        bn::{BigNum, BigNumContext},
        ec::{EcGroup, EcKey, EcPoint},
        pkey::{Id, PKey},
        rsa::Rsa,
    };

    use crate::{
        kmip::{
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::Object,
            kmip_types::{KeyFormatType, RecommendedCurve},
        },
        openssl::{kmip_public_key_to_openssl, public_key::openssl_public_key_to_kmip},
    };

    #[test]
    fn test_rsa_public_key() {
        let rsa_private_key = Rsa::generate(2048).unwrap();
        let rsa_public_key = Rsa::from_public_components(
            rsa_private_key.n().to_owned().unwrap(),
            rsa_private_key.e().to_owned().unwrap(),
        )
        .unwrap();
        let public_key = PKey::from_rsa(rsa_public_key).unwrap();

        // SPKI (== KMIP PKCS#8)
        let object = openssl_public_key_to_kmip(&public_key, KeyFormatType::PKCS8).unwrap();
        let object_ = object.clone();
        let key_block = match object {
            Object::PublicKey { key_block } => key_block,
            _ => panic!("Invalid key block"),
        };
        let key_value = match key_block {
            KeyBlock {
                key_value:
                    KeyValue {
                        key_material: KeyMaterial::ByteString(key_value),
                        ..
                    },
                ..
            } => key_value,
            _ => panic!("Invalid key block"),
        };
        let public_key_ = PKey::public_key_from_der(&key_value).unwrap();
        assert_eq!(public_key_.id(), Id::RSA);
        assert_eq!(public_key_.bits(), 2048);
        assert_eq!(public_key_.public_key_to_der().unwrap(), key_value);
        let public_key_ = kmip_public_key_to_openssl(&object_).unwrap();
        assert_eq!(public_key_.id(), Id::RSA);
        assert_eq!(public_key_.bits(), 2048);
        assert_eq!(public_key_.public_key_to_der().unwrap(), key_value);

        // PKCS#1
        let object = openssl_public_key_to_kmip(&public_key, KeyFormatType::PKCS1).unwrap();
        let object_ = object.clone();
        let key_block = match object {
            Object::PublicKey { key_block } => key_block,
            _ => panic!("Invalid key block"),
        };
        let key_value = match key_block {
            KeyBlock {
                key_value:
                    KeyValue {
                        key_material: KeyMaterial::ByteString(key_value),
                        ..
                    },
                ..
            } => key_value,
            _ => panic!("Invalid key block"),
        };
        let public_key_ =
            PKey::from_rsa(Rsa::public_key_from_der_pkcs1(&key_value).unwrap()).unwrap();
        assert_eq!(public_key_.id(), Id::RSA);
        assert_eq!(public_key_.bits(), 2048);
        assert_eq!(
            public_key_
                .rsa()
                .unwrap()
                .public_key_to_der_pkcs1()
                .unwrap(),
            key_value
        );
        let public_key_ = kmip_public_key_to_openssl(&object_).unwrap();
        assert_eq!(public_key_.id(), Id::RSA);
        assert_eq!(public_key_.bits(), 2048);
        assert_eq!(
            public_key_
                .rsa()
                .unwrap()
                .public_key_to_der_pkcs1()
                .unwrap(),
            key_value
        );

        // Transparent RSA
        let object =
            openssl_public_key_to_kmip(&public_key, KeyFormatType::TransparentRSAPublicKey)
                .unwrap();
        let object_ = object.clone();
        let key_block = match object {
            Object::PublicKey { key_block } => key_block,
            _ => panic!("Invalid key block"),
        };
        let (modulus, public_exponent) = match key_block {
            KeyBlock {
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
            } => (modulus, public_exponent),
            _ => panic!("Invalid key block"),
        };
        let public_key_ = PKey::from_rsa(
            Rsa::from_public_components(
                BigNum::from_slice(&modulus.to_bytes_be()).unwrap(),
                BigNum::from_slice(&public_exponent.to_bytes_be()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(public_key_.id(), Id::RSA);
        assert_eq!(public_key_.bits(), 2048);
        let public_key_ = kmip_public_key_to_openssl(&object_).unwrap();
        assert_eq!(public_key_.id(), Id::RSA);
        assert_eq!(public_key_.bits(), 2048);
    }

    #[test]
    fn test_ec_p_256_public_key() {
        let ec_group = EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&ec_group).unwrap();
        let ec_point = ec_key.public_key().to_owned(&ec_group).unwrap();
        let ec_public_key = EcKey::from_public_key(&ec_group, &ec_point).unwrap();
        let public_key = PKey::from_ec_key(ec_public_key).unwrap();

        // SPKI (== KMIP PKCS#8)
        let object = openssl_public_key_to_kmip(&public_key, KeyFormatType::PKCS8).unwrap();
        let object_ = object.clone();
        let key_block = match object {
            Object::PublicKey { key_block } => key_block,
            _ => panic!("Invalid key block"),
        };
        let key_value = match key_block {
            KeyBlock {
                key_value:
                    KeyValue {
                        key_material: KeyMaterial::ByteString(key_value),
                        ..
                    },
                ..
            } => key_value,
            _ => panic!("Invalid key block"),
        };
        let public_key_ = PKey::public_key_from_der(&key_value).unwrap();
        assert_eq!(public_key_.id(), Id::EC);
        assert_eq!(public_key_.bits(), 256);
        assert_eq!(public_key_.public_key_to_der().unwrap(), key_value);
        let public_key_ = kmip_public_key_to_openssl(&object_).unwrap();
        assert_eq!(public_key_.id(), Id::EC);
        assert_eq!(public_key_.bits(), 256);
        assert_eq!(public_key_.public_key_to_der().unwrap(), key_value);

        // Transparent EC
        let object =
            openssl_public_key_to_kmip(&public_key, KeyFormatType::TransparentECPublicKey).unwrap();
        let object_ = object.clone();
        let key_block = match object {
            Object::PublicKey { key_block } => key_block,
            _ => panic!("Invalid key block"),
        };
        let (q_string, recommended_curve) = match key_block {
            KeyBlock {
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
            } => (q_string, recommended_curve),
            _ => panic!("Invalid key block"),
        };
        assert_eq!(recommended_curve, RecommendedCurve::P256);
        let ec_point = EcPoint::from_bytes(
            &ec_group,
            q_string.as_slice(),
            &mut BigNumContext::new().unwrap(),
        )
        .unwrap();
        let ec_public_key = EcKey::from_public_key(&ec_group, &ec_point).unwrap();
        let public_key_ = PKey::from_ec_key(ec_public_key).unwrap();
        assert_eq!(public_key_.id(), Id::EC);
        assert_eq!(public_key_.bits(), 256);
        let public_key_ = kmip_public_key_to_openssl(&object_).unwrap();
        assert_eq!(public_key_.id(), Id::EC);
        assert_eq!(public_key_.bits(), 256);
    }

    #[test]
    fn test_ec_x25519_public_key() {
        let private_key = PKey::generate_x25519().unwrap();
        let public_key_der = private_key.public_key_to_der().unwrap();
        let public_key = PKey::public_key_from_der(&public_key_der).unwrap();

        // PKCS#8
        let object = openssl_public_key_to_kmip(&public_key, KeyFormatType::PKCS8).unwrap();
        let object_ = object.clone();
        let key_block = match object {
            Object::PublicKey { key_block } => key_block,
            _ => panic!("Invalid key block"),
        };
        let key_value = match key_block {
            KeyBlock {
                key_value:
                    KeyValue {
                        key_material: KeyMaterial::ByteString(key_value),
                        ..
                    },
                ..
            } => key_value,
            _ => panic!("Invalid key block"),
        };
        let public_key_ = PKey::public_key_from_der(&key_value).unwrap();
        assert_eq!(public_key_.id(), Id::X25519);
        assert_eq!(public_key_.bits(), 253);
        assert_eq!(public_key_.public_key_to_der().unwrap(), key_value);
        let public_key_ = kmip_public_key_to_openssl(&object_).unwrap();
        assert_eq!(public_key_.id(), Id::X25519);
        assert_eq!(public_key_.bits(), 253);
        assert_eq!(public_key_.public_key_to_der().unwrap(), key_value);

        // Transparent EC
        let object =
            openssl_public_key_to_kmip(&public_key, KeyFormatType::TransparentECPublicKey).unwrap();
        let object_ = object.clone();
        let key_block = match object {
            Object::PublicKey { key_block } => key_block,
            _ => panic!("Invalid key block"),
        };
        let (q_string, recommended_curve) = match key_block {
            KeyBlock {
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
            } => (q_string, recommended_curve),
            _ => panic!("Invalid key block"),
        };
        assert_eq!(recommended_curve, RecommendedCurve::CURVE25519);
        let public_key_ = PKey::public_key_from_raw_bytes(&q_string, Id::X25519).unwrap();
        assert_eq!(public_key_.id(), Id::X25519);
        assert_eq!(public_key_.bits(), 253);
        let public_key_ = kmip_public_key_to_openssl(&object_).unwrap();
        assert_eq!(public_key_.id(), Id::X25519);
        assert_eq!(public_key_.bits(), 253);
    }
}
