use num_bigint::BigUint;
use openssl::{
    bn::BigNum,
    ec::EcKey,
    pkey::{Id, PKey, Private},
    rsa::{Rsa, RsaPrivateKeyBuilder},
};

use crate::{
    error::KmipError,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::Object,
        kmip_types::{CryptographicAlgorithm, KeyCompressionType, KeyFormatType, RecommendedCurve},
    },
    kmip_bail,
    result::KmipResultHelper,
};

/// Convert a KMIP Private key to openssl `PKey<Private>`
///
/// The supported `KeyFormatType` are:
/// * PKCS1
/// * ECPrivateKey (SEC1)
/// * PKCS8: actually a SPKI DER (RFC 5480)
/// * TransparentRSAPrivateKey
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
pub fn kmip_private_key_to_openssl(private_key: &Object) -> Result<PKey<Private>, KmipError> {
    let key_block = match private_key {
        Object::PrivateKey { key_block } => key_block,
        x => kmip_bail!("Invalid Object: {:?}. KMIP Private Key expected", x),
    };
    let pk: PKey<Private> = match key_block.key_format_type {
        KeyFormatType::PKCS1 => {
            let key_bytes = key_block.key_bytes()?;
            // parse the RSA private key to make sure it is correct
            let rsa_private_key = Rsa::private_key_from_der(&key_bytes)?;
            PKey::from_rsa(rsa_private_key)?
        }
        // This really is a SPKI as specified by RFC 5480
        KeyFormatType::PKCS8 => {
            let key_bytes = key_block.key_bytes()?;
            // This key may be an RSA or EC key
            PKey::private_key_from_der(&key_bytes)?
        }
        KeyFormatType::ECPrivateKey => {
            let key_bytes = key_block.key_bytes()?;
            // this is the (not so appropriate) value for SEC1
            let ec_key = EcKey::private_key_from_der(&key_bytes)?;
            ec_key.check_key()?;
            PKey::from_ec_key(ec_key)?
        }
        KeyFormatType::TransparentRSAPrivateKey => match &key_block.key_value.key_material {
            KeyMaterial::TransparentRSAPrivateKey {
                modulus,
                private_exponent,
                public_exponent,
                p,
                q,
                prime_exponent_p,
                prime_exponent_q,
                crt_coefficient,
            } => {
                let mut rsa_private_key_builder = RsaPrivateKeyBuilder::new(
                    BigNum::from_slice(&modulus.to_bytes_be())?,
                    BigNum::from_slice(
                        &public_exponent
                            .to_owned()
                            .context(
                                "the public exponent is required for Transparent RSA Private Keys",
                            )?
                            .to_bytes_be(),
                    )?,
                    BigNum::from_slice(
                        &private_exponent
                            .to_owned()
                            .context(
                                "the private exponent is required for Transparent RSA Private Keys",
                            )?
                            .to_bytes_be(),
                    )?,
                )?;
                if let Some(p) = p {
                    if let Some(q) = q {
                        rsa_private_key_builder = rsa_private_key_builder
                            .set_factors(
                                BigNum::from_slice(&p.to_owned().to_bytes_be())?,
                                BigNum::from_slice(&q.to_owned().to_bytes_be())?,
                            )
                            .context("Failed to set 'p' and 'q' on the RSA Private key")?;
                    }
                }
                if let Some(prime_exponent_p) = prime_exponent_p {
                    if let Some(prime_exponent_q) = prime_exponent_q {
                        if let Some(crt_coefficient) = crt_coefficient {
                            rsa_private_key_builder = rsa_private_key_builder
                                .set_crt_params(
                                    BigNum::from_slice(&prime_exponent_p.to_owned().to_bytes_be())?,
                                    BigNum::from_slice(&prime_exponent_q.to_owned().to_bytes_be())?,
                                    BigNum::from_slice(&crt_coefficient.to_owned().to_bytes_be())?,
                                )
                                .context("Failed to set CRT parameters on the RSA Private key")?;
                        }
                    }
                }
                let rsa_private_key = rsa_private_key_builder.build();
                PKey::from_rsa(rsa_private_key)?
            }
            _ => kmip_bail!(
                "Invalid Transparent RSA private key material: TransparentRSAPrivateKey expected"
            ),
        },
        KeyFormatType::TransparentECPrivateKey => match &key_block.key_value.key_material {
            KeyMaterial::TransparentECPrivateKey {
                d,
                recommended_curve,
            } => match recommended_curve {
                RecommendedCurve::CURVE25519 => {
                    PKey::private_key_from_raw_bytes(&d.to_bytes_be(), Id::X25519)?
                }
                RecommendedCurve::CURVE448 => {
                    PKey::private_key_from_raw_bytes(&d.to_bytes_be(), Id::X448)?
                }
                RecommendedCurve::CURVEED25519 => {
                    PKey::private_key_from_raw_bytes(&d.to_bytes_be(), Id::ED25519)?
                }
                RecommendedCurve::P192
                | RecommendedCurve::P224
                | RecommendedCurve::P256
                | RecommendedCurve::P384
                | RecommendedCurve::P521 => {
                    kmip_bail!("TransparentECPrivateKey: the curve: {:?} is not yet supported in this KMIP implementation. See https://github.com/sfackler/rust-openssl/issues/2075", recommended_curve)
                }
                x => kmip_bail!("Unsupported curve: {:?} in this KMIP implementation", x),
            },
            _ => kmip_bail!(
                "Invalid Transparent EC private key material: TransparentECPrivateKey expected"
            ),
        },
        f => kmip_bail!(
            "Unsupported key format type: {:?}, for a Transparent EC private key",
            f
        ),
    };
    Ok(pk)
}

/// Convert an openssl private key to a KMIP private Key (`Object::PrivateKey`) of the given `KeyFormatType`
pub fn openssl_private_key_to_kmip(
    private_key: &PKey<Private>,
    key_format_type: KeyFormatType,
) -> Result<Object, KmipError> {
    let key_block = match key_format_type {
        KeyFormatType::TransparentRSAPrivateKey => {
            let rsa_private_key = private_key
                .rsa()
                .context("the provided openssl key is not an RSA private key")?;
            let modulus = BigUint::from_bytes_be(rsa_private_key.n().to_vec().as_slice());
            let public_exponent = BigUint::from_bytes_be(rsa_private_key.e().to_vec().as_slice());
            let private_exponent = BigUint::from_bytes_be(rsa_private_key.d().to_vec().as_slice());
            let p = rsa_private_key
                .p()
                .map(|p| BigUint::from_bytes_be(p.to_vec().as_slice()));
            let q = rsa_private_key
                .q()
                .map(|q| BigUint::from_bytes_be(q.to_vec().as_slice()));
            let prime_exponent_p = rsa_private_key
                .dmp1()
                .map(|dmp1| BigUint::from_bytes_be(dmp1.to_vec().as_slice()));
            let prime_exponent_q = rsa_private_key
                .dmq1()
                .map(|dmpq1| BigUint::from_bytes_be(dmpq1.to_vec().as_slice()));
            let crt_coefficient = rsa_private_key
                .iqmp()
                .map(|iqmp| BigUint::from_bytes_be(iqmp.to_vec().as_slice()));
            KeyBlock {
                key_format_type,
                key_value: KeyValue {
                    key_material: KeyMaterial::TransparentRSAPrivateKey {
                        modulus,
                        private_exponent: Some(private_exponent),
                        public_exponent: Some(public_exponent),
                        p,
                        q,
                        prime_exponent_p,
                        prime_exponent_q,
                        crt_coefficient,
                    },
                    attributes: None,
                },
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: Some(private_key.bits() as i32),
                key_wrapping_data: None,
                key_compression_type: None,
            }
        }
        KeyFormatType::TransparentECPrivateKey => {
            let ec_key = private_key.ec_key().context(
                "the provided openssl key is not a standardized elliptic curve private key",
            )?;
            let d = BigUint::from_bytes_be(ec_key.private_key().to_vec().as_slice());
            let (recommended_curve, cryptographic_algorithm) = match private_key.id() {
                // This is likely a curve 25519 or 448 key (i.e. a non standardized curve)
                Id::EC => {
                    let recommended_curve = match ec_key.group().curve_name() {
                        Some(nid) => match nid {
                            openssl::nid::Nid::X9_62_PRIME192V1 => {
                                crate::kmip::kmip_types::RecommendedCurve::P192
                            }
                            openssl::nid::Nid::SECP224R1 => {
                                crate::kmip::kmip_types::RecommendedCurve::P224
                            }
                            openssl::nid::Nid::X9_62_PRIME256V1 => {
                                crate::kmip::kmip_types::RecommendedCurve::P256
                            }
                            openssl::nid::Nid::SECP384R1 => {
                                crate::kmip::kmip_types::RecommendedCurve::P384
                            }
                            openssl::nid::Nid::SECP521R1 => {
                                crate::kmip::kmip_types::RecommendedCurve::P521
                            }
                            _ => {
                                kmip_bail!(
                                    "Unsupported openssl curve: {:?} in this KMIP implementation",
                                    nid
                                );
                            }
                        },
                        None => {
                            kmip_bail!(
                                "Unsupported openssl curve: {:?} in this KMIP implementation",
                                ec_key.group().curve_name()
                            );
                        }
                    };
                    (recommended_curve, CryptographicAlgorithm::ECDH)
                }

                Id::X25519 => (RecommendedCurve::CURVE25519, CryptographicAlgorithm::ECDH),
                Id::X448 => (RecommendedCurve::CURVE448, CryptographicAlgorithm::ECDH),
                Id::ED25519 => (
                    RecommendedCurve::CURVEED25519,
                    CryptographicAlgorithm::Ed25519,
                ),
                x => kmip_bail!("Unsupported curve: {:?} in KMIP format", x),
            };
            KeyBlock {
                key_format_type,
                key_value: KeyValue {
                    key_material: KeyMaterial::TransparentECPrivateKey {
                        recommended_curve,
                        d,
                    },
                    attributes: None,
                },
                cryptographic_algorithm: Some(cryptographic_algorithm),
                cryptographic_length: Some(private_key.bits() as i32),
                key_wrapping_data: None,
                key_compression_type: Some(KeyCompressionType::ECPublicKeyTypeUncompressed),
            }
        }
        KeyFormatType::PKCS8 => KeyBlock {
            key_format_type,
            key_value: KeyValue {
                key_material: KeyMaterial::ByteString(private_key.private_key_to_pkcs8()?),
                attributes: None,
            },
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
            key_compression_type: None,
        },
        // This is SEC1
        KeyFormatType::ECPrivateKey => {
            let ec_key = private_key.ec_key()?;
            KeyBlock {
                key_format_type,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(ec_key.private_key_to_der()?),
                    attributes: None,
                },
                cryptographic_algorithm: None,
                cryptographic_length: None,
                key_wrapping_data: None,
                key_compression_type: None,
            }
        }
        KeyFormatType::PKCS1 => {
            let rsa_private_key = private_key.rsa()?;
            KeyBlock {
                key_format_type,
                key_value: KeyValue {
                    key_material: KeyMaterial::ByteString(rsa_private_key.private_key_to_der()?),
                    attributes: None,
                },
                cryptographic_algorithm: None,
                cryptographic_length: None,
                key_wrapping_data: None,
                key_compression_type: None,
            }
        }
        f => kmip_bail!(
            "Unsupported key format type: {:?}, for a KMIP private key",
            f
        ),
    };
    Ok(Object::PrivateKey { key_block })
}

#[cfg(test)]
mod tests {

    use openssl::{
        bn::BigNum,
        pkey::{Id, PKey, Private},
        rsa::Rsa,
    };

    use crate::{
        kmip::{
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::Object,
            kmip_types::{CryptographicAlgorithm, KeyFormatType},
        },
        openssl::{kmip_private_key_to_openssl, private_key::openssl_private_key_to_kmip},
    };

    #[test]
    fn test_rsa_private_key() {
        let rsa_private_key = Rsa::generate(2048).unwrap();
        let private_key = PKey::from_rsa(rsa_private_key).unwrap();

        // PKCS#8
        let object = openssl_private_key_to_kmip(&private_key, KeyFormatType::PKCS8).unwrap();
        let object_ = object.clone();
        let key_block = match object {
            Object::PrivateKey { key_block } => key_block,
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
        let private_key_ = PKey::private_key_from_pkcs8(&key_value).unwrap();
        assert_eq!(private_key_.id(), Id::RSA);
        assert_eq!(private_key_.bits(), 2048);
        assert_eq!(private_key_.private_key_to_pkcs8().unwrap(), key_value);
        let private_key_ = kmip_private_key_to_openssl(&object_).unwrap();
        assert_eq!(private_key_.id(), Id::RSA);
        assert_eq!(private_key_.bits(), 2048);
        assert_eq!(private_key_.private_key_to_pkcs8().unwrap(), key_value);

        // PKCS#1
        let object = openssl_private_key_to_kmip(&private_key, KeyFormatType::PKCS1).unwrap();
        let object_ = object.clone();
        let key_block = match object {
            Object::PrivateKey { key_block } => key_block,
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
        let private_key_ = PKey::from_rsa(Rsa::private_key_from_der(&key_value).unwrap()).unwrap();
        assert_eq!(private_key_.id(), Id::RSA);
        assert_eq!(private_key_.bits(), 2048);
        assert_eq!(private_key_.private_key_to_der().unwrap(), key_value);
        let private_key_ = kmip_private_key_to_openssl(&object_).unwrap();
        assert_eq!(private_key_.id(), Id::RSA);
        assert_eq!(private_key_.bits(), 2048);
        assert_eq!(private_key_.private_key_to_der().unwrap(), key_value);

        // Transparent RSA
        let object =
            openssl_private_key_to_kmip(&private_key, KeyFormatType::TransparentRSAPrivateKey)
                .unwrap();
        let object_ = object.clone();
        let key_block = match object {
            Object::PrivateKey { key_block } => key_block,
            _ => panic!("Invalid key block"),
        };
        let (
            modulus,
            private_exponent,
            public_exponent,
            p,
            q,
            prime_exponent_p,
            prime_exponent_q,
            crt_coefficient,
        ) = match key_block {
            KeyBlock {
                key_value:
                    KeyValue {
                        key_material:
                            KeyMaterial::TransparentRSAPrivateKey {
                                modulus,
                                private_exponent,
                                public_exponent,
                                p,
                                q,
                                prime_exponent_p,
                                prime_exponent_q,
                                crt_coefficient,
                            },
                        ..
                    },
                ..
            } => (
                modulus,
                private_exponent,
                public_exponent,
                p,
                q,
                prime_exponent_p,
                prime_exponent_q,
                crt_coefficient,
            ),
            _ => panic!("Invalid key block"),
        };
        let private_key_ = PKey::from_rsa(
            Rsa::from_private_components(
                BigNum::from_slice(&modulus.to_bytes_be()).unwrap(),
                BigNum::from_slice(&public_exponent.unwrap().to_bytes_be()).unwrap(),
                BigNum::from_slice(&private_exponent.unwrap().to_bytes_be()).unwrap(),
                BigNum::from_slice(&p.unwrap().to_bytes_be()).unwrap(),
                BigNum::from_slice(&q.unwrap().to_bytes_be()).unwrap(),
                BigNum::from_slice(&prime_exponent_p.unwrap().to_bytes_be()).unwrap(),
                BigNum::from_slice(&prime_exponent_q.unwrap().to_bytes_be()).unwrap(),
                BigNum::from_slice(&crt_coefficient.unwrap().to_bytes_be()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(private_key_.id(), Id::RSA);
        assert_eq!(private_key_.bits(), 2048);
        let private_key_ = kmip_private_key_to_openssl(&object_).unwrap();
        assert_eq!(private_key_.id(), Id::RSA);
        assert_eq!(private_key_.bits(), 2048);
    }

    #[test]
    fn test_ec_private_key() {}
}
