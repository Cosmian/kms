use num_bigint_dig::BigUint;
use serde::{
    de,
    de::{MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};
use time::OffsetDateTime;
use zeroize::Zeroizing;

#[allow(clippy::wildcard_imports)]
use super::kmip_types::*;
use crate::{kmip_2_1, SafeBigUint};

/// 2.1.2 Credential Object Structure
/// A Credential is a structure used to convey information used to authenticate a client
/// or server to the other party in a KMIP message. It contains credential type and
/// credential value fields.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Credential {
    pub credential_type: CredentialType,
    pub credential_value: CredentialValue,
}

/// Credential Value variants
/// The Credential Value type contains specific authentication credential values based
/// on the credential type.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum CredentialValue {
    UsernameAndPassword {
        username: String,
        password: String,
    },
    Device {
        device_serial_number: Option<String>,
        password: Option<String>,
        device_identifier: Option<String>,
        network_identifier: Option<String>,
        machine_identifier: Option<String>,
        media_identifier: Option<String>,
    },
    Attestation {
        nonce: Vec<u8>,
        attestation_measurement: Option<Vec<u8>>,
        attestation_assertion: Option<Vec<u8>>,
    },
}

/// 2.1.3 Key Block Object Structure
/// A Key Block object is a structure used to encapsulate all of the information that is
/// closely associated with a cryptographic key. It contains information about the format
/// of the key, the algorithm it supports, and its cryptographic length.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyBlock {
    pub key_format_type: KeyFormatType,
    pub key_compression_type: Option<KeyCompressionType>,
    pub key_value: KeyValue,
    pub cryptographic_algorithm: CryptographicAlgorithm,
    pub cryptographic_length: i32,
    pub key_wrapping_data: Option<KeyWrappingData>,
}

impl KeyBlock {
    pub fn to_kmip_2_1(&self) -> crate::kmip_2_1::kmip_data_structures::KeyBlock {
        kmip_2_1::kmip_data_structures::KeyBlock {
            key_format_type: self.key_format_type.to_kmip_2_1(),
            key_compression_type: self.key_compression_type.as_ref().map(|x| x.to_kmip_2_1()),
            key_value: self.key_value.to_kmip_2_1(),
            cryptographic_algorithm: self.cryptographic_algorithm,
            cryptographic_length: self.cryptographic_length,
            key_wrapping_data: self.key_wrapping_data.clone(),
        }
    }
}

/// 2.1.4 Key Value Object Structure
/// The Key Value object is a structure used to represent the key material and associated
/// attributes within a Key Block structure.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyValue {
    pub key_material: KeyMaterial,
    pub attributes: Option<Vec<Attribute>>,
}

impl KeyValue {
    pub fn to_kmip_2_1(&self) -> kmip_2_1::kmip_data_structures::KeyValue {
        kmip_2_1::kmip_data_structures::KeyValue {
            key_material: self.key_material.to_kmip_2_1(),
            attributes: self.attributes.clone(),
        }
    }
}

/// Private fields are represented using a Zeroizing object: either array of
/// bytes, or `SafeBigUint` type.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum KeyMaterial {
    TransparentSymmetricKey {
        key: Zeroizing<Vec<u8>>,
    },
    TransparentDSAPrivateKey {
        p: Box<BigUint>,
        q: Box<BigUint>,
        g: Box<BigUint>,
        x: Box<SafeBigUint>,
    },
    TransparentDSAPublicKey {
        p: Box<BigUint>,
        q: Box<BigUint>,
        g: Box<BigUint>,
        y: Box<BigUint>,
    },
    TransparentRSAPrivateKey {
        modulus: Box<BigUint>,
        private_exponent: Option<Box<SafeBigUint>>,
        public_exponent: Option<Box<BigUint>>,
        p: Option<Box<SafeBigUint>>,
        q: Option<Box<SafeBigUint>>,
        prime_exponent_p: Option<Box<SafeBigUint>>,
        prime_exponent_q: Option<Box<SafeBigUint>>,
        crt_coefficient: Option<Box<SafeBigUint>>,
    },
    TransparentRSAPublicKey {
        modulus: Box<BigUint>,
        public_exponent: Box<BigUint>,
    },
    TransparentDHPrivateKey {
        p: Box<BigUint>,
        q: Option<Box<BigUint>>,
        g: Box<BigUint>,
        j: Option<Box<BigUint>>,
        x: Box<SafeBigUint>,
    },
    TransparentDHPublicKey {
        p: Box<BigUint>,
        q: Option<Box<BigUint>>,
        g: Box<BigUint>,
        j: Option<Box<BigUint>>,
        y: Box<BigUint>,
    },
    TransparentECDSAPrivateKey {
        recommended_curve: RecommendedCurve,
        // big int in big endian format
        d: Box<SafeBigUint>,
    },
    TransparentECDSAPublicKey {
        recommended_curve: RecommendedCurve,
        q_string: Vec<u8>,
    },
    TransparentECDHPrivateKey {
        recommended_curve: RecommendedCurve,
        // big int in big endian format
        d: Box<SafeBigUint>,
    },
    TransparentECDHPublicKey {
        recommended_curve: RecommendedCurve,
        q_string: Vec<u8>,
    },
    TransparentECMQVPrivateKey {
        recommended_curve: RecommendedCurve,
        // big int in big endian format
        d: Box<SafeBigUint>,
    },
    TransparentECMQVPublicKey {
        recommended_curve: RecommendedCurve,
        q_string: Vec<u8>,
    },

    TransparentECPrivateKey {
        recommended_curve: RecommendedCurve,
        // big int in big endian format
        d: Box<SafeBigUint>,
    },
    TransparentECPublicKey {
        recommended_curve: RecommendedCurve,
        q_string: Vec<u8>,
    },
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize, Deserialize, Clone, Copy)]
enum KeyTypeSer {
    DH,
    DSA,
    RsaPublic,
    RsaPrivate,
    ECDSA,
    ECDH,
    ECMQV,
    EC,
}

impl Serialize for KeyMaterial {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::TransparentSymmetricKey { key } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 1)?;
                st.serialize_field("Key", &**key)?;
                st.end()
            }
            Self::TransparentDHPrivateKey { p, q, g, j, x } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 6)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::DH)?;
                st.serialize_field("P", &**p)?;
                if let Some(q) = q {
                    st.serialize_field("Q", &**q)?;
                };
                st.serialize_field("G", &**g)?;
                if let Some(j) = j {
                    st.serialize_field("J", &**j)?;
                };
                st.serialize_field("X", &***x)?;
                st.end()
            }
            Self::TransparentDHPublicKey { p, q, g, j, y } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 6)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::DH)?;
                st.serialize_field("P", &**p)?;
                if let Some(q) = q {
                    st.serialize_field("Q", &**q)?;
                };
                st.serialize_field("G", &**g)?;
                if let Some(j) = j {
                    st.serialize_field("J", &**j)?;
                };
                st.serialize_field("Y", &**y)?;
                st.end()
            }
            Self::TransparentDSAPrivateKey { p, q, g, x } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 5)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::DSA)?;
                st.serialize_field("P", &**p)?;
                st.serialize_field("Q", &**q)?;
                st.serialize_field("G", &**g)?;
                st.serialize_field("X", &***x)?;
                st.end()
            }
            Self::TransparentDSAPublicKey { p, q, g, y } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 5)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::DSA)?;
                st.serialize_field("P", &**p)?;
                st.serialize_field("Q", &**q)?;
                st.serialize_field("G", &**g)?;
                st.serialize_field("Y", &**y)?;
                st.end()
            }
            Self::TransparentRSAPrivateKey {
                modulus,
                private_exponent,
                public_exponent,
                p,
                q,
                prime_exponent_p,
                prime_exponent_q,
                crt_coefficient,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 9)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::RsaPrivate)?;
                st.serialize_field("Modulus", &**modulus)?;
                if let Some(private_exponent) = private_exponent {
                    st.serialize_field("PrivateExponent", &***private_exponent)?;
                };
                if let Some(public_exponent) = public_exponent {
                    st.serialize_field("PublicExponent", &**public_exponent)?;
                };
                if let Some(p) = p {
                    st.serialize_field("P", &***p)?;
                };
                if let Some(q) = q {
                    st.serialize_field("Q", &***q)?;
                };
                if let Some(prime_exponent_p) = prime_exponent_p {
                    st.serialize_field("PrimeExponentP", &***prime_exponent_p)?;
                };
                if let Some(prime_exponent_q) = prime_exponent_q {
                    st.serialize_field("PrimeExponentQ", &***prime_exponent_q)?;
                };
                if let Some(crt_coefficient) = crt_coefficient {
                    st.serialize_field("CrtCoefficient", &***crt_coefficient)?;
                };
                st.end()
            }
            Self::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::RsaPublic)?;
                st.serialize_field("Modulus", &**modulus)?;
                st.serialize_field("PublicExponent", &**public_exponent)?;
                st.end()
            }
            Self::TransparentECDSAPrivateKey {
                recommended_curve,
                d,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::ECDSA)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("D", &***d)?;
                st.end()
            }
            Self::TransparentECDSAPublicKey {
                recommended_curve,
                q_string,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::ECDSA)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("QString", q_string)?;
                st.end()
            }
            Self::TransparentECDHPrivateKey {
                recommended_curve,
                d,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::ECDH)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("D", &***d)?;
                st.end()
            }
            Self::TransparentECDHPublicKey {
                recommended_curve,
                q_string,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::ECDH)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("QString", q_string)?;
                st.end()
            }
            Self::TransparentECMQVPrivateKey {
                recommended_curve,
                d,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::ECMQV)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("D", &***d)?;
                st.end()
            }
            Self::TransparentECMQVPublicKey {
                recommended_curve,
                q_string,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::ECMQV)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("QString", q_string)?;
                st.end()
            }
            Self::TransparentECPrivateKey {
                recommended_curve,
                d,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::EC)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("D", &***d)?;
                st.end()
            }
            Self::TransparentECPublicKey {
                recommended_curve,
                q_string,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::EC)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("QString", q_string)?;
                st.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for KeyMaterial {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            ByteString,
            D,
            P,
            Q,
            G,
            J,
            X,
            Y,
            Key,
            KeyTypeSer,
            Modulus,
            PrivateExponent,
            PublicExponent,
            PrimeExponentP,
            PrimeExponentQ,
            CrtCoefficient,
            RecommendedCurve,
            QString,
        }

        struct KeyMaterialVisitor;

        impl<'de> Visitor<'de> for KeyMaterialVisitor {
            type Value = KeyMaterial;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct KeyMaterialVisitor")
            }

            #[allow(clippy::many_single_char_names)]
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut bytestring: Option<Zeroizing<Vec<u8>>> = None;
                let mut key_type_ser: Option<KeyTypeSer> = None;
                // Here `p` and `q` describes either a public value for DH or
                // a prime secret factor for RSA. Kept as `BigUint`` and wrapped
                // as `SafeBigUint` in RSA.
                let mut p: Option<Box<BigUint>> = None;
                let mut q: Option<Box<BigUint>> = None;
                let mut g: Option<Box<BigUint>> = None;
                let mut j: Option<Box<BigUint>> = None;
                let mut y: Option<Box<BigUint>> = None;
                let mut x: Option<Box<SafeBigUint>> = None;
                let mut key: Option<Zeroizing<Vec<u8>>> = None;
                let mut modulus: Option<Box<BigUint>> = None;
                let mut public_exponent: Option<Box<BigUint>> = None;
                let mut private_exponent: Option<Box<SafeBigUint>> = None;
                let mut prime_exponent_p: Option<Box<SafeBigUint>> = None;
                let mut prime_exponent_q: Option<Box<SafeBigUint>> = None;
                let mut crt_coefficient: Option<Box<SafeBigUint>> = None;
                let mut recommended_curve: Option<RecommendedCurve> = None;
                let mut d: Option<Box<SafeBigUint>> = None;
                let mut q_string: Option<Vec<u8>> = None;

                while let Some(field) = map.next_key()? {
                    match field {
                        Field::ByteString => {
                            if bytestring.is_some() {
                                return Err(de::Error::duplicate_field("ByteString"))
                            }
                            bytestring = Some(map.next_value()?);
                        }
                        Field::D => {
                            if d.is_some() {
                                return Err(de::Error::duplicate_field("D"))
                            }
                            d = Some(Box::new(map.next_value()?));
                        }
                        Field::P => {
                            if p.is_some() {
                                return Err(de::Error::duplicate_field("P"))
                            }
                            p = Some(Box::new(map.next_value()?));
                        }
                        Field::Q => {
                            if q.is_some() {
                                return Err(de::Error::duplicate_field("Q"))
                            }
                            q = Some(Box::new(map.next_value()?));
                        }
                        Field::G => {
                            if g.is_some() {
                                return Err(de::Error::duplicate_field("G"))
                            }
                            g = Some(Box::new(map.next_value()?));
                        }
                        Field::J => {
                            if j.is_some() {
                                return Err(de::Error::duplicate_field("J"))
                            }
                            j = Some(Box::new(map.next_value()?));
                        }
                        Field::X => {
                            if x.is_some() {
                                return Err(de::Error::duplicate_field("X"))
                            }
                            x = Some(Box::new(map.next_value()?));
                        }
                        Field::Y => {
                            if y.is_some() {
                                return Err(de::Error::duplicate_field("Y"))
                            }
                            y = Some(Box::new(map.next_value()?));
                        }
                        Field::Key => {
                            if key.is_some() {
                                return Err(de::Error::duplicate_field("Key"))
                            }
                            key = Some(map.next_value()?);
                        }
                        Field::KeyTypeSer => {
                            if key_type_ser.is_some() {
                                return Err(de::Error::duplicate_field("KeyTypeSer"))
                            }
                            key_type_ser = Some(map.next_value()?);
                        }
                        Field::Modulus => {
                            if modulus.is_some() {
                                return Err(de::Error::duplicate_field("Modulus"))
                            }
                            modulus = Some(Box::new(map.next_value()?));
                        }
                        Field::PrivateExponent => {
                            if private_exponent.is_some() {
                                return Err(de::Error::duplicate_field("PrivateExponent"))
                            }
                            private_exponent = Some(Box::new(map.next_value()?));
                        }
                        Field::PublicExponent => {
                            if public_exponent.is_some() {
                                return Err(de::Error::duplicate_field("PublicExponent"))
                            }
                            public_exponent = Some(Box::new(map.next_value()?));
                        }
                        Field::PrimeExponentP => {
                            if prime_exponent_p.is_some() {
                                return Err(de::Error::duplicate_field("PrimeExponentP"))
                            }
                            prime_exponent_p = Some(Box::new(map.next_value()?));
                        }
                        Field::PrimeExponentQ => {
                            if prime_exponent_q.is_some() {
                                return Err(de::Error::duplicate_field("PrimeExponentQ"))
                            }
                            prime_exponent_q = Some(Box::new(map.next_value()?));
                        }
                        Field::CrtCoefficient => {
                            if crt_coefficient.is_some() {
                                return Err(de::Error::duplicate_field("CrtCoefficient"))
                            }
                            crt_coefficient = Some(Box::new(map.next_value()?));
                        }
                        Field::RecommendedCurve => {
                            if recommended_curve.is_some() {
                                return Err(de::Error::duplicate_field("RecommendedCurve"))
                            }
                            recommended_curve = Some(map.next_value()?);
                        }
                        Field::QString => {
                            if q_string.is_some() {
                                return Err(de::Error::duplicate_field("QString"))
                            }
                            q_string = Some(map.next_value()?);
                        }
                    }
                }

                if let Some(key) = key {
                    Ok(KeyMaterial::TransparentSymmetricKey { key })
                } else {
                    Ok(match key_type_ser {
                        Some(KeyTypeSer::DH) => {
                            let p = p.ok_or_else(|| de::Error::missing_field("P for DH key"))?;
                            let g = g.ok_or_else(|| de::Error::missing_field("G for DH key"))?;
                            if let Some(x) = x {
                                KeyMaterial::TransparentDHPrivateKey { p, q, g, j, x }
                            } else {
                                let y = y.ok_or_else(|| {
                                    de::Error::missing_field("Y for DH public key")
                                })?;
                                KeyMaterial::TransparentDHPublicKey { p, q, g, j, y }
                            }
                        }
                        Some(KeyTypeSer::DSA) => {
                            let p = p.ok_or_else(|| de::Error::missing_field("P for DSA key"))?;
                            let g = g.ok_or_else(|| de::Error::missing_field("G for DSA key"))?;
                            let q = q.ok_or_else(|| de::Error::missing_field("Q for DSA key"))?;
                            if let Some(x) = x {
                                KeyMaterial::TransparentDSAPrivateKey { p, q, g, x }
                            } else {
                                let y = y.ok_or_else(|| {
                                    de::Error::missing_field("Y for DSA public key")
                                })?;
                                KeyMaterial::TransparentDSAPublicKey { p, q, g, y }
                            }
                        }
                        Some(KeyTypeSer::RsaPublic) => {
                            let modulus = modulus.ok_or_else(|| {
                                de::Error::missing_field("Modulus for RSA public key")
                            })?;
                            let public_exponent = public_exponent.ok_or_else(|| {
                                de::Error::missing_field("Public exponent for RSA public key")
                            })?;
                            KeyMaterial::TransparentRSAPublicKey {
                                modulus,
                                public_exponent,
                            }
                        }
                        Some(KeyTypeSer::RsaPrivate) => {
                            let modulus = modulus.ok_or_else(|| {
                                de::Error::missing_field("Modulus for RSA private key")
                            })?;
                            KeyMaterial::TransparentRSAPrivateKey {
                                modulus,
                                public_exponent,
                                private_exponent,
                                p: p.map(|p| Box::new(SafeBigUint::from(*p))),
                                q: q.map(|q| Box::new(SafeBigUint::from(*q))),
                                prime_exponent_p,
                                prime_exponent_q,
                                crt_coefficient,
                            }
                        }
                        Some(KeyTypeSer::ECDSA) => {
                            let recommended_curve = recommended_curve.ok_or_else(|| {
                                de::Error::missing_field("RecommendedCurve for EC key")
                            })?;
                            if let Some(d) = d {
                                KeyMaterial::TransparentECDSAPrivateKey {
                                    recommended_curve,
                                    d,
                                }
                            } else {
                                let q_string = q_string.ok_or_else(|| {
                                    de::Error::missing_field("QString for EC public key")
                                })?;
                                KeyMaterial::TransparentECDSAPublicKey {
                                    recommended_curve,
                                    q_string,
                                }
                            }
                        }
                        Some(KeyTypeSer::ECDH) => {
                            let recommended_curve = recommended_curve.ok_or_else(|| {
                                de::Error::missing_field("RecommendedCurve for EC key")
                            })?;
                            if let Some(d) = d {
                                KeyMaterial::TransparentECDHPrivateKey {
                                    recommended_curve,
                                    d,
                                }
                            } else {
                                let q_string = q_string.ok_or_else(|| {
                                    de::Error::missing_field("QString for EC public key")
                                })?;
                                KeyMaterial::TransparentECDHPublicKey {
                                    recommended_curve,
                                    q_string,
                                }
                            }
                        }
                        Some(KeyTypeSer::ECMQV) => {
                            let recommended_curve = recommended_curve.ok_or_else(|| {
                                de::Error::missing_field("RecommendedCurve for EC key")
                            })?;
                            if let Some(d) = d {
                                KeyMaterial::TransparentECMQVPrivateKey {
                                    recommended_curve,
                                    d,
                                }
                            } else {
                                let q_string = q_string.ok_or_else(|| {
                                    de::Error::missing_field("QString for EC public key")
                                })?;
                                KeyMaterial::TransparentECMQVPublicKey {
                                    recommended_curve,
                                    q_string,
                                }
                            }
                        }
                        Some(KeyTypeSer::EC) => {
                            let recommended_curve = recommended_curve.ok_or_else(|| {
                                de::Error::missing_field("RecommendedCurve for EC key")
                            })?;
                            if let Some(d) = d {
                                KeyMaterial::TransparentECPrivateKey {
                                    recommended_curve,
                                    d,
                                }
                            } else {
                                let q_string = q_string.ok_or_else(|| {
                                    de::Error::missing_field("QString for EC public key")
                                })?;
                                KeyMaterial::TransparentECPublicKey {
                                    recommended_curve,
                                    q_string,
                                }
                            }
                        }
                        _ => {
                            return Err(de::Error::custom(
                                "unable to differentiate key material variant",
                            ))
                        }
                    })
                }
            }
        }

        const FIELDS: &[&str] = &[
            "bytestring",
            "p",
            "q",
            "g",
            "j",
            "x",
            "y",
            "key",
            "modulus",
            "public_exponent",
            "private_exponent",
            "prime_exponent_p",
            "prime_exponent_q",
            "crt_coefficient",
            "recommended_curve",
            "d",
            "q_string",
        ];
        deserializer.deserialize_struct("KeyMaterial", FIELDS, KeyMaterialVisitor)
    }
}

impl KeyMaterial {
    pub fn to_kmip_2_1(&self) -> kmip_2_1::kmip_data_structures::KeyMaterial {
        match self {
            Self::TransparentSymmetricKey { key } => {
                kmip_2_1::kmip_data_structures::KeyMaterial::TransparentSymmetricKey {
                    key: key.clone(),
                }
            }
            Self::TransparentDHPrivateKey { p, q, g, j, x } => {
                kmip_2_1::kmip_data_structures::KeyMaterial::TransparentDHPrivateKey {
                    p: p.clone(),
                    q: q.clone(),
                    g: g.clone(),
                    j: j.clone(),
                    x: x.clone(),
                }
            }
            Self::TransparentDHPublicKey { p, q, g, j, y } => {
                kmip_2_1::kmip_data_structures::KeyMaterial::TransparentDHPublicKey {
                    p: p.clone(),
                    q: q.clone(),
                    g: g.clone(),
                    j: j.clone(),
                    y: y.clone(),
                }
            }
            Self::TransparentDSAPrivateKey { p, q, g, x } => {
                kmip_2_1::kmip_data_structures::KeyMaterial::TransparentDSAPrivateKey {
                    p: p.clone(),
                    q: q.clone(),
                    g: g.clone(),
                    x: x.clone(),
                }
            }
            Self::TransparentDSAPublicKey { p, q, g, y } => {
                kmip_2_1::kmip_data_structures::KeyMaterial::TransparentDSAPublicKey {
                    p: p.clone(),
                    q: q.clone(),
                    g: g.clone(),
                    y: y.clone(),
                }
            }
            Self::TransparentRSAPrivateKey {
                modulus,
                private_exponent,
                public_exponent,
                p,
                q,
                prime_exponent_p,
                prime_exponent_q,
                crt_coefficient,
            } => kmip_2_1::kmip_data_structures::KeyMaterial::TransparentRSAPrivateKey {
                modulus: modulus.clone(),
                private_exponent: private_exponent.clone(),
                public_exponent: public_exponent.clone(),
                p: p.clone(),
                q: q.clone(),
                prime_exponent_p: prime_exponent_p.clone(),
                prime_exponent_q: prime_exponent_q.clone(),
                crt_coefficient: crt_coefficient.clone(),
            },
            Self::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            } => kmip_2_1::kmip_data_structures::KeyMaterial::TransparentRSAPublicKey {
                modulus: modulus.clone(),
                public_exponent: public_exponent.clone(),
            },
            Self::TransparentECDSAPrivateKey {
                recommended_curve,
                d,
            } => kmip_2_1::kmip_data_structures::KeyMaterial::TransparentECPrivateKey {
                recommended_curve: *recommended_curve.to_kmip_2_1(),
                d: d.clone(),
            },
            Self::TransparentECDSAPublicKey {
                recommended_curve,
                q_string,
            } => kmip_2_1::kmip_data_structures::KeyMaterial::TransparentECPublicKey {
                recommended_curve: *recommended_curve.to_kmip_2_1(),
                q_string: q_string.clone(),
            },
            Self::TransparentECDHPrivateKey {
                recommended_curve,
                d,
            } => kmip_2_1::kmip_data_structures::KeyMaterial::TransparentECPrivateKey {
                recommended_curve: *recommended_curve.to_kmip_2_1(),
                d: d.clone(),
            },
            Self::TransparentECDHPublicKey {
                recommended_curve,
                q_string,
            } => kmip_2_1::kmip_data_structures::KeyMaterial::TransparentECPublicKey {
                recommended_curve: *recommended_curve.to_kmip_2_1(),
                q_string: q_string.clone(),
            },
            Self::TransparentECMQVPrivateKey {
                recommended_curve,
                d,
            } => kmip_2_1::kmip_data_structures::KeyMaterial::TransparentECPrivateKey {
                recommended_curve: *recommended_curve.to_kmip_2_1(),
                d: d.clone(),
            },
            Self::TransparentECMQVPublicKey {
                recommended_curve,
                q_string,
            } => kmip_2_1::kmip_data_structures::KeyMaterial::TransparentECPublicKey {
                recommended_curve: *recommended_curve.to_kmip_2_1(),
                q_string: q_string.clone(),
            },
            Self::TransparentECPrivateKey {
                recommended_curve,
                d,
            } => kmip_2_1::kmip_data_structures::KeyMaterial::TransparentECPrivateKey {
                recommended_curve: *recommended_curve.to_kmip_2_1(),
                d: d.clone(),
            },
            Self::TransparentECPublicKey {
                recommended_curve,
                q_string,
            } => kmip_2_1::kmip_data_structures::KeyMaterial::TransparentECPublicKey {
                recommended_curve: *recommended_curve.to_kmip_2_1(),
                q_string: q_string.clone(),
            },
        }
    }
}

/// 2.1.5 Key Wrapping Data Object Structure
/// The Key Wrapping Data object is a structure that contains information about the
/// wrapping of a key value. It includes the wrapping method, encryption key information,
/// MAC/signature information, initialization vector/counter/nonce if applicable, and
/// encoding information.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct KeyWrappingData {
    pub wrapping_method: WrappingMethod,
    pub encryption_key_information: Option<EncryptionKeyInformation>,
    pub mac_signature_key_information: Option<MacSignatureKeyInformation>,
    pub mac_signature: Option<Vec<u8>>,
    pub iv_counter_nonce: Option<Vec<u8>>,
    pub encoding_option: Option<EncodingOption>,
}

/// Encryption Key Information Structure
/// The Encryption Key Information is a structure containing a unique identifier and
/// optional parameters used to encrypt the key.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct EncryptionKeyInformation {
    pub unique_identifier: String,
    pub cryptographic_parameters: Option<CryptographicParameters>,
}

/// MAC/Signature Key Information Structure
/// The MAC/Signature Key Information is a structure containing a unique identifier and
/// optional parameters used to generate a MAC or signature over the key.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct MacSignatureKeyInformation {
    pub unique_identifier: String,
    pub cryptographic_parameters: Option<CryptographicParameters>,
}

/// 2.1.6 Key Wrapping Specification Object Structure
/// The Key Wrapping Specification is a structure that provides information on how a key
/// should be wrapped. It includes the wrapping method, encryption key information,
/// MAC/signature information, attribute names to be included in the wrapped data and
/// encoding options.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct KeyWrappingSpecification {
    pub wrapping_method: WrappingMethod,
    pub encryption_key_information: Option<EncryptionKeyInformation>,
    pub mac_signature_key_information: Option<MacSignatureKeyInformation>,
    pub attribute_names: Option<Vec<String>>,
    pub encoding_option: Option<EncodingOption>,
}

/// Cryptographic Parameters Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct CryptographicParameters {
    pub block_cipher_mode: Option<BlockCipherMode>,
    pub padding_method: Option<PaddingMethod>,
    pub hashing_algorithm: Option<HashingAlgorithm>,
    pub key_role_type: Option<KeyRoleType>,
    pub digital_signature_algorithm: Option<DigitalSignatureAlgorithm>,
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    pub random_iv: Option<bool>,
    pub iv_length: Option<i32>,
    pub tag_length: Option<i32>,
    pub fixed_field_length: Option<i32>,
    pub invocation_field_length: Option<i32>,
    pub counter_length: Option<i32>,
    pub initial_counter_value: Option<i32>,
    pub salt_length: Option<i32>,
    pub mask_generator: Option<MaskGenerator>,
    pub mask_generator_hashing_algorithm: Option<HashingAlgorithm>,
    pub p_source: Option<Vec<u8>>,
    pub trailer_field: Option<i32>,
}

/// 2.1.7.1 Transparent Symmetric Key Structure
/// The Transparent Symmetric Key structure is used to carry the key data for a
/// symmetric key in raw form.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentSymmetricKey {
    pub key: Vec<u8>,
}

/// 2.1.7.2 Transparent DSA Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentDsaPrivateKey {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub g: Vec<u8>,
    pub x: Vec<u8>,
}

/// 2.1.7.3 Transparent DSA Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentDsaPublicKey {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub g: Vec<u8>,
    pub y: Vec<u8>,
}

/// 2.1.7.4 Transparent RSA Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentRsaPrivateKey {
    pub modulus: Vec<u8>,
    pub private_exponent: Vec<u8>,
    pub public_exponent: Option<Vec<u8>>,
    pub p: Option<Vec<u8>>,
    pub q: Option<Vec<u8>>,
    pub prime_exponent_p: Option<Vec<u8>>,
    pub prime_exponent_q: Option<Vec<u8>>,
    pub crt_coefficient: Option<Vec<u8>>,
    pub recommended_curve: Option<RecommendedCurve>,
}

/// 2.1.7.5 Transparent RSA Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentRsaPublicKey {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
}

/// 2.1.7.6 Transparent DH Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentDhPrivateKey {
    pub p: Vec<u8>,
    pub g: Vec<u8>,
    pub q: Option<Vec<u8>>,
    pub j: Option<Vec<u8>>,
    pub x: Vec<u8>,
}

/// 2.1.7.7 Transparent DH Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentDhPublicKey {
    pub p: Vec<u8>,
    pub g: Vec<u8>,
    pub q: Option<Vec<u8>>,
    pub j: Option<Vec<u8>>,
    pub y: Vec<u8>,
}

/// 2.1.7.8 Transparent ECDSA Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentEcdsaPrivateKey {
    pub recommended_curve: RecommendedCurve,
    pub d: Vec<u8>,
}

/// 2.1.7.9 Transparent ECDSA Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentEcdsaPublicKey {
    pub recommended_curve: RecommendedCurve,
    pub q_string: Vec<u8>,
}

/// 2.1.7.10 Transparent ECDH Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentEcdhPrivateKey {
    pub recommended_curve: RecommendedCurve,
    pub d: Vec<u8>,
}

/// 2.1.7.11 Transparent ECDH Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentEcdhPublicKey {
    pub recommended_curve: RecommendedCurve,
    pub q_string: Vec<u8>,
}

/// 2.1.7.12 Transparent ECMQV Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentEcmqvPrivateKey {
    pub recommended_curve: RecommendedCurve,
    pub d: Vec<u8>,
}

/// 2.1.7.13 Transparent ECMQV Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TransparentEcmqvPublicKey {
    pub recommended_curve: RecommendedCurve,
    pub q_string: Vec<u8>,
}

/// 2.1.8 Template-Attribute Structures
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct TemplateAttribute {
    pub name: Option<String>,
    pub attributes: Vec<Attribute>,
}

/// 2.1.9 Extension Information Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ExtensionInformation {
    pub extension_name: String,
    pub extension_tag: Option<i32>,
    pub extension_type: Option<i32>,
}

/// 2.1.10-23 Additional Structures
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Data(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct DataLength(pub i32);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct SignatureData(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct MacData(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Nonce(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct CorrelationValue(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct InitIndicator(pub bool);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct FinalIndicator(pub bool);

/// RNG Parameters provides information about random number generation. It contains
/// details about the RNG algorithm, cryptographic algorithms, hash algorithms, DRBG
/// algorithms and associated parameters.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct RngParameters {
    pub rng_algorithm: RNGAlgorithm,
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    pub cryptographic_length: Option<i32>,
    pub hashing_algorithm: Option<HashingAlgorithm>,
    pub drbg_algorithm: Option<DRBGAlgorithm>,
    pub recommended_curve: Option<RecommendedCurve>,
    pub fips186_variation: Option<FIPS186Variation>,
    pub prediction_resistance: Option<bool>,
}

/// Profile Information contains details about supported KMIP profiles.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ProfileInformation {
    pub profile_name: ProfileName,
    pub server_uri: Option<String>,
    pub server_port: Option<i32>,
}

/// Validation Information contains details about the validation of a cryptographic
/// module, including the validation authority, version information and validation
/// profiles.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ValidationInformation {
    pub validation_authority_type: ValidationAuthorityType,
    pub validation_authority_country: Option<String>,
    pub validation_authority_uri: Option<String>,
    pub validation_version_major: Option<i32>,
    pub validation_version_minor: Option<i32>,
    pub validation_type: Option<ValidationType>,
    pub validation_level: Option<i32>,
    pub validation_certificate_identifier: Option<String>,
    pub validation_certificate_uri: Option<String>,
    pub validation_vendor_uri: Option<String>,
    pub validation_profile: Option<String>,
}

/// Capability Information indicates various capabilities supported by a KMIP server.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct CapabilityInformation {
    pub streaming_capability: bool,
    pub asynchronous_capability: bool,
    pub attestation_capability: bool,
    pub batch_undo_capability: bool,
    pub batch_continue_capability: bool,
    pub unwrap_mode: Option<UnwrapMode>,
    pub destroy_action: Option<DestroyAction>,
    pub shredding_algorithm: Option<ShreddingAlgorithm>,
    pub rng_mode: Option<RNGMode>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticatedEncryptionAdditionalData(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct AuthenticatedEncryptionTag(pub Vec<u8>);

/// Derivation Parameters defines the parameters for a key derivation process
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct DerivationParameters {
    /// The type of derivation method to be used
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// The initialization vector or nonce if required by the derivation algorithm
    pub initialization_vector: Option<Vec<u8>>,
    /// A value that identifies the derivation process
    pub derivation_data: Option<Vec<u8>>,
    /// The length in bits of the derived data
    pub salt: Option<Vec<u8>>,
    /// Optional iteration count used by the derivation method
    pub iteration_count: Option<i32>,
}
