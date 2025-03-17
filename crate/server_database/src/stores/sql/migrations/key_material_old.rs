use std::fmt::{Display, Formatter};

use cosmian_kmip::{kmip_2_1::kmip_types::RecommendedCurve, SafeBigInt};
use num_bigint_dig::BigInt;
use serde::{
    de,
    de::{MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) enum KeyMaterial421 {
    ByteString(Zeroizing<Vec<u8>>),
    TransparentDHPrivateKey {
        p: Box<BigInt>,
        q: Option<Box<BigInt>>,
        g: Box<BigInt>,
        j: Option<Box<BigInt>>,
        x: Box<SafeBigInt>,
    },
    TransparentDHPublicKey {
        p: Box<BigInt>,
        q: Option<Box<BigInt>>,
        g: Box<BigInt>,
        j: Option<Box<BigInt>>,
        y: Box<BigInt>,
    },
    TransparentDSAPrivateKey {
        p: Box<BigInt>,
        q: Box<BigInt>,
        g: Box<BigInt>,
        x: Box<SafeBigInt>,
    },
    TransparentDSAPublicKey {
        p: Box<BigInt>,
        q: Box<BigInt>,
        g: Box<BigInt>,
        y: Box<BigInt>,
    },
    TransparentSymmetricKey {
        key: Zeroizing<Vec<u8>>,
    },
    TransparentRSAPublicKey {
        modulus: Box<BigInt>,
        public_exponent: Box<BigInt>,
    },
    TransparentRSAPrivateKey {
        modulus: Box<BigInt>,
        private_exponent: Option<Box<SafeBigInt>>,
        public_exponent: Option<Box<BigInt>>,
        p: Option<Box<SafeBigInt>>,
        q: Option<Box<SafeBigInt>>,
        prime_exponent_p: Option<Box<SafeBigInt>>,
        prime_exponent_q: Option<Box<SafeBigInt>>,
        crt_coefficient: Option<Box<SafeBigInt>>,
    },
    TransparentECPrivateKey {
        recommended_curve: RecommendedCurve,
        // big int in big endian format
        d: Box<SafeBigInt>,
    },
    TransparentECPublicKey {
        recommended_curve: RecommendedCurve,
        q_string: Vec<u8>,
    },
}

impl Display for KeyMaterial421 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ByteString(_) => write!(f, "ByteString. Not displaying key content"),
            Self::TransparentDHPrivateKey { .. } => {
                write!(f, "DH Private Key. Not displaying key content")
            }
            Self::TransparentDHPublicKey { .. } => {
                write!(f, "DH Public Key. Not displaying key content")
            }
            Self::TransparentDSAPrivateKey { .. } => {
                write!(f, "DSA Private Key. Not displaying key content")
            }
            Self::TransparentDSAPublicKey { .. } => {
                write!(f, "DSA Public Key. Not displaying key content")
            }
            Self::TransparentSymmetricKey { .. } => {
                write!(f, "Symmetric Key. Not displaying key content")
            }
            Self::TransparentRSAPublicKey { .. } => {
                write!(f, "RSA Public Key. Not displaying key content")
            }
            Self::TransparentRSAPrivateKey { .. } => {
                write!(f, "RSA Private Key. Not displaying key content")
            }
            Self::TransparentECPrivateKey { .. } => {
                write!(f, "EC Private Key. Not displaying key content")
            }
            Self::TransparentECPublicKey { .. } => {
                write!(f, "EC Public Key. Not displaying key content")
            }
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Serialize, Deserialize, Clone, Copy)]
enum KeyTypeSer {
    DH,
    DSA,
    RsaPublic,
    RsaPrivate,
    EC,
}

// Unfortunately, default serialization does not play well
// for ByteString, so we have to do it by hand. Deserialization is OK though
impl Serialize for KeyMaterial421 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::ByteString(bytes) => {
                let mut st = serializer.serialize_struct("KeyMaterial421", 1)?;
                st.serialize_field("ByteString", &**bytes)?;
                st.end()
            }
            Self::TransparentSymmetricKey { key } => {
                let mut st = serializer.serialize_struct("KeyMaterial421", 1)?;
                st.serialize_field("Key", &**key)?;
                st.end()
            }
            Self::TransparentDHPrivateKey { p, q, g, j, x } => {
                let mut st = serializer.serialize_struct("KeyMaterial421", 6)?;
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
                let mut st = serializer.serialize_struct("KeyMaterial421", 6)?;
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
                let mut st = serializer.serialize_struct("KeyMaterial421", 5)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::DSA)?;
                st.serialize_field("P", &**p)?;
                st.serialize_field("Q", &**q)?;
                st.serialize_field("G", &**g)?;
                st.serialize_field("X", &***x)?;
                st.end()
            }
            Self::TransparentDSAPublicKey { p, q, g, y } => {
                let mut st = serializer.serialize_struct("KeyMaterial421", 5)?;
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
                let mut st = serializer.serialize_struct("KeyMaterial421", 9)?;
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
                let mut st = serializer.serialize_struct("KeyMaterial421", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::RsaPublic)?;
                st.serialize_field("Modulus", &**modulus)?;
                st.serialize_field("PublicExponent", &**public_exponent)?;
                st.end()
            }
            Self::TransparentECPrivateKey {
                recommended_curve,
                d,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial421", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::EC)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("D", &***d)?;
                st.end()
            }
            Self::TransparentECPublicKey {
                recommended_curve,
                q_string,
            } => {
                let mut st = serializer.serialize_struct("KeyMaterial421", 3)?;
                st.serialize_field("KeyTypeSer", &KeyTypeSer::EC)?;
                st.serialize_field("RecommendedCurve", recommended_curve)?;
                st.serialize_field("QString", q_string)?;
                st.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for KeyMaterial421 {
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
            type Value = KeyMaterial421;

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
                // a prime secret factor for RSA. Kept as `BigInt`` and wrapped
                // as `SafeBigInt` in RSA.
                let mut p: Option<Box<BigInt>> = None;
                let mut q: Option<Box<BigInt>> = None;
                let mut g: Option<Box<BigInt>> = None;
                let mut j: Option<Box<BigInt>> = None;
                let mut y: Option<Box<BigInt>> = None;
                let mut x: Option<Box<SafeBigInt>> = None;
                let mut key: Option<Zeroizing<Vec<u8>>> = None;
                let mut modulus: Option<Box<BigInt>> = None;
                let mut public_exponent: Option<Box<BigInt>> = None;
                let mut private_exponent: Option<Box<SafeBigInt>> = None;
                let mut prime_exponent_p: Option<Box<SafeBigInt>> = None;
                let mut prime_exponent_q: Option<Box<SafeBigInt>> = None;
                let mut crt_coefficient: Option<Box<SafeBigInt>> = None;
                let mut recommended_curve: Option<RecommendedCurve> = None;
                let mut d: Option<Box<SafeBigInt>> = None;
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
                    Ok(KeyMaterial421::TransparentSymmetricKey { key })
                } else if let Some(bytestring) = bytestring {
                    Ok(KeyMaterial421::ByteString(bytestring))
                } else {
                    Ok(match key_type_ser {
                        Some(KeyTypeSer::DH) => {
                            let p = p.ok_or_else(|| de::Error::missing_field("P for DH key"))?;
                            let g = g.ok_or_else(|| de::Error::missing_field("G for DH key"))?;
                            if let Some(x) = x {
                                KeyMaterial421::TransparentDHPrivateKey { p, q, g, j, x }
                            } else {
                                let y = y.ok_or_else(|| {
                                    de::Error::missing_field("Y for DH public key")
                                })?;
                                KeyMaterial421::TransparentDHPublicKey { p, q, g, j, y }
                            }
                        }
                        Some(KeyTypeSer::DSA) => {
                            let p = p.ok_or_else(|| de::Error::missing_field("P for DSA key"))?;
                            let g = g.ok_or_else(|| de::Error::missing_field("G for DSA key"))?;
                            let q = q.ok_or_else(|| de::Error::missing_field("Q for DSA key"))?;
                            if let Some(x) = x {
                                KeyMaterial421::TransparentDSAPrivateKey { p, q, g, x }
                            } else {
                                let y = y.ok_or_else(|| {
                                    de::Error::missing_field("Y for DSA public key")
                                })?;
                                KeyMaterial421::TransparentDSAPublicKey { p, q, g, y }
                            }
                        }
                        Some(KeyTypeSer::RsaPublic) => {
                            let modulus = modulus.ok_or_else(|| {
                                de::Error::missing_field("Modulus for RSA public key")
                            })?;
                            let public_exponent = public_exponent.ok_or_else(|| {
                                de::Error::missing_field("Public exponent for RSA public key")
                            })?;
                            KeyMaterial421::TransparentRSAPublicKey {
                                modulus,
                                public_exponent,
                            }
                        }
                        Some(KeyTypeSer::RsaPrivate) => {
                            let modulus = modulus.ok_or_else(|| {
                                de::Error::missing_field("Modulus for RSA private key")
                            })?;
                            KeyMaterial421::TransparentRSAPrivateKey {
                                modulus,
                                public_exponent,
                                private_exponent,
                                p: p.map(|p| Box::new(SafeBigInt::from(*p))),
                                q: q.map(|q| Box::new(SafeBigInt::from(*q))),
                                prime_exponent_p,
                                prime_exponent_q,
                                crt_coefficient,
                            }
                        }
                        Some(KeyTypeSer::EC) => {
                            let recommended_curve = recommended_curve.ok_or_else(|| {
                                de::Error::missing_field("RecommendedCurve for EC key")
                            })?;
                            if let Some(d) = d {
                                KeyMaterial421::TransparentECPrivateKey {
                                    recommended_curve,
                                    d,
                                }
                            } else {
                                let q_string = q_string.ok_or_else(|| {
                                    de::Error::missing_field("QString for EC public key")
                                })?;
                                KeyMaterial421::TransparentECPublicKey {
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
        deserializer.deserialize_struct("KeyMaterial421", FIELDS, KeyMaterialVisitor)
    }
}
