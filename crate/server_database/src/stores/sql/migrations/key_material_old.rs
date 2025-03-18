use std::fmt::Display;

use cosmian_kmip::{
    kmip_2_1::{kmip_data_structures::KeyMaterial, kmip_types::RecommendedCurve},
    SafeBigInt,
};
use num_bigint_dig::{BigInt, BigUint, Sign};
use serde::{
    de,
    de::{MapAccess, Visitor},
    Deserialize, Serialize,
};
use zeroize::Zeroizing;

#[derive(Clone, Eq, PartialEq, Debug)]
/// This is the `KeyMaterial` enum used in KMS 4.21 and earlier versions
/// that uses `BigUint`. The new version of `KeyMaterial` uses `BigInt`.
pub(super) enum KeyMaterial421 {
    ByteString(Zeroizing<Vec<u8>>),
    TransparentDHPrivateKey {
        p: Box<BigUint>,
        q: Option<Box<BigUint>>,
        g: Box<BigUint>,
        j: Option<Box<BigUint>>,
        x: Box<BigUint>,
    },
    TransparentDHPublicKey {
        p: Box<BigUint>,
        q: Option<Box<BigUint>>,
        g: Box<BigUint>,
        j: Option<Box<BigUint>>,
        y: Box<BigUint>,
    },
    TransparentDSAPrivateKey {
        p: Box<BigUint>,
        q: Box<BigUint>,
        g: Box<BigUint>,
        x: Box<BigUint>,
    },
    TransparentDSAPublicKey {
        p: Box<BigUint>,
        q: Box<BigUint>,
        g: Box<BigUint>,
        y: Box<BigUint>,
    },
    TransparentSymmetricKey {
        key: Zeroizing<Vec<u8>>,
    },
    TransparentRSAPublicKey {
        modulus: Box<BigUint>,
        public_exponent: Box<BigUint>,
    },
    TransparentRSAPrivateKey {
        modulus: Box<BigUint>,
        private_exponent: Option<Box<BigUint>>,
        public_exponent: Option<Box<BigUint>>,
        p: Option<Box<BigUint>>,
        q: Option<Box<BigUint>>,
        prime_exponent_p: Option<Box<BigUint>>,
        prime_exponent_q: Option<Box<BigUint>>,
        crt_coefficient: Option<Box<BigUint>>,
    },
    TransparentECPrivateKey {
        recommended_curve: RecommendedCurve,
        // big int in big endian format
        d: Box<BigUint>,
    },
    TransparentECPublicKey {
        recommended_curve: RecommendedCurve,
        q_string: Vec<u8>,
    },
}

impl Display for KeyMaterial421 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
                // a prime secret factor for RSA. Kept as `BigUint`` and wrapped
                // as `BigUint` in RSA.
                let mut p: Option<Box<BigUint>> = None;
                let mut q: Option<Box<BigUint>> = None;
                let mut g: Option<Box<BigUint>> = None;
                let mut j: Option<Box<BigUint>> = None;
                let mut y: Option<Box<BigUint>> = None;
                let mut x: Option<Box<BigUint>> = None;
                let mut key: Option<Zeroizing<Vec<u8>>> = None;
                let mut modulus: Option<Box<BigUint>> = None;
                let mut public_exponent: Option<Box<BigUint>> = None;
                let mut private_exponent: Option<Box<BigUint>> = None;
                let mut prime_exponent_p: Option<Box<BigUint>> = None;
                let mut prime_exponent_q: Option<Box<BigUint>> = None;
                let mut crt_coefficient: Option<Box<BigUint>> = None;
                let mut recommended_curve: Option<RecommendedCurve> = None;
                let mut d: Option<Box<BigUint>> = None;
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
                                p: p.map(|p| Box::new(*p)),
                                q: q.map(|q| Box::new(*q)),
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

impl From<KeyMaterial421> for KeyMaterial {
    fn from(key_material: KeyMaterial421) -> Self {
        match key_material {
            KeyMaterial421::ByteString(byte_string) => Self::ByteString(byte_string),
            KeyMaterial421::TransparentDHPrivateKey { p, q, g, j, x } => {
                Self::TransparentDHPrivateKey {
                    p: Box::new(BigInt::from_biguint(Sign::Plus, *p)),
                    q: q.map(|q| Box::new(BigInt::from_biguint(Sign::Plus, *q))),
                    g: Box::new(BigInt::from_biguint(Sign::Plus, *g)),
                    j: j.map(|j| Box::new(BigInt::from_biguint(Sign::Plus, *j))),
                    x: Box::new(SafeBigInt::from(*x)),
                }
            }
            KeyMaterial421::TransparentDHPublicKey { p, q, g, j, y } => {
                Self::TransparentDHPublicKey {
                    p: Box::new(BigInt::from_biguint(Sign::Plus, *p)),
                    q: q.map(|q| Box::new(BigInt::from_biguint(Sign::Plus, *q))),
                    g: Box::new(BigInt::from_biguint(Sign::Plus, *g)),
                    j: j.map(|j| Box::new(BigInt::from_biguint(Sign::Plus, *j))),
                    y: Box::new(BigInt::from_biguint(Sign::Plus, *y)),
                }
            }
            KeyMaterial421::TransparentDSAPrivateKey { p, q, g, x } => {
                Self::TransparentDSAPrivateKey {
                    p: Box::new(BigInt::from_biguint(Sign::Plus, *p)),
                    q: Box::new(BigInt::from_biguint(Sign::Plus, *q)),
                    g: Box::new(BigInt::from_biguint(Sign::Plus, *g)),
                    x: Box::new(SafeBigInt::from(*x)),
                }
            }
            KeyMaterial421::TransparentDSAPublicKey { p, q, g, y } => {
                Self::TransparentDSAPublicKey {
                    p: Box::new(BigInt::from_biguint(Sign::Plus, *p)),
                    q: Box::new(BigInt::from_biguint(Sign::Plus, *q)),
                    g: Box::new(BigInt::from_biguint(Sign::Plus, *g)),
                    y: Box::new(BigInt::from_biguint(Sign::Plus, *y)),
                }
            }
            KeyMaterial421::TransparentSymmetricKey { key } => {
                Self::TransparentSymmetricKey { key }
            }
            KeyMaterial421::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            } => Self::TransparentRSAPublicKey {
                modulus: Box::new(BigInt::from_biguint(Sign::Plus, *modulus)),
                public_exponent: Box::new(BigInt::from_biguint(Sign::Plus, *public_exponent)),
            },
            KeyMaterial421::TransparentRSAPrivateKey {
                modulus,
                private_exponent,
                public_exponent,
                p,
                q,
                prime_exponent_p,
                prime_exponent_q,
                crt_coefficient,
            } => Self::TransparentRSAPrivateKey {
                modulus: Box::new(BigInt::from_biguint(Sign::Plus, *modulus)),
                private_exponent: private_exponent
                    .map(|private_exponent| Box::new(SafeBigInt::from(*private_exponent))),
                public_exponent: public_exponent.map(|public_exponent| {
                    Box::new(BigInt::from_biguint(Sign::Plus, *public_exponent))
                }),
                p: p.map(|p| Box::new(SafeBigInt::from(*p))),
                q: q.map(|q| Box::new(SafeBigInt::from(*q))),
                prime_exponent_p: prime_exponent_p
                    .map(|prime_exponent_p| Box::new(SafeBigInt::from(*prime_exponent_p))),
                prime_exponent_q: prime_exponent_q
                    .map(|prime_exponent_q| Box::new(SafeBigInt::from(*prime_exponent_q))),
                crt_coefficient: crt_coefficient
                    .map(|crt_coefficient| Box::new(SafeBigInt::from(*crt_coefficient))),
            },
            KeyMaterial421::TransparentECPrivateKey {
                recommended_curve,
                d,
            } => Self::TransparentECPrivateKey {
                recommended_curve,
                d: Box::new(SafeBigInt::from(*d)),
            },
            KeyMaterial421::TransparentECPublicKey {
                recommended_curve,
                q_string,
            } => Self::TransparentECPublicKey {
                recommended_curve,
                q_string,
            },
        }
    }
}
