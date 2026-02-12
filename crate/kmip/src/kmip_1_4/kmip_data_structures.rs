use cosmian_logger::trace;
use num_bigint_dig::BigInt;
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, MapAccess, Visitor},
    ser::SerializeStruct,
};
use tracing::instrument;
use zeroize::Zeroizing;

use super::{
    kmip_attributes::Attribute,
    kmip_types::{
        CryptographicAlgorithm, DigitalSignatureAlgorithm, EncodingOption, KeyCompressionType,
        KeyFormatType, ProfileName, RecommendedCurve, WrappingMethod,
    },
};
use crate::{
    KmipError, SafeBigInt,
    kmip_0::kmip_types::{
        BlockCipherMode, DRBGAlgorithm, DestroyAction, FIPS186Variation, HashingAlgorithm,
        KeyRoleType, MaskGenerator, PaddingMethod, RNGAlgorithm, ShreddingAlgorithm, UnwrapMode,
    },
    kmip_2_1,
};

/// 2.1.3 Key Block Object Structure
/// A Key Block object is a structure used to encapsulate all of the information that is
/// closely associated with a cryptographic key. It contains information about the format
/// of the key, the algorithm it supports, and its cryptographic length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlock {
    pub key_format_type: KeyFormatType,
    pub key_compression_type: Option<KeyCompressionType>,
    pub key_value: Option<KeyValue>,
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    pub cryptographic_length: Option<i32>,
    pub key_wrapping_data: Option<KeyWrappingData>,
}

impl Serialize for KeyBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut st = serializer.serialize_struct("KeyBlock", 6)?;
        st.serialize_field("KeyFormatType", &self.key_format_type)?;
        if let Some(key_compression_type) = &self.key_compression_type {
            st.serialize_field("KeyCompressionType", key_compression_type)?;
        }
        if let Some(key_value) = &self.key_value {
            st.serialize_field(
                "KeyValue",
                &KeyValueSerializer {
                    key_format_type: self.key_format_type,
                    key_value: key_value.clone(),
                },
            )?;
        }
        if let Some(cryptographic_algorithm) = &self.cryptographic_algorithm {
            st.serialize_field("CryptographicAlgorithm", cryptographic_algorithm)?;
        }
        if let Some(cryptographic_length) = &self.cryptographic_length {
            st.serialize_field("CryptographicLength", cryptographic_length)?;
        }
        if let Some(key_wrapping_data) = &self.key_wrapping_data {
            st.serialize_field("KeyWrappingData", key_wrapping_data)?;
        }
        st.end()
    }
}

impl<'de> Deserialize<'de> for KeyBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(field_identifier)]
        enum Field {
            KeyFormatType,
            KeyCompressionType,
            KeyValue,
            CryptographicAlgorithm,
            CryptographicLength,
            KeyWrappingData,
        }

        struct KeyBlockVisitor;

        impl<'de> Visitor<'de> for KeyBlockVisitor {
            type Value = KeyBlock;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct KeyBlock")
            }

            #[instrument(level = "trace", skip(self, map))]
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut key_format_type: Option<KeyFormatType> = None;
                let mut key_compression_type: Option<KeyCompressionType> = None;
                let mut key_value: Option<KeyValue> = None;
                let mut cryptographic_algorithm: Option<CryptographicAlgorithm> = None;
                let mut cryptographic_length: Option<i32> = None;
                let mut key_wrapping_data: Option<KeyWrappingData> = None;

                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::KeyFormatType => {
                            if key_format_type.is_some() {
                                return Err(de::Error::duplicate_field("KeyFormatType"));
                            }
                            key_format_type = Some(map.next_value()?);
                        }
                        Field::KeyCompressionType => {
                            if key_compression_type.is_some() {
                                return Err(de::Error::duplicate_field("KeyCompressionType"));
                            }
                            key_compression_type = Some(map.next_value()?);
                        }
                        Field::KeyValue => {
                            if key_value.is_some() {
                                return Err(de::Error::duplicate_field("KeyValue"));
                            }
                            key_value =
                                Some(map.next_value_seed(KeyValueDeserializer {
                                    key_format_type:
                                        key_format_type.ok_or_else(|| {
                                            de::Error::missing_field("KeyFormatType")
                                        })?,
                                })?);
                        }
                        Field::CryptographicAlgorithm => {
                            if cryptographic_algorithm.is_some() {
                                return Err(de::Error::duplicate_field("CryptographicAlgorithm"));
                            }
                            cryptographic_algorithm = Some(map.next_value()?);
                        }
                        Field::CryptographicLength => {
                            if cryptographic_length.is_some() {
                                return Err(de::Error::duplicate_field("CryptographicLength"));
                            }
                            cryptographic_length = Some(map.next_value()?);
                        }
                        Field::KeyWrappingData => {
                            if key_wrapping_data.is_some() {
                                return Err(de::Error::duplicate_field("KeyWrappingData"));
                            }
                            key_wrapping_data = Some(map.next_value()?);
                        }
                    }
                }
                let key_format_type =
                    key_format_type.ok_or_else(|| de::Error::missing_field("KeyFormatType"))?;
                Ok(KeyBlock {
                    key_format_type,
                    key_compression_type,
                    key_value,
                    cryptographic_algorithm,
                    cryptographic_length,
                    key_wrapping_data,
                })
            }
        }

        trace!("==> Deserializing KeyBlock");
        deserializer.deserialize_struct(
            "KeyBlock",
            &[
                "KeyFormatType",
                "KeyCompressionType",
                "KeyValue",
                "CryptographicAlgorithm",
                "CryptographicLength",
                "KeyWrappingData",
            ],
            KeyBlockVisitor,
        )
    }
}

impl From<KeyBlock> for kmip_2_1::kmip_data_structures::KeyBlock {
    fn from(val: KeyBlock) -> Self {
        Self {
            key_format_type: val.key_format_type.into(),
            key_compression_type: val.key_compression_type.map(Into::into),
            key_value: val.key_value.map(Into::into),
            cryptographic_algorithm: val.cryptographic_algorithm.map(Into::into),
            cryptographic_length: val.cryptographic_length,
            key_wrapping_data: val.key_wrapping_data.map(Into::into),
        }
    }
}

impl TryFrom<kmip_2_1::kmip_data_structures::KeyBlock> for KeyBlock {
    type Error = KmipError;

    fn try_from(val: kmip_2_1::kmip_data_structures::KeyBlock) -> Result<Self, Self::Error> {
        Ok(Self {
            key_format_type: val.key_format_type.try_into()?,
            key_compression_type: val
                .key_compression_type
                .map(TryInto::try_into)
                .transpose()?,
            key_value: val.key_value.map(TryInto::try_into).transpose()?,
            cryptographic_algorithm: val
                .cryptographic_algorithm
                .map(TryInto::try_into)
                .transpose()?,
            cryptographic_length: val.cryptographic_length,
            key_wrapping_data: val.key_wrapping_data.map(TryInto::try_into).transpose()?,
        })
    }
}

/// 2.1.4 Key Value Object Structure
/// The Key Value object is a structure used to represent the key material and associated
/// attributes within a Key Block structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyValue {
    /// The key value is a byte string when key wrapped
    ByteString(Zeroizing<Vec<u8>>),
    /// The key value is a structure when the key is not wrapped
    Structure {
        key_material: KeyMaterial,
        attribute: Option<Vec<Attribute>>,
    },
}

/// Structure used to serialize `KeyValue`
/// This structure maintains the `KeyFormatType` which is passed down
/// to the serializer of the `KeyMaterial` called
struct KeyValueSerializer {
    key_format_type: KeyFormatType,
    key_value: KeyValue,
}

impl Serialize for KeyValueSerializer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.key_value {
            KeyValue::ByteString(bytes) => serializer.serialize_bytes(bytes),
            KeyValue::Structure {
                key_material,
                attribute,
            } => {
                let mut st = serializer.serialize_struct("KeyValue", 2)?;
                st.serialize_field(
                    "KeyMaterial",
                    &KeyMaterialSerializer {
                        key_format_type: self.key_format_type,
                        key_material: key_material.clone(),
                    },
                )?;
                if let Some(attributes) = &attribute {
                    if !attributes.is_empty() {
                        st.serialize_field("Attribute", &attribute)?;
                    }
                }
                st.end()
            }
        }
    }
}

struct KeyValueDeserializer {
    key_format_type: KeyFormatType,
}

impl<'de> DeserializeSeed<'de> for KeyValueDeserializer {
    type Value = KeyValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(field_identifier)]
        enum Field {
            KeyMaterial,
            Attribute,
        }

        struct KeyValueVisitor {
            key_format_type: KeyFormatType,
        }

        impl<'de> Visitor<'de> for KeyValueVisitor {
            type Value = KeyValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct KeyValue")
            }

            /// This is called by the TTLV deserializer in `deserialize_seq`
            /// which is itself called by the call to `deserializer.deserialize_any()` below
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut bytestring = Vec::<u8>::new();
                while let Some(byte) = seq.next_element()? {
                    bytestring.push(byte);
                }
                Ok(KeyValue::ByteString(Zeroizing::new(bytestring)))
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut key_material: Option<KeyMaterial> = None;
                let mut attributes: Option<Vec<Attribute>> = None;

                while let Some(field) = map.next_key()? {
                    match field {
                        Field::KeyMaterial => {
                            if key_material.is_some() {
                                return Err(de::Error::duplicate_field("KeyMaterial"));
                            }
                            key_material = Some(map.next_value_seed(KeyMaterialDeserializer {
                                key_format_type: self.key_format_type,
                            })?);
                        }
                        Field::Attribute => {
                            if attributes.is_some() {
                                return Err(de::Error::duplicate_field("Attributes"));
                            }
                            attributes = Some(map.next_value()?);
                        }
                    }
                }

                let key_material =
                    key_material.ok_or_else(|| de::Error::missing_field("KeyMaterial"))?;
                Ok(KeyValue::Structure {
                    key_material,
                    attribute: attributes,
                })
            }
        }

        deserializer.deserialize_any(KeyValueVisitor {
            key_format_type: self.key_format_type,
        })
    }
}

impl From<KeyValue> for kmip_2_1::kmip_data_structures::KeyValue {
    fn from(val: KeyValue) -> Self {
        match val {
            KeyValue::ByteString(zeroizing) => Self::ByteString(zeroizing),
            KeyValue::Structure {
                key_material,
                attribute,
            } => Self::Structure {
                key_material: key_material.into(),
                attributes: attribute.map(Into::into),
            },
        }
    }
}

impl TryFrom<kmip_2_1::kmip_data_structures::KeyValue> for KeyValue {
    type Error = KmipError;

    fn try_from(val: kmip_2_1::kmip_data_structures::KeyValue) -> Result<Self, Self::Error> {
        match val {
            kmip_2_1::kmip_data_structures::KeyValue::ByteString(zeroizing) => {
                Ok(Self::ByteString(zeroizing))
            }
            kmip_2_1::kmip_data_structures::KeyValue::Structure {
                key_material,
                attributes,
            } => {
                let attributes_1_4 = attributes
                    .map(|attr| {
                        let attrs: Vec<kmip_2_1::kmip_attributes::Attribute> = attr.into();
                        attrs
                            .into_iter()
                            .map(TryInto::try_into)
                            .filter(|a| {
                                if let Ok(att) = a {
                                    // FIXME PyKMIP does not support OriginalCreationDate attribute
                                    if matches!(a, Ok(Attribute::OriginalCreationDate(_))) {
                                        return false;
                                    }
                                    if let Attribute::CustomAttribute(custom_attribute) = att {
                                        // FIXME Filter out custom attributes that start with "y-" => not supported by PyKMIP
                                        return !custom_attribute.name.starts_with("y-");
                                    }
                                    return true;
                                }
                                false
                            })
                            .collect::<Result<Vec<Attribute>, KmipError>>()
                    })
                    .transpose()?;
                Ok(Self::Structure {
                    key_material: key_material.try_into()?,
                    attribute: attributes_1_4,
                })
            }
        }
    }
}

/// Private fields are represented using a Zeroizing object: either array of
/// bytes, or `SafeBigInt` type.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum KeyMaterial {
    ByteString(Zeroizing<Vec<u8>>),
    TransparentSymmetricKey {
        key: Zeroizing<Vec<u8>>,
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
    TransparentRSAPublicKey {
        modulus: Box<BigInt>,
        public_exponent: Box<BigInt>,
    },
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
    TransparentECDSAPrivateKey {
        recommended_curve: RecommendedCurve,
        // big int in big endian format
        d: Box<SafeBigInt>,
    },
    TransparentECDSAPublicKey {
        recommended_curve: RecommendedCurve,
        q_string: Vec<u8>,
    },
    TransparentECDHPrivateKey {
        recommended_curve: RecommendedCurve,
        // big int in big endian format
        d: Box<SafeBigInt>,
    },
    TransparentECDHPublicKey {
        recommended_curve: RecommendedCurve,
        q_string: Vec<u8>,
    },
    TransparentECMQVPrivateKey {
        recommended_curve: RecommendedCurve,
        // big int in big endian format
        d: Box<SafeBigInt>,
    },
    TransparentECMQVPublicKey {
        recommended_curve: RecommendedCurve,
        q_string: Vec<u8>,
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

struct KeyMaterialSerializer {
    key_format_type: KeyFormatType,
    key_material: KeyMaterial,
}

impl Serialize for KeyMaterialSerializer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if let KeyMaterial::ByteString(ref bytes) = self.key_material {
            match self.key_format_type {
                KeyFormatType::Raw
                | KeyFormatType::ECPrivateKey
                | KeyFormatType::Opaque
                | KeyFormatType::PKCS1
                | KeyFormatType::PKCS12
                | KeyFormatType::PKCS8
                | KeyFormatType::X509
                | KeyFormatType::ConfigurableKEM
                | KeyFormatType::CoverCryptSecretKey
                | KeyFormatType::CoverCryptPublicKey => serializer.serialize_bytes(bytes),
                x => Err(serde::ser::Error::custom(format!(
                    "KeyMaterialWrapper: {x:?} key format type does not support byte strings"
                ))),
            }
        } else {
            match &self.key_material {
                KeyMaterial::TransparentSymmetricKey { key } => {
                    let mut st = serializer.serialize_struct("KeyMaterial", 1)?;
                    st.serialize_field("Key", &**key)?;
                    st.end()
                }
                KeyMaterial::TransparentDHPrivateKey { p, q, g, j, x } => {
                    let mut st = serializer.serialize_struct("KeyMaterial", 6)?;
                    st.serialize_field("P", &**p)?;
                    if let Some(q) = q {
                        st.serialize_field("Q", &**q)?;
                    }
                    st.serialize_field("G", &**g)?;
                    if let Some(j) = j {
                        st.serialize_field("J", &**j)?;
                    }
                    st.serialize_field("X", &***x)?;
                    st.end()
                }
                KeyMaterial::TransparentDHPublicKey { p, q, g, j, y } => {
                    let mut st = serializer.serialize_struct("KeyMaterial", 6)?;
                    st.serialize_field("P", &**p)?;
                    if let Some(q) = q {
                        st.serialize_field("Q", &**q)?;
                    }
                    st.serialize_field("G", &**g)?;
                    if let Some(j) = j {
                        st.serialize_field("J", &**j)?;
                    }
                    st.serialize_field("Y", &**y)?;
                    st.end()
                }
                KeyMaterial::TransparentDSAPrivateKey { p, q, g, x } => {
                    let mut st = serializer.serialize_struct("KeyMaterial", 5)?;
                    st.serialize_field("P", &**p)?;
                    st.serialize_field("Q", &**q)?;
                    st.serialize_field("G", &**g)?;
                    st.serialize_field("X", &***x)?;
                    st.end()
                }
                KeyMaterial::TransparentDSAPublicKey { p, q, g, y } => {
                    let mut st = serializer.serialize_struct("KeyMaterial", 5)?;
                    st.serialize_field("P", &**p)?;
                    st.serialize_field("Q", &**q)?;
                    st.serialize_field("G", &**g)?;
                    st.serialize_field("Y", &**y)?;
                    st.end()
                }
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
                    let mut st = serializer.serialize_struct("KeyMaterial", 9)?;
                    st.serialize_field("Modulus", &**modulus)?;
                    if let Some(private_exponent) = private_exponent {
                        st.serialize_field("PrivateExponent", &***private_exponent)?;
                    }
                    if let Some(public_exponent) = public_exponent {
                        st.serialize_field("PublicExponent", &**public_exponent)?;
                    }
                    if let Some(p) = p {
                        st.serialize_field("P", &***p)?;
                    }
                    if let Some(q) = q {
                        st.serialize_field("Q", &***q)?;
                    }
                    if let Some(prime_exponent_p) = prime_exponent_p {
                        st.serialize_field("PrimeExponentP", &***prime_exponent_p)?;
                    }
                    if let Some(prime_exponent_q) = prime_exponent_q {
                        st.serialize_field("PrimeExponentQ", &***prime_exponent_q)?;
                    }
                    if let Some(crt_coefficient) = crt_coefficient {
                        st.serialize_field("CrtCoefficient", &***crt_coefficient)?;
                    }
                    st.end()
                }
                KeyMaterial::TransparentRSAPublicKey {
                    modulus,
                    public_exponent,
                } => {
                    let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                    st.serialize_field("Modulus", &**modulus)?;
                    st.serialize_field("PublicExponent", &**public_exponent)?;
                    st.end()
                }
                KeyMaterial::TransparentECDSAPrivateKey {
                    recommended_curve,
                    d,
                }
                | KeyMaterial::TransparentECDHPrivateKey {
                    recommended_curve,
                    d,
                }
                | KeyMaterial::TransparentECMQVPrivateKey {
                    recommended_curve,
                    d,
                }
                | KeyMaterial::TransparentECPrivateKey {
                    recommended_curve,
                    d,
                } => {
                    let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                    st.serialize_field("RecommendedCurve", recommended_curve)?;
                    st.serialize_field("D", &***d)?;
                    st.end()
                }
                KeyMaterial::TransparentECDSAPublicKey {
                    recommended_curve,
                    q_string,
                }
                | KeyMaterial::TransparentECDHPublicKey {
                    recommended_curve,
                    q_string,
                }
                | KeyMaterial::TransparentECMQVPublicKey {
                    recommended_curve,
                    q_string,
                }
                | KeyMaterial::TransparentECPublicKey {
                    recommended_curve,
                    q_string,
                } => {
                    let mut st = serializer.serialize_struct("KeyMaterial", 3)?;
                    st.serialize_field("RecommendedCurve", recommended_curve)?;
                    st.serialize_field("QString", q_string)?;
                    st.end()
                }
                KeyMaterial::ByteString(_zeroizing) => Err(serde::ser::Error::custom(
                    "KeyMaterial: only keys with Key Format Raw should have a key material as a \
                     byte string",
                )),
            }
        }
    }
}

struct KeyMaterialDeserializer {
    key_format_type: KeyFormatType,
}

impl<'de> DeserializeSeed<'de> for KeyMaterialDeserializer {
    type Value = KeyMaterial;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
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
            Modulus,
            PrivateExponent,
            PublicExponent,
            PrimeExponentP,
            PrimeExponentQ,
            CrtCoefficient,
            RecommendedCurve,
            QString,
        }

        struct KeyMaterialVisitor {
            key_format_type: KeyFormatType,
        }

        impl<'de> Visitor<'de> for KeyMaterialVisitor {
            type Value = KeyMaterial;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct KeyMaterialVisitor")
            }

            /// This is called by the TTLV deserializer in `deserialize_seq`
            /// which is itself called by the call to `deserializer.deserialize_any()` below
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut bytestring = Vec::<u8>::new();
                while let Some(byte) = seq.next_element()? {
                    bytestring.push(byte);
                }
                match self.key_format_type {
                    KeyFormatType::Raw
                    | KeyFormatType::ECPrivateKey
                    | KeyFormatType::Opaque
                    | KeyFormatType::PKCS1
                    | KeyFormatType::PKCS12
                    | KeyFormatType::PKCS8
                    | KeyFormatType::X509
                    | KeyFormatType::ConfigurableKEM
                    | KeyFormatType::CoverCryptPublicKey
                    | KeyFormatType::CoverCryptSecretKey => {
                        Ok(KeyMaterial::ByteString(Zeroizing::new(bytestring)))
                    }
                    _ => Err(de::Error::custom(format!(
                        "KeyMaterialVisitor: {:?} key format type is not expected to have a byte \
                         string key material",
                        self.key_format_type
                    ))),
                }
            }

            #[expect(clippy::many_single_char_names)]
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut bytestring: Option<Zeroizing<Vec<u8>>> = None;
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
                                return Err(de::Error::duplicate_field("ByteString"));
                            }
                            bytestring = Some(map.next_value()?);
                        }
                        Field::D => {
                            if d.is_some() {
                                return Err(de::Error::duplicate_field("D"));
                            }
                            d = Some(Box::new(map.next_value()?));
                        }
                        Field::P => {
                            if p.is_some() {
                                return Err(de::Error::duplicate_field("P"));
                            }
                            p = Some(Box::new(map.next_value()?));
                        }
                        Field::Q => {
                            if q.is_some() {
                                return Err(de::Error::duplicate_field("Q"));
                            }
                            q = Some(Box::new(map.next_value()?));
                        }
                        Field::G => {
                            if g.is_some() {
                                return Err(de::Error::duplicate_field("G"));
                            }
                            g = Some(Box::new(map.next_value()?));
                        }
                        Field::J => {
                            if j.is_some() {
                                return Err(de::Error::duplicate_field("J"));
                            }
                            j = Some(Box::new(map.next_value()?));
                        }
                        Field::X => {
                            if x.is_some() {
                                return Err(de::Error::duplicate_field("X"));
                            }
                            x = Some(Box::new(map.next_value()?));
                        }
                        Field::Y => {
                            if y.is_some() {
                                return Err(de::Error::duplicate_field("Y"));
                            }
                            y = Some(Box::new(map.next_value()?));
                        }
                        Field::Key => {
                            if key.is_some() {
                                return Err(de::Error::duplicate_field("Key"));
                            }
                            key = Some(map.next_value()?);
                        }
                        Field::Modulus => {
                            if modulus.is_some() {
                                return Err(de::Error::duplicate_field("Modulus"));
                            }
                            modulus = Some(Box::new(map.next_value()?));
                        }
                        Field::PrivateExponent => {
                            if private_exponent.is_some() {
                                return Err(de::Error::duplicate_field("PrivateExponent"));
                            }
                            private_exponent = Some(Box::new(map.next_value()?));
                        }
                        Field::PublicExponent => {
                            if public_exponent.is_some() {
                                return Err(de::Error::duplicate_field("PublicExponent"));
                            }
                            public_exponent = Some(Box::new(map.next_value()?));
                        }
                        Field::PrimeExponentP => {
                            if prime_exponent_p.is_some() {
                                return Err(de::Error::duplicate_field("PrimeExponentP"));
                            }
                            prime_exponent_p = Some(Box::new(map.next_value()?));
                        }
                        Field::PrimeExponentQ => {
                            if prime_exponent_q.is_some() {
                                return Err(de::Error::duplicate_field("PrimeExponentQ"));
                            }
                            prime_exponent_q = Some(Box::new(map.next_value()?));
                        }
                        Field::CrtCoefficient => {
                            if crt_coefficient.is_some() {
                                return Err(de::Error::duplicate_field("CrtCoefficient"));
                            }
                            crt_coefficient = Some(Box::new(map.next_value()?));
                        }
                        Field::RecommendedCurve => {
                            if recommended_curve.is_some() {
                                return Err(de::Error::duplicate_field("RecommendedCurve"));
                            }
                            recommended_curve = Some(map.next_value()?);
                        }
                        Field::QString => {
                            if q_string.is_some() {
                                return Err(de::Error::duplicate_field("QString"));
                            }
                            q_string = Some(map.next_value()?);
                        }
                    }
                }

                if let Some(key) = key {
                    Ok(KeyMaterial::TransparentSymmetricKey { key })
                } else {
                    Ok(match &self.key_format_type {
                        KeyFormatType::TransparentDHPublicKey
                        | KeyFormatType::TransparentDHPrivateKey => {
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
                        KeyFormatType::TransparentDSAPublicKey
                        | KeyFormatType::TransparentDSAPrivateKey => {
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
                        KeyFormatType::TransparentRSAPublicKey => {
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
                        KeyFormatType::TransparentRSAPrivateKey => {
                            let modulus = modulus.ok_or_else(|| {
                                de::Error::missing_field("Modulus for RSA private key")
                            })?;
                            KeyMaterial::TransparentRSAPrivateKey {
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
                        KeyFormatType::TransparentECDSAPublicKey
                        | KeyFormatType::TransparentECDSAPrivateKey => {
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
                        KeyFormatType::TransparentECDHPublicKey
                        | KeyFormatType::TransparentECDHPrivateKey => {
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
                        KeyFormatType::TransparentECMQVPublicKey
                        | KeyFormatType::TransparentECMQVPrivateKey => {
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
                        KeyFormatType::TransparentECPublicKey
                        | KeyFormatType::TransparentECPrivateKey => {
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
                        f => {
                            return Err(de::Error::custom(format!(
                                "unsupported key format type: {f:?}, for the key material"
                            )));
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

        match self.key_format_type {
            KeyFormatType::Raw
            | KeyFormatType::ECPrivateKey
            | KeyFormatType::Opaque
            | KeyFormatType::PKCS1
            | KeyFormatType::PKCS12
            | KeyFormatType::PKCS8
            | KeyFormatType::X509
            | KeyFormatType::CoverCryptPublicKey
            | KeyFormatType::CoverCryptSecretKey => {
                trace!(
                    "===> KeyMaterial: Deserializing {:?} key format type as seq",
                    self.key_format_type
                );
                // This will call visit_seq for both the TTLV and the JSON deserializer
                deserializer.deserialize_any(KeyMaterialVisitor {
                    key_format_type: self.key_format_type,
                })
            }
            f => {
                trace!("===> KeyMaterial: Deserializing key format type: {f:?} as struct");
                deserializer.deserialize_struct(
                    "KeyMaterial",
                    FIELDS,
                    KeyMaterialVisitor {
                        key_format_type: self.key_format_type,
                    },
                )
            }
        }
    }
}

impl From<KeyMaterial> for kmip_2_1::kmip_data_structures::KeyMaterial {
    fn from(val: KeyMaterial) -> Self {
        match val {
            KeyMaterial::TransparentSymmetricKey { key } => Self::TransparentSymmetricKey { key },
            KeyMaterial::TransparentDHPrivateKey { p, q, g, j, x } => {
                Self::TransparentDHPrivateKey { p, q, g, j, x }
            }
            KeyMaterial::TransparentDHPublicKey { p, q, g, j, y } => {
                Self::TransparentDHPublicKey { p, q, g, j, y }
            }
            KeyMaterial::TransparentDSAPrivateKey { p, q, g, x } => {
                Self::TransparentDSAPrivateKey { p, q, g, x }
            }
            KeyMaterial::TransparentDSAPublicKey { p, q, g, y } => {
                Self::TransparentDSAPublicKey { p, q, g, y }
            }
            KeyMaterial::TransparentRSAPrivateKey {
                modulus,
                private_exponent,
                public_exponent,
                p,
                q,
                prime_exponent_p,
                prime_exponent_q,
                crt_coefficient,
            } => Self::TransparentRSAPrivateKey {
                modulus,
                private_exponent,
                public_exponent,
                p,
                q,
                prime_exponent_p,
                prime_exponent_q,
                c_r_t_coefficient: crt_coefficient,
            },
            KeyMaterial::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            } => Self::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            },
            KeyMaterial::TransparentECMQVPrivateKey {
                recommended_curve,
                d,
            }
            | KeyMaterial::TransparentECPrivateKey {
                recommended_curve,
                d,
            }
            | KeyMaterial::TransparentECDSAPrivateKey {
                recommended_curve,
                d,
            }
            | KeyMaterial::TransparentECDHPrivateKey {
                recommended_curve,
                d,
            } => Self::TransparentECPrivateKey {
                recommended_curve: recommended_curve.into(),
                d,
            },
            KeyMaterial::TransparentECDSAPublicKey {
                recommended_curve,
                q_string,
            }
            | KeyMaterial::TransparentECMQVPublicKey {
                recommended_curve,
                q_string,
            }
            | KeyMaterial::TransparentECPublicKey {
                recommended_curve,
                q_string,
            }
            | KeyMaterial::TransparentECDHPublicKey {
                recommended_curve,
                q_string,
            } => Self::TransparentECPublicKey {
                recommended_curve: recommended_curve.into(),
                q_string,
            },
            KeyMaterial::ByteString(zeroizing) => Self::ByteString(zeroizing),
        }
    }
}

impl TryFrom<kmip_2_1::kmip_data_structures::KeyMaterial> for KeyMaterial {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_data_structures::KeyMaterial) -> Result<Self, Self::Error> {
        match value {
            kmip_2_1::kmip_data_structures::KeyMaterial::TransparentSymmetricKey { key } => {
                Ok(Self::TransparentSymmetricKey { key })
            }
            kmip_2_1::kmip_data_structures::KeyMaterial::TransparentDHPrivateKey {
                p,
                q,
                g,
                j,
                x,
            } => Ok(Self::TransparentDHPrivateKey { p, q, g, j, x }),
            kmip_2_1::kmip_data_structures::KeyMaterial::TransparentDHPublicKey {
                p,
                q,
                g,
                j,
                y,
            } => Ok(Self::TransparentDHPublicKey { p, q, g, j, y }),
            kmip_2_1::kmip_data_structures::KeyMaterial::TransparentDSAPrivateKey {
                p,
                q,
                g,
                x,
            } => Ok(Self::TransparentDSAPrivateKey { p, q, g, x }),
            kmip_2_1::kmip_data_structures::KeyMaterial::TransparentDSAPublicKey { p, q, g, y } => {
                Ok(Self::TransparentDSAPublicKey { p, q, g, y })
            }
            kmip_2_1::kmip_data_structures::KeyMaterial::TransparentRSAPrivateKey {
                modulus,
                private_exponent,
                public_exponent,
                p,
                q,
                prime_exponent_p,
                prime_exponent_q,
                c_r_t_coefficient: crt_coefficient,
            } => Ok(Self::TransparentRSAPrivateKey {
                modulus,
                private_exponent,
                public_exponent,
                p,
                q,
                prime_exponent_p,
                prime_exponent_q,
                crt_coefficient,
            }),
            kmip_2_1::kmip_data_structures::KeyMaterial::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            } => Ok(Self::TransparentRSAPublicKey {
                modulus,
                public_exponent,
            }),
            kmip_2_1::kmip_data_structures::KeyMaterial::ByteString(zeroizing) => {
                Ok(Self::ByteString(zeroizing))
            }
            kmip_2_1::kmip_data_structures::KeyMaterial::TransparentECPrivateKey {
                recommended_curve,
                d,
            } => Ok(Self::TransparentECPrivateKey {
                recommended_curve: recommended_curve.try_into()?,
                d,
            }),
            kmip_2_1::kmip_data_structures::KeyMaterial::TransparentECPublicKey {
                recommended_curve,
                q_string,
            } => Ok(Self::TransparentECPublicKey {
                recommended_curve: recommended_curve.try_into()?,
                q_string,
            }),
        }
    }
}

/// 2.1.5 Key Wrapping Data Object Structure
/// The Key Wrapping Data object is a structure that contains information about the
/// wrapping of a key value. It includes the wrapping method, encryption key information,
/// MAC/signature information, initialization vector/counter/nonce if applicable, and
/// encoding information.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct KeyWrappingData {
    pub wrapping_method: WrappingMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_key_information: Option<EncryptionKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_signature_key_information: Option<MacSignatureKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_signature: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv_counter_nonce: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_option: Option<EncodingOption>,
}

impl From<KeyWrappingData> for kmip_2_1::kmip_data_structures::KeyWrappingData {
    fn from(val: KeyWrappingData) -> Self {
        Self {
            wrapping_method: val.wrapping_method.into(),
            encryption_key_information: val.encryption_key_information.map(Into::into),
            mac_signature_key_information: val.mac_signature_key_information.map(Into::into),
            mac_signature: val.mac_signature,
            iv_counter_nonce: val.iv_counter_nonce,
            encoding_option: val.encoding_option.map(Into::into),
        }
    }
}

impl TryFrom<kmip_2_1::kmip_data_structures::KeyWrappingData> for KeyWrappingData {
    type Error = KmipError;

    fn try_from(val: kmip_2_1::kmip_data_structures::KeyWrappingData) -> Result<Self, Self::Error> {
        Ok(Self {
            wrapping_method: val.wrapping_method.try_into()?,
            encryption_key_information: val
                .encryption_key_information
                .map(TryInto::try_into)
                .transpose()?,
            mac_signature_key_information: val
                .mac_signature_key_information
                .map(TryInto::try_into)
                .transpose()?,
            mac_signature: val.mac_signature,
            iv_counter_nonce: val.iv_counter_nonce,
            encoding_option: val.encoding_option.map(TryInto::try_into).transpose()?,
        })
    }
}

/// Encryption Key Information Structure
/// The Encryption Key Information is a structure containing a unique identifier and
/// optional parameters used to encrypt the key.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptionKeyInformation {
    pub unique_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,
}

impl From<EncryptionKeyInformation> for kmip_2_1::kmip_types::EncryptionKeyInformation {
    fn from(val: EncryptionKeyInformation) -> Self {
        Self {
            unique_identifier: kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                val.unique_identifier,
            ),
            cryptographic_parameters: val.cryptographic_parameters.map(Into::into),
        }
    }
}

impl TryFrom<kmip_2_1::kmip_types::EncryptionKeyInformation> for EncryptionKeyInformation {
    type Error = KmipError;

    fn try_from(val: kmip_2_1::kmip_types::EncryptionKeyInformation) -> Result<Self, Self::Error> {
        Ok(Self {
            unique_identifier: val.unique_identifier.to_string(),
            cryptographic_parameters: val
                .cryptographic_parameters
                .map(TryInto::try_into)
                .transpose()?,
        })
    }
}

/// MAC/Signature Key Information Structure
/// The MAC/Signature Key Information is a structure containing a unique identifier and
/// optional parameters used to generate a MAC or signature over the key.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct MacSignatureKeyInformation {
    pub unique_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,
}

impl From<MacSignatureKeyInformation> for kmip_2_1::kmip_types::MacSignatureKeyInformation {
    fn from(val: MacSignatureKeyInformation) -> Self {
        Self {
            unique_identifier: kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                val.unique_identifier,
            ),
            cryptographic_parameters: val.cryptographic_parameters.map(Into::into),
        }
    }
}

impl TryFrom<kmip_2_1::kmip_types::MacSignatureKeyInformation> for MacSignatureKeyInformation {
    type Error = KmipError;

    fn try_from(
        val: kmip_2_1::kmip_types::MacSignatureKeyInformation,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            unique_identifier: val.unique_identifier.to_string(),
            cryptographic_parameters: val
                .cryptographic_parameters
                .map(TryInto::try_into)
                .transpose()?,
        })
    }
}

/// 2.1.6 Key Wrapping Specification Object Structure
/// The Key Wrapping Specification is a structure that provides information on how a key
/// should be wrapped. It includes the wrapping method, encryption key information,
/// MAC/signature information, attribute names to be included in the wrapped data and
/// encoding options.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct KeyWrappingSpecification {
    pub wrapping_method: WrappingMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_key_information: Option<EncryptionKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_signature_key_information: Option<MacSignatureKeyInformation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_option: Option<EncodingOption>,
}

impl From<KeyWrappingSpecification> for kmip_2_1::kmip_data_structures::KeyWrappingSpecification {
    fn from(val: KeyWrappingSpecification) -> Self {
        Self {
            wrapping_method: val.wrapping_method.into(),
            encryption_key_information: val.encryption_key_information.map(Into::into),
            encoding_option: val.encoding_option.map(Into::into),
            mac_or_signature_key_information: val.mac_signature_key_information.map(Into::into),
            attribute_name: val.attribute_names,
        }
    }
}

/// Cryptographic Parameters Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CryptographicParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_cipher_mode: Option<BlockCipherMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding_method: Option<PaddingMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashing_algorithm: Option<HashingAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_role_type: Option<KeyRoleType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digital_signature_algorithm: Option<DigitalSignatureAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub random_iv: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_field_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation_field_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counter_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_counter_value: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask_generator: Option<MaskGenerator>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask_generator_hashing_algorithm: Option<HashingAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p_source: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trailer_field: Option<i32>,
}

impl From<CryptographicParameters> for kmip_2_1::kmip_types::CryptographicParameters {
    fn from(val: CryptographicParameters) -> Self {
        Self {
            block_cipher_mode: val.block_cipher_mode,
            padding_method: val.padding_method,
            hashing_algorithm: val.hashing_algorithm,
            key_role_type: val.key_role_type,
            digital_signature_algorithm: val.digital_signature_algorithm.map(Into::into),
            cryptographic_algorithm: val.cryptographic_algorithm.map(Into::into),
            random_iv: val.random_iv,
            iv_length: val.iv_length,
            tag_length: val.tag_length,
            fixed_field_length: val.fixed_field_length,
            invocation_field_length: val.invocation_field_length,
            counter_length: val.counter_length,
            initial_counter_value: val.initial_counter_value,
            salt_length: val.salt_length,
            mask_generator: val.mask_generator,
            mask_generator_hashing_algorithm: val.mask_generator_hashing_algorithm,
            p_source: val.p_source,
            trailer_field: val.trailer_field,
        }
    }
}

impl TryFrom<kmip_2_1::kmip_types::CryptographicParameters> for CryptographicParameters {
    type Error = KmipError;

    fn try_from(val: kmip_2_1::kmip_types::CryptographicParameters) -> Result<Self, Self::Error> {
        Ok(Self {
            block_cipher_mode: val.block_cipher_mode,
            padding_method: val.padding_method,
            hashing_algorithm: val.hashing_algorithm,
            key_role_type: val.key_role_type,
            digital_signature_algorithm: val
                .digital_signature_algorithm
                .map(TryInto::try_into)
                .transpose()?,
            cryptographic_algorithm: val
                .cryptographic_algorithm
                .map(TryInto::try_into)
                .transpose()?,
            random_iv: val.random_iv,
            iv_length: val.iv_length,
            tag_length: val.tag_length,
            fixed_field_length: val.fixed_field_length,
            invocation_field_length: val.invocation_field_length,
            counter_length: val.counter_length,
            initial_counter_value: val.initial_counter_value,
            salt_length: val.salt_length,
            mask_generator: val.mask_generator,
            mask_generator_hashing_algorithm: val.mask_generator_hashing_algorithm,
            p_source: val.p_source,
            trailer_field: val.trailer_field,
        })
    }
}

/// 2.1.7.1 Transparent Symmetric Key Structure
/// The Transparent Symmetric Key structure is used to carry the key data for a
/// symmetric key in raw form.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransparentSymmetricKey {
    pub key: Vec<u8>,
}

/// 2.1.7.2 Transparent DSA Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransparentDsaPrivateKey {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub g: Vec<u8>,
    pub x: Vec<u8>,
}

/// 2.1.7.3 Transparent DSA Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransparentDsaPublicKey {
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub g: Vec<u8>,
    pub y: Vec<u8>,
}

/// 2.1.7.4 Transparent RSA Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransparentRsaPrivateKey {
    pub modulus: Vec<u8>,
    pub private_exponent: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_exponent: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prime_exponent_p: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prime_exponent_q: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crt_coefficient: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_curve: Option<RecommendedCurve>,
}

/// 2.1.7.5 Transparent RSA Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransparentRsaPublicKey {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
}

/// 2.1.7.6 Transparent DH Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransparentDhPrivateKey {
    pub p: Vec<u8>,
    pub g: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub j: Option<Vec<u8>>,
    pub x: Vec<u8>,
}

/// 2.1.7.7 Transparent DH Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransparentDhPublicKey {
    pub p: Vec<u8>,
    pub g: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub j: Option<Vec<u8>>,
    pub y: Vec<u8>,
}

/// 2.1.7.8 Transparent ECDSA Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransparentEcdsaPrivateKey {
    pub recommended_curve: RecommendedCurve,
    pub d: Vec<u8>,
}

/// 2.1.7.9 Transparent ECDSA Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransparentEcdsaPublicKey {
    pub recommended_curve: RecommendedCurve,
    pub q_string: Vec<u8>,
}

/// 2.1.7.10 Transparent ECDH Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransparentEcdhPrivateKey {
    pub recommended_curve: RecommendedCurve,
    pub d: Vec<u8>,
}

/// 2.1.7.11 Transparent ECDH Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransparentEcdhPublicKey {
    pub recommended_curve: RecommendedCurve,
    pub q_string: Vec<u8>,
}

/// 2.1.7.12 Transparent ECMQV Private Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransparentEcmqvPrivateKey {
    pub recommended_curve: RecommendedCurve,
    pub d: Vec<u8>,
}

/// 2.1.7.13 Transparent ECMQV Public Key Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TransparentEcmqvPublicKey {
    pub recommended_curve: RecommendedCurve,
    pub q_string: Vec<u8>,
}

/// 2.1.8 Template-Attribute Structures
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct TemplateAttribute {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute: Option<Vec<Attribute>>,
}

impl<'de> Deserialize<'de> for TemplateAttribute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(field_identifier)]
        enum Field {
            Attribute,
        }

        struct TemplateAttributeVisitor;

        impl<'de> Visitor<'de> for TemplateAttributeVisitor {
            type Value = TemplateAttribute;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct TemplateAttribute")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut attributes: Option<Vec<Attribute>> = None;

                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::Attribute => {
                            // Collect one or more consecutive Attribute entries.
                            // Depending on the TTLV deserializer, this may yield all repeated
                            // siblings in one Vec, but we also support multiple occurrences
                            // by extending the existing Vec to avoid duplicate_field errors.
                            let mut batch: Vec<Attribute> = map.next_value()?;
                            if batch.is_empty() {
                                continue;
                            }
                            if let Some(ref mut acc) = attributes {
                                acc.append(&mut batch);
                            } else {
                                attributes = Some(batch);
                            }
                        }
                    }
                }

                Ok(TemplateAttribute {
                    attribute: attributes,
                })
            }
        }

        deserializer.deserialize_struct(
            "TemplateAttribute",
            &["Attribute"],
            TemplateAttributeVisitor,
        )
    }
}

impl From<TemplateAttribute> for kmip_2_1::kmip_attributes::Attributes {
    fn from(val: TemplateAttribute) -> Self {
        val.attribute.map_or_else(Self::default, Into::into)
    }
}

/// 2.1.9 Extension Information Structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ExtensionInformation {
    pub extension_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_tag: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_type: Option<i32>,
}

impl TryFrom<kmip_2_1::kmip_data_structures::ExtensionInformation> for ExtensionInformation {
    type Error = KmipError;

    fn try_from(
        val: kmip_2_1::kmip_data_structures::ExtensionInformation,
    ) -> Result<Self, Self::Error> {
        let extension_type = val.extension_type.map(i32::try_from).transpose()?;
        Ok(Self {
            extension_name: val.extension_name,
            extension_tag: val.extension_tag,
            extension_type,
        })
    }
}

/// 2.1.10-23 Additional Structures
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Data(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DataLength(pub i32);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SignatureData(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct MacData(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Nonce(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CorrelationValue(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct InitIndicator(pub bool);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct FinalIndicator(pub bool);

/// RNG Parameters provides information about random number generation. It contains
/// details about the RNG algorithm, cryptographic algorithms, hash algorithms, DRBG
/// algorithms and associated parameters.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RngParameters {
    pub rng_algorithm: RNGAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashing_algorithm: Option<HashingAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drbg_algorithm: Option<DRBGAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_curve: Option<RecommendedCurve>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fips186_variation: Option<FIPS186Variation>,
    pub prediction_resistance: Option<bool>,
}

/// Profile Information contains details about supported KMIP profiles.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ProfileInformation {
    pub profile_name: ProfileName,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_port: Option<i32>,
}

impl TryFrom<kmip_2_1::kmip_data_structures::ProfileInformation> for ProfileInformation {
    type Error = KmipError;

    fn try_from(
        val: kmip_2_1::kmip_data_structures::ProfileInformation,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            profile_name: ProfileName::KMIP21,
            server_uri: val.server_uri,
            server_port: val.server_port,
        })
    }
}

/// The `CapabilityInformation` structure provides information about the capabilities
/// of the server, such as supported operations, objects, and algorithms.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct CapabilityInformation {
    /// Specifies a particular KMIP profile supported by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streaming_capability: Option<bool>,

    /// Indicates whether the server supports asynchronous operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asynchronous_capability: Option<bool>,

    /// Indicates whether the server supports attestation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_capability: Option<bool>,

    /// Indicates whether the server supports batching of operations in a single request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_undo_capability: Option<bool>,

    /// Indicates whether the server supports batching of operations in a single request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_continue_capability: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unwrap_mode: Option<UnwrapMode>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub destroy_action: Option<DestroyAction>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub shredding_algorithm: Option<ShreddingAlgorithm>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub rng_mode: Option<kmip_2_1::kmip_types::RNGMode>,
}

impl TryFrom<kmip_2_1::kmip_data_structures::CapabilityInformation> for CapabilityInformation {
    type Error = KmipError;

    fn try_from(
        value: kmip_2_1::kmip_data_structures::CapabilityInformation,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            streaming_capability: value.streaming_capability,
            asynchronous_capability: value.asynchronous_capability,
            attestation_capability: value.attestation_capability,
            batch_undo_capability: value.batch_undo_capability,
            batch_continue_capability: value.batch_continue_capability,
            unwrap_mode: value.unwrap_mode,
            destroy_action: value.destroy_action,
            shredding_algorithm: value.shredding_algorithm,
            rng_mode: value.rng_mode,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct AuthenticatedEncryptionAdditionalData(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct AuthenticatedEncryptionTag(pub Vec<u8>);

/// Derivation Parameters defines the parameters for a key derivation process
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DerivationParameters {
    /// The type of derivation method to be used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// The initialization vector or nonce if required by the derivation algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialization_vector: Option<Vec<u8>>,
    /// A value that identifies the derivation process
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_data: Option<Vec<u8>>,
    /// The length in bits of the derived data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<Vec<u8>>,
    /// Optional iteration count used by the derivation method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration_count: Option<i32>,
}

/// The RNG Parameters base object is a structure that contains a mandatory RNG Algorithm
/// and a set of OPTIONAL fields that describe a Random Number Generator.
/// Specific fields pertain only to certain types of RNGs.
///
/// The RNG Algorithm SHALL be specified and if the algorithm implemented is unknown
/// or the implementation does not want to provide the specific details of the RNG Algorithm
/// then the Unspecified enumeration SHALL be used.
///
/// If the cryptographic building blocks used within the RNG are known
/// they MAY be specified in combination of the remaining fields
///  within the RNG Parameters structure.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RNGParameters {
    pub rng_algorithm: RNGAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashing_algorithm: Option<HashingAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drbg_algorithm: Option<DRBGAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_curve: Option<RecommendedCurve>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fips186_variation: Option<FIPS186Variation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prediction_resistance: Option<bool>,
}

impl TryFrom<kmip_2_1::kmip_data_structures::RNGParameters> for RNGParameters {
    type Error = KmipError;

    fn try_from(val: kmip_2_1::kmip_data_structures::RNGParameters) -> Result<Self, Self::Error> {
        Ok(Self {
            rng_algorithm: val.rng_algorithm,
            cryptographic_algorithm: val
                .cryptographic_algorithm
                .map(TryInto::try_into)
                .transpose()?,
            cryptographic_length: val.cryptographic_length,
            hashing_algorithm: val.hashing_algorithm,
            drbg_algorithm: val.drbg_algorithm,
            recommended_curve: val.recommended_curve.map(TryInto::try_into).transpose()?,
            fips186_variation: val.fips186_variation,
            prediction_resistance: val.prediction_resistance,
        })
    }
}

// The Server Information  base object is a structure that contains a set of OPTIONAL fields
/// that describe server information.
///
/// Where a server supports returning information in a vendor-specific field for
/// which there is an equivalent field within the structure,
/// the server SHALL provide the standardized version of the field.
#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ServerInformation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_serial_number: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_load: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_level: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_date: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_info: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternative_failover_endpoints: Option<Vec<String>>,
}

impl TryFrom<kmip_2_1::kmip_data_structures::ServerInformation> for ServerInformation {
    type Error = KmipError;

    fn try_from(
        value: kmip_2_1::kmip_data_structures::ServerInformation,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            server_name: value.server_name,
            server_serial_number: value.server_serial_number,
            server_version: value.server_version,
            server_load: value.server_load,
            product_name: value.product_name,
            build_level: value.build_level,
            build_date: value.build_date,
            cluster_info: value.cluster_info,
            alternative_failover_endpoints: value.alternative_failover_endpoints,
        })
    }
}
